//! Benchmark inputs: generic programs of a chosen code size and trace length under distinct keys, their leaf proofs,
//! and leanSPHINCS signatures. Inner proving is the dependency owner's cost, so it is done ahead of a timed run and
//! stored in a corpus file.

use crate::api::{Leaf, RawSig, leaf_statement};
use crate::wire::{Reader, Writer, get_leaf, get_sigs, put_leaf, put_sigs};
use lean_compiler::{compile, parse};
use leanvm_core::cpu::{Program, bytecode_table, prove};
use signatures::lean_sphincs;
use std::time::Instant;

/// The source of a generic program: copies its hinted public input to the output, runs a hinted-length loop (one
/// keccak, two multiplications and a store an iteration; sets the trace), then `pad` straight-line multiply-adds
/// whose constants embed `seed` (sets the code size, and makes each seed a distinct key).
pub fn program_source(pad: usize, seed: u64) -> String {
    let mut s = String::from(
        "def main():\n    h = StackBuf(2)\n    hint_witness(h, \"pi\")\n    n = hint_witness(\"n\")\n    buf = HeapBuf(n * GEN)\n    m = HeapBuf(n)\n    buf[1] = h[0]\n    for x in mul_range(1, n):\n        a = buf[x]\n        k = StackBuf(2)\n        keccak_cells([a, h[0], h[1]], k)\n        buf[x * GEN] = k[0]\n        m[x] = a * h[1] + k[0] * k[1]\n",
    );
    s += &format!("    acc = h[0] + {}\n", seed + 1);
    for i in 0..pad {
        s += &format!(
            "    acc = acc * h[1] + {}\n",
            seed.wrapping_mul(1_000_003).wrapping_add(i as u64 + 2) & 0xffff_ffff
        );
    }
    s + "    p = 1\n    p[1] = h[0]\n    p[GEN] = h[1]\n    return\n"
}

pub fn compile_program(pad: usize, seed: u64) -> Program {
    compile(&parse(&program_source(pad, seed)).expect("the generated program parses"))
}

/// The largest padding whose program for `seed`, support code included, still has at most `2^code_log` instructions:
/// the most expensive program of that padded size. Per seed, since the embedded constants change the instruction
/// count. `None` if even no padding exceeds it.
pub fn pad_for_code_log(code_log: usize, seed: u64) -> Option<usize> {
    let fits = |pad: usize| compile_program(pad, seed).code_len() <= 1 << code_log;
    if !fits(0) {
        return None;
    }
    let (mut lo, mut hi) = (0usize, 1usize);
    while fits(hi) {
        lo = hi;
        hi *= 2;
    }
    while hi - lo > 1 {
        let mid = (lo + hi) / 2;
        if fits(mid) { lo = mid } else { hi = mid }
    }
    Some(lo)
}

/// `n` distinct claims derived from `seed`, strictly increasing as a leaf requires.
pub fn claims(seed: u64, n: usize) -> Vec<[u8; 32]> {
    let mut out: Vec<[u8; 32]> = (0..n as u64)
        .map(|i| primitives::hash::hash(&[seed.to_le_bytes(), i.to_le_bytes()].concat()))
        .collect();
    out.sort();
    out.dedup();
    assert_eq!(out.len(), n, "claims are distinct");
    out
}

/// A leaf and what proving it took.
pub struct ProvedLeaf {
    pub leaf: Leaf,
    pub stats: leanvm_core::cpu::Stats,
    pub code_len: usize,
    pub code_log: usize,
    pub prove_s: f64,
    pub key_ms: f64,
}

/// Proves a leaf of `program` over `n_claims` claims at inner `log_inv_rate`, looping `iters` times.
pub fn prove_leaf(
    program: &Program,
    iters: usize,
    log_inv_rate: usize,
    n_claims: usize,
    seed: u64,
) -> ProvedLeaf {
    let table: Vec<u64> = bytecode_table(program.prog()).iter().map(|w| w.0).collect();
    let start = Instant::now();
    #[cfg(feature = "committed")]
    let mut program = program.clone().committed();
    #[cfg(not(feature = "committed"))]
    let mut program = program.clone();
    let key_ms = start.elapsed().as_secs_f64() * 1e3;
    let claims = claims(seed, n_claims);
    let pi = fiat_shamir::merkle::hash_to_scalars(&leaf_statement(&claims));
    program.set_witness("pi", vec![pi.to_vec()]);
    program.set_witness("n", vec![vec![primitives::field::g_pow(iters).into()]]);
    let start = Instant::now();
    let (proof, stats) = prove(&program, pi, log_inv_rate).expect("the leaf proves");
    let prove_s = start.elapsed().as_secs_f64();
    let vk =
        rec_aggregation::generic_verification_key(&table).expect("within the instruction bound");
    let witness = rec_aggregation::generic_witness(&table, &proof).expect("a witness");
    ProvedLeaf {
        leaf: Leaf {
            claims,
            vk,
            witness,
        },
        stats,
        code_len: program.code_len(),
        code_log: program.prog().len().trailing_zeros() as usize,
        prove_s,
        key_ms,
    }
}

/// `n` leanSPHINCS signatures from keys and messages derived from `seed`.
pub fn signatures(seed: u64, n: usize) -> Vec<RawSig> {
    (0..n as u64)
        .map(|i| {
            let master = primitives::hash::hash(
                &[b"sk".as_slice(), &seed.to_le_bytes(), &i.to_le_bytes()].concat(),
            );
            let message = primitives::hash::hash(
                &[b"msg".as_slice(), &seed.to_le_bytes(), &i.to_le_bytes()].concat(),
            );
            let (sk, pk) = lean_sphincs::key_gen_from_seed(master);
            (
                pk,
                message,
                lean_sphincs::sign(&sk, &message).expect("signs"),
            )
        })
        .collect()
}

/// Corpus file tags.
const LEAF_FILE: u8 = 1;
const SIGS_FILE: u8 = 2;

pub fn write_leaf_file(path: &str, leaf: &Leaf) -> std::io::Result<()> {
    let mut w = Writer::default();
    w.u8(LEAF_FILE);
    put_leaf(&mut w, leaf);
    std::fs::write(path, w.buf)
}

pub fn read_leaf_file(path: &str) -> std::io::Result<Leaf> {
    let bytes = std::fs::read(path)?;
    let mut r = Reader::new(&bytes);
    if r.u8()? != LEAF_FILE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not a leaf file",
        ));
    }
    let leaf = get_leaf(&mut r)?;
    r.end()?;
    Ok(leaf)
}

pub fn write_sigs_file(path: &str, sigs: &[RawSig]) -> std::io::Result<()> {
    let mut w = Writer::default();
    w.u8(SIGS_FILE);
    put_sigs(&mut w, sigs);
    std::fs::write(path, w.buf)
}

pub fn read_sigs_file(path: &str) -> std::io::Result<Vec<RawSig>> {
    let bytes = std::fs::read(path)?;
    let mut r = Reader::new(&bytes);
    if r.u8()? != SIGS_FILE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not a signature file",
        ));
    }
    let sigs = get_sigs(&mut r)?;
    r.end()?;
    Ok(sigs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_give_distinct_keys_and_padding_sets_the_code_size() {
        let table = |p: &Program| {
            bytecode_table(p.prog())
                .iter()
                .map(|w| w.0)
                .collect::<Vec<u64>>()
        };
        let (a, b) = (compile_program(4, 1), compile_program(4, 2));
        assert_ne!(
            rec_aggregation::generic_verification_key(&table(&a)),
            rec_aggregation::generic_verification_key(&table(&b))
        );
        for seed in [0, 1000, 40_000] {
            let pad = pad_for_code_log(8, seed).expect("2^8 fits the loop");
            assert!(compile_program(pad, seed).code_len() <= 256);
            assert!(compile_program(pad + 1, seed).code_len() > 256);
        }
    }

    #[test]
    fn claims_are_sorted_and_distinct() {
        let c = claims(5, 300);
        assert!(c.windows(2).all(|w| w[0] < w[1]));
        assert_ne!(claims(5, 1), claims(6, 1));
    }
}
