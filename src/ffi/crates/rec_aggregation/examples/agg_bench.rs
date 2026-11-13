//! Shape and cost of fixed aggregation workloads, at log_inv_rate 1. `agg_bench sigs [n]` proves two disjoint
//! leanSPHINCS leaves of `n` signatures and their 2-children merge; `agg_bench generic` proves leaves of leanSTARK
//! dependencies (1 small, 1 of 2^11 instructions, 16 small, 40 signatures + 4 small, and one 16-claim batch leaf of
//! 2^11 instructions).

use lean_compiler::{compile, parse};
use leanvm_core::cpu::{Program, bytecode_table, prove};
use rec_aggregation::aggregation::unified_guest;
use rec_aggregation::{
    BATCH_DOMAIN, BatchLeaf, EthereumClaims, EthereumProof, MAX_CLAIMS_PER_BATCH_LEAF, aggregate_with_stats, batch_hash,
    batched_key, generic_verification_key, generic_witness,
};
use signatures::lean_sphincs;
use std::time::Instant;

const RATE: usize = 1;

type RawSphincs = (
    lean_sphincs::LeanSphincsPublicKey,
    lean_sphincs::Message,
    lean_sphincs::LeanSphincsSignature,
);

fn signers(n: usize) -> Vec<RawSphincs> {
    // Fresh keys and messages per run: the workload's shape, not its values, is what the bench measures.
    (0..n)
        .map(|_| {
            let (sk, pk) = lean_sphincs::key_gen_from_seed(rand::random());
            let message = rand::random();
            (pk, message, lean_sphincs::sign(&sk, &message).expect("signs"))
        })
        .collect()
}

/// Publishes `keccak256` of a hinted 48-byte preimage: the batch hash of one claim.
const PREIMAGE: &str = "\
def main():
    pre = StackBuf(3)
    hint_witness(pre, \"pre\")
    c = StackBuf(2)
    keccak_cells([pre[0], pre[1], pre[2]], c)
    p = 1
    p[1] = c[0]
    p[GEN] = c[1]
    return
";

/// Accepts any canonical public input after 900 multiply-adds: 2^11 instructions.
fn wide_source() -> String {
    let mut src = String::from("def main():\n    h = StackBuf(2)\n    hint_witness(h, \"pi\")\n    acc = h[0]\n");
    src += &"    acc = acc * h[1] + h[0]\n".repeat(900);
    src + "    p = 1\n    p[1] = h[0]\n    p[GEN] = h[1]\n    return\n"
}

fn cells(digest: &[u8; 32]) -> [primitives::field::F192; 2] {
    fiat_shamir::merkle::hash_to_scalars(digest)
}

/// A batch leaf of `claims`: the program proves `batch_hash(claims)` with its witness stream.
fn dependency(program: &Program, witness: (&str, Vec<primitives::field::F192>), claims: Vec<[u8; 32]>) -> BatchLeaf {
    let table: Vec<u64> = bytecode_table(program.prog()).iter().map(|w| w.0).collect();
    let mut program = program.clone();
    program.set_witness(witness.0, vec![witness.1]);
    let (proof, _) = prove(&program, cells(&batch_hash(&claims)), RATE).expect("the dependency proves");
    let vk = generic_verification_key(&table).expect("within the cap");
    (claims, vk, generic_witness(&table, &proof).expect("a witness"))
}

fn preimage_deps(n: usize) -> Vec<BatchLeaf> {
    let program = compile(&parse(PREIMAGE).expect("parse"));
    (0..n)
        .map(|i| {
            let claim = [i as u8 + 1; 32];
            let pre = [&BATCH_DOMAIN[..], &claim].concat();
            let pre_cells = pre.chunks(16).map(|c| {
                primitives::field::F192::new(
                    u64::from_le_bytes(c[..8].try_into().unwrap()),
                    u64::from_le_bytes(c[8..].try_into().unwrap()),
                    0,
                )
            });
            dependency(&program, ("pre", pre_cells.collect()), vec![claim])
        })
        .collect()
}

fn report(name: &str, run: impl FnOnce() -> (EthereumProof, leanvm_core::cpu::Stats)) -> EthereumProof {
    let start = Instant::now();
    let (proof, stats) = run();
    let prove = start.elapsed().as_secs_f64();
    let start = Instant::now();
    proof.verify().expect("verifies");
    let verify = start.elapsed().as_secs_f64() * 1e3;
    println!(
        "{name}: cycles {}, prove {prove:.3} s, verify {verify:.2} ms, proof {} B, log_mem {}, committed 2^{:.2}",
        stats.cycles,
        proof.proof_bytes().len(),
        stats.log_mem,
        (stats.committed as f64).log2()
    );
    proof
}

/// The superset guest, so the batch-leaf modes run too.
const GUEST: rec_aggregation::Guest = rec_aggregation::Guest::Batched;

fn main() {
    leanvm_core::init_prover();
    let mode = std::env::args().nth(1).unwrap_or_else(|| "sigs".into());
    rec_aggregation::warm_up(GUEST);
    let guest = unified_guest(GUEST);
    let vk: String = rec_aggregation::aggregated_vk(GUEST).iter().map(|b| format!("{b:02x}")).collect();
    println!(
        "guest code_len {}, bytecode log {}, aggregated vk {vk}",
        guest.code_len(),
        guest.prog().len().trailing_zeros()
    );
    let leaf = |deps: Vec<BatchLeaf>, sigs: Vec<RawSphincs>| {
        move || aggregate_with_stats(GUEST, &[], deps, sigs, &[], None, RATE).expect("proves")
    };
    match mode.as_str() {
        "sigs" => {
            let n: usize = std::env::args().nth(2).map_or(40, |a| a.parse().expect("n"));
            let left = report(&format!("leaf {n} sigs"), leaf(vec![], signers(n)));
            let right = report(&format!("leaf {n} sigs (2nd)"), leaf(vec![], signers(n)));
            report("merge 2 children", || {
                aggregate_with_stats(GUEST, &[left, right], vec![], vec![], &[], None, RATE).expect("proves")
            });
        }
        "generic" => {
            let wide = compile(&parse(&wide_source()).expect("parse"));
            let small = compile(&parse(PREIMAGE).expect("parse")).prog().len();
            println!("small program {small} instructions, wide program {}", wide.prog().len());
            let deps = preimage_deps(16);
            report("leaf 1 small generic", leaf(deps[..1].to_vec(), vec![]));
            let wide_leaf = |claims: Vec<[u8; 32]>| {
                let pi = cells(&batch_hash(&claims)).to_vec();
                dependency(&wide, ("pi", pi), claims)
            };
            report("leaf 1 generic of 2^11 instructions", leaf(vec![wide_leaf(vec![[9; 32]])], vec![]));
            report("leaf 16 small generic", leaf(deps.clone(), vec![]));
            report(
                "leaf 40 sigs + 4 small generic",
                leaf(deps[..4].to_vec(), signers(40)),
            );
            let claims = (1..=16).map(|i| [i; 32]).collect();
            report("leaf 1 batch of 16 claims, 2^11 instructions", leaf(vec![wide_leaf(claims)], vec![]));
        }
        "batch" => {
            // ethereum/EIPs#12664 activation shapes at the near-cap program: one leaf of `size` claims (default the
            // maximum) with every claim a batched dependency, and a step of `n` such leaves each keeping one.
            let wide = compile(&parse(&wide_source()).expect("parse"));
            let size: u16 = std::env::args().nth(3).map_or(MAX_CLAIMS_PER_BATCH_LEAF as u16, |a| a.parse().expect("size"));
            let full = |seed: u8| -> Vec<[u8; 32]> {
                (0..size)
                    .map(|i| {
                        let mut claim = [seed; 32];
                        claim[30..].copy_from_slice(&i.to_be_bytes());
                        claim
                    })
                    .collect()
            };
            let wide_leaf = |claims: Vec<[u8; 32]>| {
                let pi = cells(&batch_hash(&claims)).to_vec();
                dependency(&wide, ("pi", pi), claims)
            };
            let declared = |entries: Vec<([u8; 32], [u8; 32])>| {
                let mut generic = entries;
                generic.sort();
                EthereumClaims { generic, ..Default::default() }
            };
            let max = size;
            let one = wide_leaf(full(1));
            let all = declared(one.0.iter().map(|c| (*c, batched_key(max, &one.1))).collect());
            report(&format!("leaf 1 batch of {max} claims, all batched, 2^11 instructions"), || {
                aggregate_with_stats(GUEST, &[], vec![one.clone()], vec![], &[], Some(&all), RATE).expect("proves")
            });
            let n = std::env::args().nth(2).map_or(16, |a| a.parse().expect("n"));
            let leaves: Vec<BatchLeaf> = (0..n).map(|i| wide_leaf(full(2 + i as u8))).collect();
            let kept = declared(leaves.iter().map(|(c, vk, _)| (c[0], batched_key(max, vk))).collect());
            report(&format!("step of {n} batches of {max} claims, one kept each"), || {
                aggregate_with_stats(GUEST, &[], leaves.clone(), vec![], &[], Some(&kept), RATE).expect("proves")
            });
        }
        _ => panic!("mode: sigs [n] | generic | batch [n] [size]"),
    }
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    println!(
        "{}",
        status
            .lines()
            .find(|l| l.starts_with("VmHWM"))
            .unwrap_or("VmHWM unknown")
    );
}
