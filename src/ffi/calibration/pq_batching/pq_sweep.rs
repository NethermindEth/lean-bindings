// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

//! The calibration suite's driver for batching post-quantum signature leaves (`calib/pq_batching.py`). It is not
//! part of this crate: the suite copies it into `src/ffi/examples` of the library revision under test and builds it
//! there, so it uses only that revision's public API (`nethermind_lean::pq`, `rec_aggregation`,
//! `rec_aggregation_base`).
//!
//! ```text
//! pq_sweep leaf   <scheme> <n> <msg_len> <offset> <committed|flat> [--save FILE] [--probe] [--cold]
//! pq_sweep step   <committed|flat> <OUT|-> INPUT... [--cold]  one aggregation step over leaf and aggregate files
//! pq_sweep verify FILE <reps>                                native verification of a leaf or an aggregate
//! ```
//!
//! `leaf` signs `n` distinct messages under keys `offset..offset + n` and proves the leaf once untimed, then once
//! timed. `step` proves its step once untimed, then once timed. Each prints one JSON line. `--cold` skips the untimed
//! run. `--probe` proves only once, and reports `fits: false` when the leaf does not prove (its witness exceeds the
//! verifier's committed-witness bound, or it runs past the VM's step limit) instead of failing.

use std::collections::BTreeMap;
use std::time::Instant;

use fiat_shamir::merkle::hash_to_scalars;
use leanvm_core::cpu::{Program, Proof, Stats, bytecode_table, prove};
use nethermind_lean::pq::common::{Claim, Hints, Scheme, program, witness};
use nethermind_lean::pq::{Profile, falcon, mldsa, slhdsa};
use rec_aggregation::{BATCH_DOMAIN, EthereumClaims, EthereumProof, Guest, MAX_CLAIMS_PER_BATCH_LEAF, batch_hash};

const LOG_INV_RATE: usize = 1;
const LEAF_MAGIC: &[u8; 4] = b"PQLF";
const AGG_MAGIC: &[u8; 4] = b"PQAG";

#[derive(Clone, Copy, PartialEq)]
enum Key {
    Committed,
    Flat,
}

impl Key {
    fn parse(s: &str) -> Key {
        match s {
            "committed" => Key::Committed,
            "flat" => Key::Flat,
            other => panic!("unknown key {other}"),
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |name: &str| args.iter().position(|a| a == name);
    let cold = flag("--cold").is_some();
    match args.first().map(String::as_str) {
        Some("leaf") => {
            let n: usize = args[2].parse().expect("n");
            let msg_len: usize = args[3].parse().expect("message length");
            let offset: usize = args[4].parse().expect("key offset");
            let key = Key::parse(&args[5]);
            let save = flag("--save").map(|i| args[i + 1].clone());
            let probe = flag("--probe").is_some();
            match args[1].as_str() {
                "mldsa44" => leaf::<mldsa::MlDsa44>(n, key, save, probe || cold, |i| mldsa_item(offset + i, msg_len)),
                "falcon512" => leaf::<falcon::Falcon512>(n, key, save, probe || cold, |i| {
                    assert_eq!(msg_len, 32, "Falcon leaves take 32-byte messages");
                    falcon::Falcon512::item(offset + i)
                }),
                "slhdsa128s" => leaf::<slhdsa::SlhDsa128s>(n, key, save, probe || cold, |i| {
                    assert_eq!(msg_len, 32, "SLH-DSA leaves take 32-byte messages");
                    slhdsa::SlhDsa128s::item(offset + i)
                }),
                other => panic!("unknown scheme {other}"),
            }
        }
        Some("step") => {
            let inputs: Vec<String> = args[3..].iter().filter(|a| *a != "--cold").cloned().collect();
            step(Key::parse(&args[1]), &args[2], &inputs, cold)
        }
        Some("verify") => verify(&args[1], args[2].parse().expect("repetitions")),
        _ => {
            eprintln!("usage: pq_sweep leaf|step|verify ...");
            std::process::exit(2);
        }
    }
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    nethermind_lean::keccak(bytes)
}

/// Key `i`'s ML-DSA-44 signature over a `msg_len`-byte message distinct in `i`. A 69-byte message has the WebAuthn
/// shape the leaf's claim is designed for: `rpIdHash ‖ flags ‖ signCount ‖ sha256(clientDataJSON)`.
fn mldsa_item(i: usize, msg_len: usize) -> mldsa::Item {
    let msg: Vec<u8> = if msg_len == 32 {
        return mldsa::MlDsa44::item(i);
    } else if msg_len == 69 {
        let mut m = keccak(b"example.com").to_vec();
        m.push(0x05);
        m.extend_from_slice(&(i as u32).to_be_bytes());
        m.extend_from_slice(&keccak(&[b"clientDataJSON".as_slice(), &(i as u64).to_le_bytes()].concat()));
        m
    } else {
        (0..msg_len.div_ceil(32))
            .flat_map(|j| keccak(&[(i as u64).to_le_bytes(), (j as u64).to_le_bytes()].concat()))
            .take(msg_len)
            .collect()
    };
    let (pk, sig) = Profile::MlDsa44.sign(i, &msg).expect("a message length ML-DSA-44 takes");
    mldsa::verified(&pk, &msg, &sig).expect("the native check accepts it")
}

/// Runs `f` on `0..n` across the machine's threads (SLH-DSA signing is slow).
fn parallel<T: Send>(n: usize, f: impl Fn(usize) -> T + Sync) -> Vec<T> {
    let threads = std::thread::available_parallelism().map_or(1, usize::from).min(n.max(1));
    let mut slots: Vec<Option<T>> = (0..n).map(|_| None).collect();
    std::thread::scope(|scope| {
        let f = &f;
        let handles: Vec<_> = (0..threads)
            .map(|t| scope.spawn(move || (t..n).step_by(threads).map(|i| (i, f(i))).collect::<Vec<_>>()))
            .collect();
        for h in handles {
            for (i, v) in h.join().expect("a worker") {
                slots[i] = Some(v);
            }
        }
    });
    slots.into_iter().map(|v| v.expect("an item")).collect()
}

/// The scheme's leaf program proved under the flat key: the same bytecode, with the table's own digest as its
/// Fiat-Shamir IV rather than its commitment's key (`Program::committed`), as guest 0 verifies it.
fn flat_program<S: Scheme>(committed: &Program) -> Program {
    let dir = std::env::temp_dir().join(format!("pq_sweep-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a temporary directory");
    // SAFETY: no other thread exists yet, so nothing reads the environment concurrently.
    unsafe { std::env::set_var("PQ_LEAVES_DUMP", &dir) };
    program::<S>();
    // SAFETY: as above.
    unsafe { std::env::remove_var("PQ_LEAVES_DUMP") };
    let source = std::fs::read_to_string(dir.join(format!("{}.py", S::NAME))).expect("the dumped leaf source");
    std::fs::remove_dir_all(&dir).ok();
    let mut ps = BTreeMap::new();
    ps.insert("BATCH_DOMAIN".to_string(), u128::from_le_bytes(BATCH_DOMAIN).to_string());
    ps.insert("MAX_CLAIMS".to_string(), MAX_CLAIMS_PER_BATCH_LEAF.to_string());
    S::placeholders(&mut ps);
    let ps = ps.into_iter().map(|(k, v)| (format!("{k}_PLACEHOLDER"), v)).collect();
    let ast = lean_compiler::parse_with_replacements(&source, &ps).expect("the dumped source parses");
    let flat = lean_compiler::compile(&ast);
    let words = |p: &Program| bytecode_table(p.prog()).iter().map(|w| w.0).collect::<Vec<u64>>();
    assert!(words(&flat) == words(committed), "the flat program must be the committed program's bytecode");
    flat
}

fn peak_rss() -> u64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: getrusage writes a whole rusage into the zeroed buffer it is given, which outlives the call.
    let usage = unsafe {
        libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr());
        usage.assume_init()
    };
    let max = usage.ru_maxrss as u64;
    if cfg!(target_os = "macos") { max } else { max * 1024 }
}

fn stats_json(st: &Stats) -> String {
    let log = |x: usize| (x.max(1) as f64).log2();
    let max_rows = st.rows.iter().copied().max().unwrap_or(0);
    format!(
        "\"cycles\":{},\"rows\":{:?},\"committed\":{},\"log_committed\":{:.4},\"log_padded\":{},\"log_max_rows\":{:.3},\"log_mem\":{}",
        st.cycles,
        st.rows,
        st.committed,
        log(st.committed),
        st.committed.max(1).next_power_of_two().trailing_zeros(),
        log(max_rows),
        st.log_mem
    )
}

fn prove_once(program: &Program, hints: &Hints, statement: &Claim) -> Result<(Proof, Stats, f64), String> {
    let mut program = program.clone();
    for (name, entries) in &hints.0 {
        program.set_witness(name, entries.clone());
    }
    let started = Instant::now();
    let proved = prove(&program, hash_to_scalars(statement), LOG_INV_RATE);
    let s = started.elapsed().as_secs_f64();
    proved.map(|(p, st)| (p, st, s)).map_err(|e| format!("{e:?}"))
}

fn leaf<S: Scheme>(n: usize, key: Key, save: Option<String>, once: bool, item: impl Fn(usize) -> S::Item + Sync) {
    let probe = std::env::args().any(|a| a == "--probe");
    let started = Instant::now();
    let committed = program::<S>();
    let program = match key {
        Key::Committed => committed,
        Key::Flat => flat_program::<S>(&committed),
    };
    let compile_s = started.elapsed().as_secs_f64();
    let started = Instant::now();
    let (claims, hints) = witness::<S>(parallel(n, item));
    let witness_s = started.elapsed().as_secs_f64();
    let statement = batch_hash(&claims);
    let runs = if once { 1 } else { 2 };
    let mut last = None;
    for run in 0..runs {
        match prove_once(&program, &hints, &statement) {
            Ok(r) => last = Some(r),
            Err(e) if probe => {
                println!("{{\"scheme\":\"{}\",\"n\":{n},\"fits\":false,\"error\":{e:?},\"peak_rss\":{}}}", S::NAME, peak_rss());
                return;
            }
            Err(e) => panic!("run {run}: the leaf does not prove: {e}"),
        }
    }
    let (proof, st, prove_s) = last.expect("a proof");
    let table: Vec<u64> = bytecode_table(program.prog()).iter().map(|w| w.0).collect();
    let (vk, wit) = match key {
        Key::Committed => (
            rec_aggregation::generic_verification_key(&table).expect("within the instruction bound"),
            rec_aggregation::generic_witness(&table, &proof).expect("a witness"),
        ),
        Key::Flat => (
            rec_aggregation_base::generic_verification_key(&table).expect("within the instruction bound"),
            rec_aggregation_base::generic_witness(&table, &proof).expect("a witness"),
        ),
    };
    let proof_bytes = proof.to_bytes().len();
    if let Some(path) = save {
        let mut out = LEAF_MAGIC.to_vec();
        out.push(key as u8);
        out.extend((claims.len() as u32).to_le_bytes());
        claims.iter().for_each(|c| out.extend(c));
        out.extend(vk);
        out.extend(statement);
        out.extend((wit.len() as u64).to_le_bytes());
        out.extend(&wit);
        std::fs::write(path, out).expect("the leaf file");
    }
    println!(
        "{{\"scheme\":\"{}\",\"n\":{n},\"key\":\"{}\",\"fits\":true,\"warm\":{},\"prove_s\":{prove_s:.4},{},\"instructions\":{},\"proof_bytes\":{proof_bytes},\"witness_bytes\":{},\"peak_rss\":{},\"compile_s\":{compile_s:.3},\"witness_s\":{witness_s:.3},\"threads\":\"{}\"}}",
        S::NAME,
        if key == Key::Committed { "committed" } else { "flat" },
        !once,
        stats_json(&st),
        program.prog().len(),
        wit.len(),
        peak_rss(),
        std::env::var("LEANVM_NUM_THREADS").unwrap_or_else(|_| "all".into()),
    );
}

struct LeafFile {
    key: Key,
    claims: Vec<Claim>,
    vk: [u8; 32],
    statement: [u8; 32],
    witness: Vec<u8>,
}

struct AggFile {
    key: Key,
    claims: Vec<([u8; 32], [u8; 32])>,
    proof: Vec<u8>,
}

enum Input {
    Leaf(LeafFile),
    Agg(AggFile),
}

fn take<'a>(b: &mut &'a [u8], n: usize) -> &'a [u8] {
    let (h, t) = b.split_at(n);
    *b = t;
    h
}

fn read_input(path: &str) -> Input {
    let all = std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let mut b = &all[..];
    let magic: [u8; 4] = take(&mut b, 4).try_into().unwrap();
    let key = if take(&mut b, 1)[0] == Key::Committed as u8 { Key::Committed } else { Key::Flat };
    let n = u32::from_le_bytes(take(&mut b, 4).try_into().unwrap()) as usize;
    if &magic == LEAF_MAGIC {
        let claims = (0..n).map(|_| take(&mut b, 32).try_into().unwrap()).collect();
        let vk = take(&mut b, 32).try_into().unwrap();
        let statement = take(&mut b, 32).try_into().unwrap();
        let len = u64::from_le_bytes(take(&mut b, 8).try_into().unwrap()) as usize;
        Input::Leaf(LeafFile { key, claims, vk, statement, witness: take(&mut b, len).to_vec() })
    } else {
        assert_eq!(&magic, AGG_MAGIC, "{path}: not a leaf or aggregate file");
        let claims = (0..n)
            .map(|_| (take(&mut b, 32).try_into().unwrap(), take(&mut b, 32).try_into().unwrap()))
            .collect();
        let len = u64::from_le_bytes(take(&mut b, 8).try_into().unwrap()) as usize;
        Input::Agg(AggFile { key, claims, proof: take(&mut b, len).to_vec() })
    }
}

fn write_agg(path: &str, key: Key, claims: &[([u8; 32], [u8; 32])], proof: &[u8]) {
    let mut out = AGG_MAGIC.to_vec();
    out.push(key as u8);
    out.extend((claims.len() as u32).to_le_bytes());
    for (d, k) in claims {
        out.extend(d);
        out.extend(k);
    }
    out.extend((proof.len() as u64).to_le_bytes());
    out.extend(proof);
    std::fs::write(path, out).expect("the aggregate file");
}

/// One aggregation step over `inputs` (leaves and earlier aggregates of the same key), publishing every claim.
fn step(key: Key, out: &str, inputs: &[String], cold: bool) {
    let started = Instant::now();
    let inputs: Vec<Input> = inputs.iter().map(|p| read_input(p)).collect();
    let (mut leaves, mut aggs) = (Vec::new(), Vec::new());
    for i in inputs {
        match i {
            Input::Leaf(l) => {
                assert!(l.key == key, "a leaf of the other key");
                leaves.push(l)
            }
            Input::Agg(a) => {
                assert!(a.key == key, "an aggregate of the other key");
                aggs.push(a)
            }
        }
    }
    let n_leaf_claims: usize = leaves.iter().map(|l| l.claims.len()).sum();
    let n_children = aggs.len();
    let (s, st, proof, claims) = match key {
        Key::Committed => {
            rec_aggregation::warm_up(Guest::Batched);
            let children: Vec<EthereumProof> = aggs
                .iter()
                .map(|a| {
                    let c = EthereumClaims { generic: a.claims.clone(), lean_sphincs: vec![], da_commitment: None };
                    EthereumProof::from_proof_bytes(Guest::Batched, &a.proof, c).expect("a child aggregate")
                })
                .collect();
            let batch: Vec<_> = leaves.iter().map(|l| (l.claims.clone(), l.vk, l.witness.clone())).collect();
            let load_s = started.elapsed().as_secs_f64();
            let run = || {
                let t = Instant::now();
                let (p, st) = rec_aggregation::aggregate_with_stats(Guest::Batched, &children, batch.clone(), vec![], &[], None, LOG_INV_RATE)
                    .expect("the step proves");
                (t.elapsed().as_secs_f64(), st, p)
            };
            if !cold {
                run();
            }
            let (s, st, p) = run();
            eprintln!("load {load_s:.3} s");
            (s, st, p.proof_bytes(), p.claims().generic.clone())
        }
        Key::Flat => {
            rec_aggregation_base::warm_up();
            let children: Vec<rec_aggregation_base::EthereumProof> = aggs
                .iter()
                .map(|a| {
                    let c = rec_aggregation_base::EthereumClaims { generic: a.claims.clone(), lean_sphincs: vec![], da_commitment: None };
                    rec_aggregation_base::EthereumProof::from_proof_bytes(&a.proof, c).expect("a child aggregate")
                })
                .collect();
            let raw: Vec<_> = leaves.iter().map(|l| (l.statement, l.vk, l.witness.clone())).collect();
            let run = || {
                let t = Instant::now();
                let (p, st) = rec_aggregation_base::aggregate_with_stats(&children, raw.clone(), vec![], &[], None, LOG_INV_RATE)
                    .expect("the step proves");
                (t.elapsed().as_secs_f64(), st, p)
            };
            if !cold {
                run();
            }
            let (s, st, p) = run();
            (s, st, p.proof_bytes(), p.claims().generic.clone())
        }
    };
    if out != "-" {
        write_agg(out, key, &claims, &proof);
    }
    println!(
        "{{\"step\":true,\"warm\":{},\"key\":\"{}\",\"leaves\":{},\"leaf_claims\":{n_leaf_claims},\"children\":{n_children},\"claims\":{},\"agg_s\":{s:.4},{},\"proof_bytes\":{},\"peak_rss\":{},\"threads\":\"{}\"}}",
        !cold,
        if key == Key::Committed { "committed" } else { "flat" },
        leaves.len(),
        claims.len(),
        stats_json(&st),
        proof.len(),
        peak_rss(),
        std::env::var("LEANVM_NUM_THREADS").unwrap_or_else(|_| "all".into()),
    );
}

/// Native verification of a leaf (as a mempool checks it before admission, hints included) or of an aggregate
/// (decoding included): one untimed run, then `reps` timed; prints the median and range in milliseconds.
fn verify(path: &str, reps: usize) {
    let input = read_input(path);
    let check: Box<dyn Fn() -> bool> = match &input {
        Input::Leaf(l) if l.key == Key::Committed => {
            Box::new(|| rec_aggregation::verify_batch_leaf(Guest::Batched, &l.claims, &l.vk, &l.witness))
        }
        Input::Leaf(l) => Box::new(|| rec_aggregation_base::verify_generic(&l.statement, &l.vk, &l.witness)),
        Input::Agg(a) if a.key == Key::Committed => Box::new(|| {
            let c = EthereumClaims { generic: a.claims.clone(), lean_sphincs: vec![], da_commitment: None };
            EthereumProof::from_proof_bytes(Guest::Batched, &a.proof, c).is_ok_and(|p| p.verify().is_ok())
        }),
        Input::Agg(a) => Box::new(|| {
            let c = rec_aggregation_base::EthereumClaims { generic: a.claims.clone(), lean_sphincs: vec![], da_commitment: None };
            rec_aggregation_base::EthereumProof::from_proof_bytes(&a.proof, c).is_ok_and(|p| p.verify().is_ok())
        }),
    };
    assert!(check(), "{path} does not verify");
    let mut ms: Vec<f64> = (0..reps)
        .map(|_| {
            let t = Instant::now();
            assert!(check());
            t.elapsed().as_secs_f64() * 1e3
        })
        .collect();
    ms.sort_by(f64::total_cmp);
    let (kind, claims, bytes) = match &input {
        Input::Leaf(l) => ("leaf", l.claims.len(), l.witness.len()),
        Input::Agg(a) => ("aggregate", a.claims.len(), a.proof.len()),
    };
    println!(
        "{{\"verify\":\"{kind}\",\"claims\":{claims},\"bytes\":{bytes},\"median_ms\":{:.3},\"min_ms\":{:.3},\"max_ms\":{:.3},\"reps\":{reps}}}",
        ms[ms.len() / 2],
        ms[0],
        ms[ms.len() - 1]
    );
}
