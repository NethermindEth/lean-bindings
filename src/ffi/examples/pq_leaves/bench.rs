// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

//! Size reports, the negative tests and proving benchmarks over the library's signature leaves.

use std::collections::BTreeMap;
use std::time::Instant;

use nethermind_lean::pq::common::{Leaf, MAX_INSTRUCTIONS, Scheme, items, program, prove_items, prove_witness, size, witness};
use rec_aggregation::{EthereumClaims, Guest, aggregate_with_stats, batch_hash, verify_batch_leaf};

/// Generic leaves are proved at rate 1/2, as the template and the calibration suite prove them.
const LOG_INV_RATE: usize = 1;

pub fn report_size<S: Scheme>() {
    let program = program::<S>();
    let s = size(&program);
    if std::env::var_os("PQ_LEAVES_BREAKDOWN").is_some() {
        let mut by: BTreeMap<String, usize> = BTreeMap::new();
        for pc in 0..s.instructions as u32 {
            let site = program.site_at(pc);
            *by.entry(site.split(" (").next().unwrap_or("").to_string()).or_default() += 1;
        }
        let mut v: Vec<_> = by.into_iter().collect();
        v.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
        for (f, c) in v {
            eprintln!("{c:6} {f}");
        }
        let dis = lean_compiler::disassemble(program.prog());
        let annotated: String = dis
            .lines()
            .enumerate()
            .map(|(pc, l)| format!("{:5} {:28} {l}\n", pc, program.site_at(pc as u32)))
            .collect();
        std::fs::write(std::env::var("PQ_LEAVES_BREAKDOWN").unwrap(), annotated).ok();
    }
    println!(
        "{{\"scheme\":\"{}\",\"instructions\":{},\"padded\":{},\"log_padded\":{},\"bound\":{},\"fits\":{}}}",
        S::NAME,
        s.instructions,
        s.padded,
        s.padded.trailing_zeros(),
        MAX_INSTRUCTIONS,
        s.padded <= MAX_INSTRUCTIONS
    );
}


/// Peak resident set of this process, in bytes.
pub fn peak_rss() -> u64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: getrusage writes a whole rusage into the zeroed buffer it is given, which outlives the call.
    let usage = unsafe {
        libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr());
        usage.assume_init()
    };
    let max = usage.ru_maxrss as u64;
    if cfg!(target_os = "macos") { max } else { max * 1024 }
}


/// The reference vectors, then: an honest leaf verifies; a forged signature and a wrong claim are rejected.
pub fn test<S: Scheme>() {
    S::reference_check();
    println!("{}: reference vectors match", S::NAME);
    let program = program::<S>();
    let items = items::<S>(2);
    let leaf = prove_items::<S>(&program, items.clone(), None).expect("an honest leaf proves");
    assert!(verify_batch_leaf(Guest::Batched, &leaf.claims, &leaf.key, &leaf.witness));
    println!("{}: a leaf of 2 signatures proves and verifies ({} cycles)", S::NAME, leaf.stats.cycles);

    let mut wrong = leaf.claims.clone();
    wrong[1][31] ^= 1;
    wrong.sort();
    assert!(!verify_batch_leaf(Guest::Batched, &wrong, &leaf.key, &leaf.witness));
    assert!(!verify_batch_leaf(Guest::Batched, &leaf.claims[..1], &leaf.key, &leaf.witness));
    assert!(
        prove_items::<S>(&program, items.clone(), Some(batch_hash(&wrong))).is_err(),
        "a statement over other claims must not prove"
    );
    println!("{}: a wrong claim is rejected (verifier and prover)", S::NAME);

    if S::NAME != "null" {
        let forged = vec![items[0].clone(), S::forge(&items[1])];
        match prove_items::<S>(&program, forged, None) {
            Ok(_) => panic!("{}: a forged signature proved", S::NAME),
            Err(e) => println!("{}: a forged signature is rejected ({e})", S::NAME),
        }
    }
}

/// Proves an `n`-signature leaf once untimed and `reps` times timed, one JSON line a run. With `aggregate`, each run
/// also proves the aggregation step that verifies the leaf with every claim declared.
pub fn prove_leaf<S: Scheme>(n: usize, reps: usize, aggregate: bool) {
    let started = Instant::now();
    let program = program::<S>();
    let compile_s = started.elapsed().as_secs_f64();
    let s = size(&program);
    let started = Instant::now();
    let (claims, hints) = witness::<S>(items::<S>(n));
    let witness_s = started.elapsed().as_secs_f64();
    if aggregate {
        rec_aggregation::warm_up(Guest::Batched);
    }
    for run in 0..=reps {
        let leaf = prove_witness(&program, claims.clone(), &hints, None).expect("the leaf proves");
        let agg = aggregate.then(|| aggregation_step(&leaf));
        if run == 0 {
            continue;
        }
        let st = &leaf.stats;
        let agg = agg.map_or(String::new(), |(s, cycles)| format!(",\"agg_s\":{s:.4},\"agg_cycles\":{cycles}"));
        println!(
            "{{\"scheme\":\"{}\",\"n\":{n},\"run\":{run},\"prove_s\":{:.4},\"cycles\":{},\"rows\":{:?},\"committed\":{},\"log_committed\":{:.3},\"log_mem\":{},\"instructions\":{},\"padded\":{},\"witness_bytes\":{},\"peak_rss\":{},\"compile_s\":{compile_s:.3},\"witness_s\":{witness_s:.3},\"threads\":\"{}\"{agg}}}",
            S::NAME,
            leaf.prove_s,
            st.cycles,
            st.rows,
            st.committed,
            (st.committed as f64).log2(),
            st.log_mem,
            s.instructions,
            s.padded,
            leaf.witness.len(),
            peak_rss(),
            std::env::var("LEANVM_NUM_THREADS").unwrap_or_else(|_| "all".into()),
        );
    }
}

/// The step verifying `leaf` with all its claims declared: its proving time and cycles.
fn aggregation_step(leaf: &Leaf) -> (f64, usize) {
    let declare = EthereumClaims {
        generic: leaf.claims.iter().map(|c| (*c, leaf.key)).collect(),
        lean_sphincs: vec![],
        da_commitment: None,
    };
    let started = Instant::now();
    let (_, stats) = aggregate_with_stats(
        Guest::Batched,
        &[],
        vec![(leaf.claims.clone(), leaf.key, leaf.witness.clone())],
        vec![],
        &[],
        Some(&declare),
        LOG_INV_RATE,
    )
    .expect("the leaf aggregates");
    (started.elapsed().as_secs_f64(), stats.cycles)
}

/// Prints every recognized profile's key and equivalence vectors as JSON.
pub fn print_vectors() {
    println!("{}", nethermind_lean::pq::vectors_json());
}
