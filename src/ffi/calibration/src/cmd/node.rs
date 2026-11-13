//! Single-step measurements and corpus generation, one per process.
//!
//! ```text
//! calib-node info
//! calib-node pad CODE_LOG [SEED]
//! calib-node leaf OUT CODE_LOG ITERS RATE CLAIMS SEED  prove a generic leaf of the most instructions within 2^CODE_LOG
//!                                                      (untimed for the block) into a corpus file
//! calib-node sigs OUT COUNT SEED                       sign COUNT messages into a corpus file
//! calib-node cell sigs SIGFILE N                       one step verifying N signatures
//! calib-node cell leaves GUEST RETAIN LEAF...         one step verifying these leaves; GUEST base|batched; RETAIN
//!                                                      claims each (batched: sponsored, with the payment)
//! calib-node cell merge SIGFILE C K                    one step merging C children of K signatures each
//! calib-node cell mergebatch RETAIN LEAF...            one step merging one sponsored-leaf child per leaf
//! calib-node cell finalize RETAIN LEAF...              one finalizing step over one sponsored-leaf child per leaf
//! ```
//!
//! A cell proves untimed inputs and an untimed one-signature warm-up step, then times exactly one step and prints
//! `RESULT {json}`.

use gas_calibration::api::{self, GuestKind, Leaf, RawSig};
use gas_calibration::json::{Obj, array};
use gas_calibration::{capabilities, inputs, sys};
use rec_aggregation::{EthereumClaims, EthereumProof};
use std::time::Instant;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn usage() -> ! {
    eprintln!("usage: see the module documentation of calib-node");
    std::process::exit(2)
}

fn num(s: &str) -> usize {
    s.parse().unwrap_or_else(|_| usage())
}

fn guest(s: &str) -> GuestKind {
    match s {
        "base" => GuestKind::Base,
        "batched" => GuestKind::Batched,
        _ => usage(),
    }
}

fn skipped(cell: &str, reason: &str) -> ! {
    let mut o = Obj::default();
    o.str("cell", cell)
        .str("status", "skipped")
        .str("reason", reason)
        .raw("build", &capabilities());
    println!("RESULT {}", o.finish());
    std::process::exit(0)
}

fn stats_json(o: &mut Obj, stats: &api::Stats) {
    o.num("node_cycles", stats.cycles)
        .num("node_committed", stats.committed)
        .float("node_log_committed", (stats.committed.max(1) as f64).log2())
        .num("node_log_mem", stats.log_mem)
        .num("node_bytecode", stats.bytecode)
        .raw(
            "node_rows",
            &array(stats.rows.iter().map(|r| r.to_string())),
        );
}

/// Times one step, verifies it natively and prints its result line.
fn report(
    cell: &str,
    extra: impl FnOnce(&mut Obj),
    run: impl FnOnce() -> Result<(EthereumProof, api::Stats), String>,
) {
    let start = Instant::now();
    let (proof, stats) = run().unwrap_or_else(|e| {
        let mut o = Obj::default();
        o.str("cell", cell).str("status", "failed").str("error", &e);
        println!("RESULT {}", o.finish());
        std::process::exit(1)
    });
    let prove_s = start.elapsed().as_secs_f64();
    let start = Instant::now();
    proof.verify().expect("the step verifies");
    let verify_ms = start.elapsed().as_secs_f64() * 1e3;
    let mut o = Obj::default();
    o.str("cell", cell)
        .str("status", "ok")
        .float("prove_s", prove_s)
        .float("verify_ms", verify_ms);
    o.num("proof_bytes", api::proof_bytes(&proof).len())
        .num("output_claims", proof.claims().generic.len());
    stats_json(&mut o, &stats);
    extra(&mut o);
    o.num("peak_rss", sys::peak_rss_bytes())
        .raw("build", &capabilities());
    println!("RESULT {}", o.finish());
}

fn read_leaves(paths: &[String]) -> Vec<Leaf> {
    paths
        .iter()
        .map(|p| inputs::read_leaf_file(p).expect("a leaf file"))
        .collect()
}

/// A step's declared output for sponsored leaves: each leaf's first `retain` claims and its payment, sorted.
fn sponsored(leaves: &[Leaf], retain: usize) -> EthereumClaims {
    let mut generic = Vec::new();
    for l in leaves {
        let kept = &l.claims[..retain.min(l.claims.len())];
        generic
            .extend(api::batch::sponsored(l, kept).unwrap_or_else(|e| skipped("sponsored", &e.0)));
    }
    generic.sort();
    EthereumClaims {
        generic,
        ..Default::default()
    }
}

fn warm_up() {
    api::warm_up();
}

fn sigs_from(path: &str, n: usize) -> Vec<RawSig> {
    let mut sigs = inputs::read_sigs_file(path).expect("a signature file");
    assert!(
        sigs.len() >= n,
        "the file holds {} signatures, {n} asked",
        sigs.len()
    );
    sigs.truncate(n);
    sigs
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let a = |i: usize| args.get(i).map(String::as_str).unwrap_or_else(|| usage());
    match a(0) {
        "info" => println!("{}", capabilities()),
        "pad" => {
            match inputs::pad_for_code_log(num(a(1)), args.get(2).map_or(0, |s| num(s)) as u64) {
                Some(p) => println!("{p}"),
                None => std::process::exit(1),
            }
        }
        "leaf" => {
            leanvm_core::init_prover();
            let (out, code_log, iters, rate, claims, seed) =
                (a(1), num(a(2)), num(a(3)), num(a(4)), num(a(5)), num(a(6)));
            let pad = inputs::pad_for_code_log(code_log, seed as u64).unwrap_or_else(|| usage());
            let program = inputs::compile_program(pad, seed as u64);
            let p = inputs::prove_leaf(&program, iters, rate, claims, seed as u64);
            inputs::write_leaf_file(out, &p.leaf).expect("writes the leaf");
            let mut o = Obj::default();
            o.str("file", out)
                .num("pad", pad)
                .num("iters", iters)
                .num("rate", rate)
                .num("claims", claims);
            o.num("inner_instructions", p.code_len)
                .num("inner_code_log", p.code_log);
            o.num("inner_cycles", p.stats.cycles)
                .num("inner_committed", p.stats.committed);
            o.float(
                "inner_log_committed",
                (p.stats.committed.max(1) as f64).log2(),
            );
            o.raw(
                "inner_rows",
                &array(p.stats.rows.iter().map(|r| r.to_string())),
            );
            o.num("witness_bytes", p.leaf.witness.len())
                .float("inner_prove_s", p.prove_s)
                .float("key_ms", p.key_ms);
            o.num("peak_rss", sys::peak_rss_bytes())
                .raw("build", &capabilities());
            println!("RESULT {}", o.finish());
        }
        "sigs" => {
            let sigs = inputs::signatures(num(a(3)) as u64, num(a(2)));
            inputs::write_sigs_file(a(1), &sigs).expect("writes the signatures");
        }
        "cell" => cell(&args[1..]),
        _ => usage(),
    }
}

fn cell(args: &[String]) {
    let a = |i: usize| args.get(i).map(String::as_str).unwrap_or_else(|| usage());
    let rest = |i: usize| args.get(i..).unwrap_or_default().to_vec();
    match a(0) {
        "sigs" => {
            let n = num(a(2));
            let sigs = sigs_from(a(1), n);
            warm_up();
            report(
                &format!("sigs-{n}"),
                |o| {
                    o.num("sigs", n);
                },
                || api::prove(GuestKind::Base, &[], vec![], sigs, None),
            );
        }
        "leaves" => {
            let (kind, retain) = (guest(a(1)), num(a(2)));
            let leaves = read_leaves(&rest(3));
            if kind == GuestKind::Batched && !api::BATCH {
                skipped(
                    "leaves",
                    "the batch-pricing guest is not in this library revision",
                );
            }
            let declare = (kind == GuestKind::Batched).then(|| sponsored(&leaves, retain));
            warm_up();
            let name = format!(
                "leaves-{}-x{}-c{}-r{retain}",
                a(1),
                leaves.len(),
                leaves[0].claims.len()
            );
            let (count, claims) = (leaves.len(), leaves[0].claims.len());
            report(
                &name,
                |o| {
                    o.num("leaves", count)
                        .num("claims", claims)
                        .num("retain", retain);
                },
                || api::prove(kind, &[], leaves, vec![], declare.as_ref()),
            );
        }
        "merge" => {
            let (c, k) = (num(a(2)), num(a(3)));
            let sigs = sigs_from(a(1), c * k);
            warm_up();
            let children: Vec<EthereumProof> = sigs
                .chunks(k)
                .map(|s| {
                    api::prove(GuestKind::Base, &[], vec![], s.to_vec(), None)
                        .expect("a child")
                        .0
                })
                .collect();
            report(
                &format!("merge-{c}x{k}"),
                |o| {
                    o.num("children", c).num("claims_per_child", k);
                },
                || api::prove(GuestKind::Base, &children, vec![], vec![], None),
            );
        }
        "mergebatch" | "finalize" => {
            if !api::BATCH {
                skipped(
                    a(0),
                    "the batch-pricing guest is not in this library revision",
                );
            }
            let retain = num(a(1));
            let leaves = read_leaves(&rest(2));
            warm_up();
            let mut children = Vec::new();
            let mut sources = Vec::new();
            let mut union = Vec::new();
            for l in &leaves {
                let declare = sponsored(std::slice::from_ref(l), retain);
                let child = api::prove(
                    GuestKind::Batched,
                    &[],
                    vec![l.clone()],
                    vec![],
                    Some(&declare),
                )
                .expect("a child")
                .0;
                union.extend(declare.generic);
                sources.push(api::batch::source(l));
                children.push(child);
            }
            union.sort();
            let declare = EthereumClaims {
                generic: union,
                ..Default::default()
            };
            let (c, records) = (children.len(), declare.generic.len());
            let name = format!("{}-{c}x{retain}", a(0));
            let extra = |o: &mut Obj| {
                o.num("children", c)
                    .num("retain", retain)
                    .num("records", records);
            };
            if a(0) == "finalize" {
                report(&name, extra, || {
                    api::finalize(&children, vec![], vec![], &declare, &sources)
                });
            } else {
                report(&name, extra, || {
                    api::prove(
                        GuestKind::Batched,
                        &children,
                        vec![],
                        vec![],
                        Some(&declare),
                    )
                });
            }
        }
        _ => usage(),
    }
}
