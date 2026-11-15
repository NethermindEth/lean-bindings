// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

//! Post-quantum signature leaves for ethereum/EIPs#12664 batch claims: generic leanVM programs that verify N
//! signatures and publish `get_batch_hash(claims)`, one claim per signature (see `README.md`).
//!
//! ```text
//! pq_leaves size  <scheme>                       program size against the 2^11 instruction bound
//! pq_leaves test  <scheme>                       reference vectors, then the negative cases
//! pq_leaves prove <scheme> <n> [reps] [--agg]    one JSON line per timed run, after a warm-up
//! pq_leaves vectors                              EIP-8437 native/leaf equivalence vectors, as JSON
//! pq_leaves sign <profile> <key> <message-hex>    a test key's signature, as JSON
//! ```
//!
//! Schemes: `null` (hinted claims, the statement alone), `mldsa44`, `falcon512`, `slhdsa128s`.

mod bench;

use bench::{prove_leaf, report_size};
use nethermind_lean::pq::common::{self, Scheme};
use nethermind_lean::pq::{falcon, mldsa, slhdsa};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let arg = |i: usize| args.get(i).map(String::as_str);
    if arg(0) == Some("vectors") {
        bench::print_vectors();
        return;
    }
    if arg(0) == Some("sign") {
        bench::print_signature(&args[1..]);
        return;
    }
    let (Some(command), Some(scheme)) = (arg(0), arg(1)) else {
        eprintln!("usage: pq_leaves size|test|prove <scheme> [n] [reps] [--agg] | pq_leaves vectors | pq_leaves sign <profile> <key> <message-hex>");
        std::process::exit(2);
    };
    leanvm_core::init_prover();
    match scheme {
        "null" => run::<common::Null>(command, &args),
        "mldsa44" => run::<mldsa::MlDsa44>(command, &args),
        "falcon512" => run::<falcon::Falcon512>(command, &args),
        "slhdsa128s" => run::<slhdsa::SlhDsa128s>(command, &args),
        other => panic!("unknown scheme {other}"),
    }
}

fn run<S: Scheme>(command: &str, args: &[String]) {
    match command {
        "size" => report_size::<S>(),
        "test" => bench::test::<S>(),
        "prove" => {
            let n: usize = args.get(2).map_or(1, |n| n.parse().expect("claim count"));
            let reps: usize = args.get(3).map_or(3, |r| r.parse().expect("repetitions"));
            let aggregate = args.iter().any(|a| a == "--agg");
            prove_leaf::<S>(n, reps, aggregate);
        }
        other => panic!("unknown command {other}"),
    }
}
