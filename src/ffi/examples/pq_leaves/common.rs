// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

//! The leaf skeleton (`leaf.py`) under a scheme's `verify_claim`, its hint streams, proving and the checks every
//! scheme shares.

use std::collections::BTreeMap;
use std::time::Instant;

use fiat_shamir::merkle::hash_to_scalars;
use leanvm_core::cpu::{Program, bytecode_table, prove};
use primitives::field::{F192, g_pow};
use rec_aggregation::{
    BATCH_DOMAIN, EthereumClaims, Guest, MAX_CLAIMS_PER_BATCH_LEAF, aggregate_with_stats, batch_claim_key, batch_hash,
    generic_verification_key, generic_witness, payment_key, verify_batch_leaf,
};

const LEAF: &str = include_str!("leaf.py");
/// Generic leaves are proved at rate 1/2, as the template and the calibration suite prove them.
const LOG_INV_RATE: usize = 1;
/// The largest program a leanSTARK key admits (`MAX_GENERIC_BYTECODE_LOG`).
const MAX_INSTRUCTIONS: usize = 1 << rec_aggregation::MAX_GENERIC_BYTECODE_LOG;

pub type Claim = [u8; 32];

/// Named hint streams, each a sequence of entries in the order the program pops them.
#[derive(Default, Clone)]
pub struct Hints(pub BTreeMap<String, Vec<Vec<F192>>>);

impl Hints {
    pub fn push(&mut self, name: &str, entry: Vec<F192>) {
        self.0.entry(name.to_string()).or_default().push(entry);
    }
}

/// One signature scheme's leaf.
pub trait Scheme {
    /// A signed message: whatever `claim` and `push_hints` need.
    type Item: Clone;
    const NAME: &'static str;
    /// zkDSL defining `setup_scheme()` and `verify_claim(ctx)`.
    fn source() -> String;
    fn placeholders(_: &mut BTreeMap<String, String>) {}
    /// `n` distinct signed messages, deterministic in `n`.
    fn items(n: usize) -> Vec<Self::Item>;
    fn claim(item: &Self::Item) -> Claim;
    /// The streams the per-proof setup pops, before any claim's.
    fn setup_hints(_: &mut Hints) {}
    /// One claim's streams. Must not check the signature: the negative test relies on it computing a rejected
    /// signature's streams as it would an accepted one's.
    fn push_hints(item: &Self::Item, hints: &mut Hints);
    /// The item with its signature broken (its claim unchanged), which the program must reject.
    fn forge(item: &Self::Item) -> Self::Item;
    /// Checks the scheme's reference implementation and known-answer vectors against the host's own computation.
    fn reference_check() {}
}

/// The `null` scheme: hinted claims, no verification. It isolates the skeleton's cost (count, digest, publish).
pub struct Null;

impl Scheme for Null {
    type Item = Claim;
    const NAME: &'static str = "null";
    fn source() -> String {
        "def setup_scheme():\n    return 0\n\n\ndef verify_claim(ctx):\n    c = StackBuf(2)\n    hint_witness(c, \"claim\")\n    return c[0], c[1]\n".into()
    }
    fn items(n: usize) -> Vec<Claim> {
        (0..n as u64).map(|i| nethermind_lean::keccak(&i.to_le_bytes())).collect()
    }
    fn claim(item: &Claim) -> Claim {
        *item
    }
    fn push_hints(item: &Claim, hints: &mut Hints) {
        hints.push("claim", hash_to_scalars(item).to_vec());
    }
    fn forge(item: &Claim) -> Claim {
        *item
    }
}

/// `g^n`, a count as the program takes it.
pub fn count(n: usize) -> F192 {
    g_pow(n).into()
}

/// A field literal for a placeholder.
pub fn f192_literal(f: F192) -> String {
    format!("f192({}, {}, {})", f.c0, f.c1, f.c2)
}

pub fn field_list(values: &[F192]) -> String {
    format!("[{}]", values.iter().map(|&f| f192_literal(f)).collect::<Vec<_>>().join(", "))
}

/// 16 bytes as one canonical cell: two little-endian 64-bit lanes.
pub fn cell(bytes: &[u8]) -> F192 {
    let lane = |o: usize| u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap());
    F192::new(lane(0), lane(8), 0)
}

/// Bytes, zero-padded to whole cells.
pub fn cells(bytes: &[u8]) -> Vec<F192> {
    bytes
        .chunks(16)
        .map(|c| {
            let mut b = [0u8; 16];
            b[..c.len()].copy_from_slice(c);
            cell(&b)
        })
        .collect()
}

/// The program of scheme `S`, committed, as a leanSTARK key names it.
pub fn program<S: Scheme>() -> Program {
    let mut ps = BTreeMap::new();
    ps.insert("BATCH_DOMAIN".to_string(), u128::from_le_bytes(BATCH_DOMAIN).to_string());
    ps.insert("MAX_CLAIMS".to_string(), MAX_CLAIMS_PER_BATCH_LEAF.to_string());
    S::placeholders(&mut ps);
    let ps = ps.into_iter().map(|(k, v)| (format!("{k}_PLACEHOLDER"), v)).collect();
    let source = hoist_constants(&format!("{}\n\n{LEAF}", S::source()));
    if let Some(dir) = std::env::var_os("PQ_LEAVES_DUMP") {
        std::fs::write(std::path::Path::new(&dir).join(format!("{}.py", S::NAME)), &source).ok();
    }
    let ast = lean_compiler::parse_with_replacements(&source, &ps).unwrap_or_else(|e| panic!("{}: {e}", S::NAME));
    lean_compiler::compile(&ast).committed()
}

/// Global constants must precede every function, so the scheme's and the skeleton's are moved to the top. A constant
/// defined twice must be defined identically.
fn hoist_constants(source: &str) -> String {
    let mut seen = BTreeMap::<&str, &str>::new();
    let (mut constants, mut body) = (String::new(), String::new());
    for line in source.lines() {
        let constant = line.split_once(" = ").filter(|(name, _)| {
            !name.is_empty() && name.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        });
        match constant {
            None => {
                body.push_str(line);
                body.push('\n');
            }
            Some((name, value)) => {
                let value = value.split('#').next().unwrap().trim();
                match seen.insert(name, value) {
                    None => {
                        constants.push_str(line);
                        constants.push('\n');
                    }
                    Some(first) => assert_eq!(first, value, "conflicting definitions of {name}"),
                }
            }
        }
    }
    format!("{constants}\n{body}")
}

pub struct Size {
    pub instructions: usize,
    pub padded: usize,
}

pub fn size(program: &Program) -> Size {
    let instructions = program.code_len();
    Size {
        instructions,
        padded: instructions.next_power_of_two(),
    }
}

pub fn report_size<S: Scheme>() {
    let program = program::<S>();
    let s = size(&program);
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

/// The items of a leaf, sorted by claim, with their claims and hint streams.
fn witness<S: Scheme>(mut items: Vec<S::Item>) -> (Vec<Claim>, Hints) {
    assert!((1..=MAX_CLAIMS_PER_BATCH_LEAF).contains(&items.len()));
    items.sort_by_cached_key(S::claim);
    let claims: Vec<Claim> = items.iter().map(S::claim).collect();
    assert!(claims.windows(2).all(|w| w[0] < w[1]), "claims must be distinct");
    let mut hints = Hints::default();
    let n = items.len();
    hints.push("n_claims", vec![count(n)]);
    let cells = 1 + 2 * n;
    hints.push(
        "leaf_digest_split",
        vec![count(cells / 17), count(cells % 17), F192::new(u64::from(cells % 17 <= 8), 0, 0)],
    );
    S::setup_hints(&mut hints);
    for item in &items {
        S::push_hints(item, &mut hints);
    }
    (claims, hints)
}

pub struct Leaf {
    pub claims: Vec<Claim>,
    pub key: [u8; 32],
    pub witness: Vec<u8>,
    pub stats: leanvm_core::cpu::Stats,
    pub prove_s: f64,
}

/// Proves the leaf of `items` under `program`; `Err` when the program rejects them.
pub fn prove_items<S: Scheme>(program: &Program, items: Vec<S::Item>, statement: Option<Claim>) -> Result<Leaf, String> {
    let (claims, hints) = witness::<S>(items);
    let mut program = program.clone();
    for (name, entries) in hints.0 {
        program.set_witness(&name, entries);
    }
    let statement = statement.unwrap_or_else(|| batch_hash(&claims));
    let started = Instant::now();
    let proved = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prove(&program, hash_to_scalars(&statement), LOG_INV_RATE)
    }));
    let prove_s = started.elapsed().as_secs_f64();
    let (proof, stats) = match proved {
        Ok(Ok(proved)) => proved,
        Ok(Err(e)) => return Err(format!("{e:?}")),
        Err(_) => return Err("witness generation panicked".into()),
    };
    let table: Vec<u64> = bytecode_table(program.prog()).iter().map(|w| w.0).collect();
    let key = generic_verification_key(&table).ok_or("above the instruction bound")?;
    let witness = generic_witness(&table, &proof).ok_or("no witness")?;
    Ok(Leaf {
        claims,
        key,
        witness,
        stats,
        prove_s,
    })
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
    let items = S::items(2);
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
/// also proves the aggregation step that verifies the leaf with every claim sponsored, as the calibration suite's
/// batch-leaf cell does.
pub fn prove_leaf<S: Scheme>(n: usize, reps: usize, aggregate: bool) {
    let started = Instant::now();
    let program = program::<S>();
    let compile_s = started.elapsed().as_secs_f64();
    let s = size(&program);
    let items = S::items(n);
    if aggregate {
        rec_aggregation::warm_up(Guest::Batched);
    }
    for run in 0..=reps {
        let leaf = prove_items::<S>(&program, items.clone(), None).expect("the leaf proves");
        let agg = aggregate.then(|| aggregation_step(&leaf));
        if run == 0 {
            continue;
        }
        let st = &leaf.stats;
        let agg = agg.map_or(String::new(), |(s, cycles)| format!(",\"agg_s\":{s:.4},\"agg_cycles\":{cycles}"));
        println!(
            "{{\"scheme\":\"{}\",\"n\":{n},\"run\":{run},\"prove_s\":{:.4},\"cycles\":{},\"rows\":{:?},\"committed\":{},\"log_committed\":{:.3},\"log_mem\":{},\"instructions\":{},\"padded\":{},\"witness_bytes\":{},\"peak_rss\":{},\"compile_s\":{compile_s:.3},\"threads\":\"{}\"{agg}}}",
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

/// The step verifying `leaf` with all its claims and its payment declared: its proving time and cycles.
fn aggregation_step(leaf: &Leaf) -> (f64, usize) {
    let source = batch_hash(&leaf.claims);
    let mut generic: Vec<_> = leaf
        .claims
        .iter()
        .map(|c| (*c, batch_claim_key(&leaf.key, &source)))
        .collect();
    generic.push((source, payment_key(&leaf.key)));
    let declare = EthereumClaims {
        generic,
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
