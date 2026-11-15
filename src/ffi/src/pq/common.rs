// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

//! The leaf skeleton (`leaf.py`) under a scheme's `verify_claim`, its hint streams and proving.

use std::collections::BTreeMap;
use std::time::Instant;

use fiat_shamir::merkle::hash_to_scalars;
use leanvm_core::cpu::{Program, bytecode_table, prove};
use primitives::field::{F192, g_pow};
use rec_aggregation::{BATCH_DOMAIN, MAX_CLAIMS_PER_BATCH_LEAF, batch_hash, generic_verification_key, generic_witness};

const LEAF: &str = include_str!("leaf.py");
/// Generic leaves are proved at rate 1/2, as the template and the calibration suite prove them.
const LOG_INV_RATE: usize = 1;
/// The largest program a leanSTARK key admits (`MAX_GENERIC_BYTECODE_LOG`).
pub const MAX_INSTRUCTIONS: usize = 1 << rec_aggregation::MAX_GENERIC_BYTECODE_LOG;

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
    type Item: Clone + Send + Sync;
    const NAME: &'static str;
    /// zkDSL defining `setup_scheme()` and `verify_claim(ctx)`.
    fn source() -> String;
    fn placeholders(_: &mut BTreeMap<String, String>) {}
    /// The `i`th signed message, deterministic in `i` and distinct from every other.
    fn item(i: usize) -> Self::Item;
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
    fn item(i: usize) -> Claim {
        crate::keccak(&(i as u64).to_le_bytes())
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

/// Runs `f` on `0..n` across the machine's threads, in order of index.
fn parallel<T: Send>(n: usize, f: impl Fn(usize) -> T + Sync) -> Vec<T> {
    let threads = std::thread::available_parallelism().map_or(1, usize::from).min(n.max(1));
    let mut out: Vec<Vec<T>> = Vec::new();
    std::thread::scope(|scope| {
        let f = &f;
        let handles: Vec<_> = (0..threads)
            .map(|t| scope.spawn(move || (t..n).step_by(threads).map(f).collect::<Vec<T>>()))
            .collect();
        out = handles.into_iter().map(|h| h.join().expect("a worker")).collect();
    });
    let mut iters: Vec<_> = out.into_iter().map(Vec::into_iter).collect();
    (0..n).map(|i| iters[i % threads].next().expect("an item")).collect()
}

/// `n` distinct signed messages: [`Scheme::item`] of `0..n`, generated in parallel (signing is slow for some schemes).
pub fn items<S: Scheme>(n: usize) -> Vec<S::Item> {
    parallel(n, S::item)
}

/// `g^n`, a count as the program takes it.
pub fn count(n: usize) -> F192 {
    g_pow(n).into()
}

/// A field literal for a placeholder.
pub fn f192_literal(f: F192) -> String {
    format!("f192({}, {}, {})", f.c0, f.c1, f.c2)
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

/// The items of a leaf, sorted by claim, with their claims and hint streams.
pub fn witness<S: Scheme>(mut items: Vec<S::Item>) -> (Vec<Claim>, Hints) {
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
    for one in parallel(items.len(), |i| {
        let mut h = Hints::default();
        S::push_hints(&items[i], &mut h);
        h
    }) {
        for (name, entries) in one.0 {
            hints.0.entry(name).or_default().extend(entries);
        }
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
    prove_witness(program, claims, &hints, statement)
}

pub fn prove_witness(program: &Program, claims: Vec<Claim>, hints: &Hints, statement: Option<Claim>) -> Result<Leaf, String> {
    let mut program = program.clone();
    for (name, entries) in &hints.0 {
        program.set_witness(name, entries.clone());
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
