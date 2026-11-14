// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

//! Pinned LeanVM verification and recursive aggregation of complete dependency sets.

mod base;

use rec_aggregation::{
    BATCHED_LEANSTARK_SCHEME, BatchLeaf, EthereumClaims, EthereumProof, Guest,
    LEANSTARK_LEAF_PAYMENT_SCHEME, MAX_CLAIMS_PER_BATCH_LEAF, MAX_GENERIC_BYTECODE_LOG,
    MAX_INNER_PROOFS_PER_STEP, valid_batch_claims, verify_batch_leaf,
};
use signatures::lean_sphincs::{self, LeanSphincsPublicKey, LeanSphincsSignature};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeSet, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Barrier, Mutex, OnceLock};
use std::thread::ThreadId;

pub const MAX_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_INPUT_BYTES: usize = 18 * 1024 * 1024;
/// A local bound: one guest node proves this many signatures in about 9 GiB.
const MAX_DEPS: usize = 256;
// The upstream prover's timings assume its allocator: jemalloc keeps a proof's freed pages mapped for the next one.
// It serves this library's allocations only, and holds their peak until the process exits.
#[global_allocator]
static ALLOCATOR: bench::Jemalloc = bench::Jemalloc;
const LOG_INV_RATE: usize = 1;
static PROVER: Mutex<()> = Mutex::new(());

/// Takes the prover for one proof: `rec_aggregation::aggregate` allows one call at a time per process.
fn begin_proof() -> std::sync::MutexGuard<'static, ()> {
    let guard = PROVER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    parallel::init();
    guard
}

// leanVM's carry-less-multiply field arithmetic is about 68x slower without these features. An
// environment RUSTFLAGS replaces .cargo/config.toml's target-cpu=native instead of adding to it, so
// refuse to build a backend that silently lost them.
#[cfg(any(
    all(target_arch = "x86_64", not(target_feature = "pclmulqdq")),
    all(target_arch = "aarch64", not(target_feature = "aes"))
))]
compile_error!(
    "nethermind_lean needs carry-less multiply: build from tools/lean-ffi so .cargo/config.toml \
     applies, or include -C target-cpu=native (or +pclmulqdq / +aes) in RUSTFLAGS"
);
static ACTIVE_ABI_CALLS: AtomicUsize = AtomicUsize::new(0);
static ABI_WORKERS: OnceLock<Vec<ThreadId>> = OnceLock::new();
thread_local! { static IN_ABI: Cell<bool> = const { Cell::new(false) }; }
thread_local! { static LAST_PANIC: RefCell<String> = const { RefCell::new(String::new()) }; }
type Dep = [u8; 96];
const LEAN_SPHINCS: u8 = 0x10;
/// EIP-8288 reserves this scheme; accepting it is an experimental extension of this stack.
const LEAN_STARK: u8 = 0x11;

pub fn keccak(bytes: &[u8]) -> [u8; 32] {
    primitives::hash::hash(bytes)
}

pub fn aggregated_vk(guest: Guest) -> [u8; 32] {
    rec_aggregation::aggregated_vk(guest)
}

/// The key of the guest an ABI call names: guest 0 is the ABI 12 package's EIP-8288 guest ([`base`]), not this crate's
/// `Guest::Base`.
pub fn abi_aggregated_vk(guest: Guest) -> [u8; 32] {
    match guest {
        Guest::Base => base::aggregated_vk(),
        Guest::Batched => aggregated_vk(guest),
    }
}
fn abi_verify(guest: Guest, hash: &[u8; 32], proof: &[u8]) -> Result<(), ()> {
    match guest {
        Guest::Base => base::verify_aggregate(hash, proof),
        Guest::Batched => verify_aggregate(guest, hash, proof),
    }
}
fn abi_prove(guest: Guest, hash: &[u8; 32], input: &[u8]) -> Result<Vec<u8>, ()> {
    match guest {
        Guest::Base => base::prove_aggregate(hash, input),
        Guest::Batched => prove_aggregate(guest, hash, input),
    }
}

/// The aggregation program an ABI call names: 0 for EIP-8288's, 1 for the one with ethereum/EIPs#12664 batch pricing.
fn guest_of(id: u32) -> Result<Guest, ()> {
    match id {
        0 => Ok(Guest::Base),
        1 => Ok(Guest::Batched),
        _ => Err(()),
    }
}

/// EIP-8288 `get_batch_hash`: a batch leaf's public statement over its claims.
pub fn batch_hash(claims: &[[u8; 32]]) -> [u8; 32] {
    rec_aggregation::batch_hash(claims)
}

struct Reader<'a> {
    guest: Guest,
    bytes: &'a [u8],
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ()> {
        if n > self.bytes.len() {
            return Err(());
        }
        let (a, b) = self.bytes.split_at(n);
        self.bytes = b;
        Ok(a)
    }
    fn number(&mut self) -> Result<usize, ()> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().map_err(|_| ())?) as usize)
    }
    fn count(&mut self) -> Result<usize, ()> {
        let n = self.number()?;
        if n > MAX_DEPS { Err(()) } else { Ok(n) }
    }
    fn blob(&mut self) -> Result<&'a [u8], ()> {
        let n = self.number()?;
        if n > MAX_BYTES {
            return Err(());
        }
        self.take(n)
    }
    fn dep(&mut self) -> Result<Dep, ()> {
        let d: Dep = self.take(96)?.try_into().map_err(|_| ())?;
        if !known_scheme(self.guest, &d) {
            return Err(());
        }
        Ok(d)
    }
    fn deps(&mut self) -> Result<Vec<Dep>, ()> {
        (0..self.count()?).map(|_| self.dep()).collect()
    }
    /// A 192-byte record: a dependency, then its source payment for a batch claim and zeros otherwise.
    fn record(&mut self) -> Result<Record, ()> {
        let dep = self.dep()?;
        let source: Dep = self.take(96)?.try_into().map_err(|_| ())?;
        let valid = if dep[31] == BATCHED_LEANSTARK_SCHEME {
            known_scheme(self.guest, &source)
                && source[31] == LEANSTARK_LEAF_PAYMENT_SCHEME
                && key(&source) == key(&dep)
        } else {
            source == [0; 96]
        };
        if valid { Ok((dep, source)) } else { Err(()) }
    }
    fn records(&mut self) -> Result<Vec<Record>, ()> {
        (0..self.count()?).map(|_| self.record()).collect()
    }
    fn end(self) -> Result<(), ()> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(())
        }
    }
}

/// Whether `dep` is one `guest` accepts: 31 zero bytes, then leanSPHINCS or leanSTARK, and under [`Guest::Batched`] the
/// ethereum/EIPs#12664 batch claim, or leaf payment with a nonzero digest.
fn known_scheme(guest: Guest, dep: &Dep) -> bool {
    dep[..31].iter().all(|b| *b == 0)
        && match dep[31] {
            LEAN_SPHINCS | LEAN_STARK => true,
            BATCHED_LEANSTARK_SCHEME => guest == Guest::Batched,
            LEANSTARK_LEAF_PAYMENT_SCHEME => guest == Guest::Batched && data(dep) != [0; 32],
            _ => false,
        }
}
/// EIP-8288 leanSPHINCS `verification_key_hash`: the key itself, root then public parameter.
pub fn verification_key(pk: &LeanSphincsPublicKey) -> [u8; 32] {
    let mut out = [0; 32];
    out[..16].copy_from_slice(&pk.root);
    out[16..].copy_from_slice(&pk.public_param);
    out
}
fn public_key(vk: &[u8; 32]) -> LeanSphincsPublicKey {
    LeanSphincsPublicKey {
        root: vk[..16].try_into().unwrap(),
        public_param: vk[16..].try_into().unwrap(),
    }
}
fn data(dep: &Dep) -> [u8; 32] {
    dep[32..64].try_into().unwrap()
}
fn key(dep: &Dep) -> [u8; 32] {
    dep[64..].try_into().unwrap()
}
/// A dependency and, for a batch claim, its source: the payment of the leaf that established it (ethereum/EIPs#12664);
/// zeros for any other scheme.
type Record = (Dep, Dep);

/// A record's leanSTARK list entry in an intermediate statement: a batch claim keyed by its source, anything else as in a
/// finalized one.
fn state_entry((dep, source): &Record) -> ([u8; 32], [u8; 32]) {
    match dep[31] {
        BATCHED_LEANSTARK_SCHEME => (
            data(dep),
            rec_aggregation::batch_claim_key(&key(dep), &data(source)),
        ),
        _ => final_entry(dep),
    }
}
/// A dependency's leanSTARK list entry in a finalized statement, what block validation computes from the dependency
/// alone: a batch claim keyed by `rec_aggregation::finalized_claim_key`, a payment by `rec_aggregation::payment_key`.
fn final_entry(dep: &Dep) -> ([u8; 32], [u8; 32]) {
    match dep[31] {
        BATCHED_LEANSTARK_SCHEME => (data(dep), rec_aggregation::finalized_claim_key(&key(dep))),
        LEANSTARK_LEAF_PAYMENT_SCHEME => (data(dep), rec_aggregation::payment_key(&key(dep))),
        _ => (data(dep), key(dep)),
    }
}
fn lean_sphincs_claims(deps: impl Iterator<Item = Dep>) -> Vec<rec_aggregation::LeanSphincsClaim> {
    let mut claims: Vec<_> = deps
        .filter(|dep| dep[31] == LEAN_SPHINCS)
        .map(|dep| (data(&dep), public_key(&key(&dep))))
        .collect();
    claims.sort();
    claims
}
/// The claims of an intermediate statement over `records`.
fn state_claims(records: &[Record]) -> EthereumClaims {
    let mut generic: Vec<_> = records
        .iter()
        .filter(|(dep, _)| dep[31] != LEAN_SPHINCS)
        .map(state_entry)
        .collect();
    generic.sort();
    EthereumClaims {
        lean_sphincs: lean_sphincs_claims(records.iter().map(|(dep, _)| *dep)),
        generic,
        ..Default::default()
    }
}
/// Whether `deps` hold a batch claim or leaf payment, whose block is proved against [`final_statement`].
fn has_batch_schemes(deps: impl IntoIterator<Item = Dep>) -> bool {
    deps.into_iter().any(|dep| {
        matches!(
            dep[31],
            BATCHED_LEANSTARK_SCHEME | LEANSTARK_LEAF_PAYMENT_SCHEME
        )
    })
}
/// The dependency digest of a canonical list, `block_deps_hash` as block validation computes it: EIP-8288 `get_deps_hash`
/// for a leanSPHINCS-only list, else the split-domain digest of `rec_aggregation::deps_hash`, each batch-pricing entry keyed
/// by its scheme.
pub fn commitment(ds: &[Dep]) -> [u8; 32] {
    let mut generic: Vec<_> = ds
        .iter()
        .filter(|dep| dep[31] != LEAN_SPHINCS)
        .map(final_entry)
        .collect();
    generic.sort();
    rec_aggregation::deps_hash(&lean_sphincs_claims(ds.iter().copied()), &generic)
}
/// The statement a finalized proof of `ds` carries: ethereum/EIPs#12664 `get_batch_final_hash(commitment(ds))`, what a
/// block holding either new scheme is verified against.
pub fn final_statement(ds: &[Dep]) -> [u8; 32] {
    rec_aggregation::batch_final_hash(&commitment(ds))
}
/// The digest of an intermediate statement over `records`, ethereum/EIPs#12664 `get_batch_state_hash` in this guest's
/// form: [`commitment`]'s, each batch claim bound to its source. Without batch claims it is [`commitment`].
pub fn state_commitment(records: &[Record]) -> [u8; 32] {
    let claims = state_claims(records);
    rec_aggregation::deps_hash(&claims.lean_sphincs, &claims.generic)
}
#[cfg(test)]
fn canonical(ds: Vec<Dep>) -> Vec<Dep> {
    ds.into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
fn parse_sphincs(
    vk: &[u8; 32],
    witness: &[u8],
) -> Result<(LeanSphincsPublicKey, LeanSphincsSignature), ()> {
    if witness.len() != lean_sphincs::PUB_KEY_SIZE + lean_sphincs::SIG_SIZE || witness[..32] != *vk
    {
        return Err(());
    }
    let sig = LeanSphincsSignature::from_bytes(witness[32..].try_into().map_err(|_| ())?);
    Ok((public_key(vk), sig))
}
fn verify_sphincs(hash: &[u8; 32], vk: &[u8; 32], witness: &[u8]) -> bool {
    parse_sphincs(vk, witness).is_ok_and(|(pk, sig)| lean_sphincs::verify(&pk, hash, &sig).is_ok())
}
/// A direct witness of `dep`: a leanSTARK one is a one-claim leaf, which may also establish the batch claim on its claim.
fn verify_witness(dep: &Dep, witness: &[u8]) -> bool {
    match dep[31] {
        LEAN_SPHINCS => verify_sphincs(&data(dep), &key(dep), witness),
        _ => rec_aggregation::verify_generic(&data(dep), &key(dep), witness),
    }
}
/// The record of a direct dependency: a batch claim's source is its singleton leaf's payment.
fn direct_record(dep: Dep) -> Record {
    if dep[31] != BATCHED_LEANSTARK_SCHEME {
        return (dep, [0; 96]);
    }
    (
        dep,
        dependency(
            LEANSTARK_LEAF_PAYMENT_SCHEME,
            &batch_hash(&[data(&dep)]),
            &key(&dep),
        ),
    )
}
fn dependency(scheme: u8, data: &[u8; 32], key: &[u8; 32]) -> Dep {
    let mut dep = [0; 96];
    dep[31] = scheme;
    dep[32..64].copy_from_slice(data);
    dep[64..].copy_from_slice(key);
    dep
}

/// A leanVM program that accepts every public input: the leanSTARK dependency anyone can prove. For tests and fixtures.
pub const ANY_INPUT_PROGRAM: &str = "def main():\n    h = StackBuf(2)\n    hint_witness(h, \"pi\")\n    p = 1\n    p[1] = h[0]\n    p[GEN] = h[1]\n    return\n";

/// Compiles `source`, a leanVM program reading its public input from the `pi` hint, and proves it on `hash`: the
/// leanSTARK witness and verification key `guest` takes for the batch leaf whose `batch_hash(claims)` is `hash`, so of
/// the dependency `(data_hash, key)` for `hash = batch_hash(&[data_hash])`. Guest 0 keys a program by its flat table
/// digest, guest 1 by its committed bytecode key. For tests and fixtures.
pub fn prove_stark(guest: Guest, source: &str, hash: &[u8; 32]) -> Result<(Vec<u8>, [u8; 32]), ()> {
    let _guard = begin_proof();
    let program = lean_compiler::compile(&lean_compiler::parse(source).map_err(|_| ())?);
    let mut program = match guest {
        Guest::Base => program,
        Guest::Batched => program.committed(),
    };
    let table: Vec<u64> = leanvm_core::cpu::bytecode_table(program.prog())
        .iter()
        .map(|word| word.0)
        .collect();
    let input = fiat_shamir::merkle::hash_to_scalars(hash);
    program.set_witness("pi", vec![input.to_vec()]);
    let (proof, _) = leanvm_core::cpu::prove(&program, input, LOG_INV_RATE).map_err(|_| ())?;
    match guest {
        Guest::Base => Ok((
            rec_aggregation_base::generic_witness(&table, &proof).ok_or(())?,
            rec_aggregation_base::generic_verification_key(&table).ok_or(())?,
        )),
        Guest::Batched => Ok((
            rec_aggregation::generic_witness(&table, &proof).ok_or(())?,
            rec_aggregation::generic_verification_key(&table).ok_or(())?,
        )),
    }
}

// EIP-8288 `stark_proof`: the guest proof alone, checked against `deps_hash` and the pinned key.
// The empty proof of an empty list never reaches the guest: callers decide that case themselves.
fn verify_aggregate(guest: Guest, hash: &[u8; 32], proof: &[u8]) -> Result<(), ()> {
    if proof.is_empty() || proof.len() > MAX_BYTES {
        return Err(());
    }
    rec_aggregation::verify_deps_hash(guest, hash, proof).map_err(|_| ())
}

// A recursive child is proven against its declared dependencies, which the caller supplies.
fn decode_child(guest: Guest, records: &[Record], proof: &[u8]) -> Result<EthereumProof, ()> {
    if proof.is_empty() || proof.len() > MAX_BYTES {
        return Err(());
    }
    let proof =
        EthereumProof::from_proof_bytes(guest, proof, state_claims(records)).map_err(|_| ())?;
    proof.verify().map_err(|_| ())?;
    Ok(proof)
}

/// A leaf of the aggregation input with the records it establishes.
type InputLeaf = (BatchLeaf, Vec<Record>);

/// Proves `hash` from `input`: the intermediate statement of the selected records ([`state_commitment`]), or, when they
/// hold a batch claim or payment, their dependencies' [`final_statement`], every batch claim's source payment among them
/// (ethereum/EIPs#12664). Without either scheme the intermediate statement is the ordinary [`commitment`].
pub fn prove_aggregate(guest: Guest, hash: &[u8; 32], input: &[u8]) -> Result<Vec<u8>, ()> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(());
    }
    if input == [0; 12] {
        return if *hash == commitment(&[]) {
            Ok(vec![])
        } else {
            Err(())
        };
    }
    let _guard = begin_proof();
    let mut r = Reader {
        guest,
        bytes: input,
    };
    let mut all: Vec<Record> = Vec::new();
    let mut raw = Vec::new();
    // EIP-8288 MAX_INNER_PROOFS_PER_STEP: every supplied leanSTARK proof, a direct one as a singleton leaf, and every
    // child, discarded or redundant ones included; leanSPHINCS witnesses do not count.
    let mut inner_proofs = 0;
    for _ in 0..r.count()? {
        let dep = r.dep()?;
        // A payment's digest is a leaf statement, which a direct proof of one claim does not show.
        if dep[31] == LEANSTARK_LEAF_PAYMENT_SCHEME {
            return Err(());
        }
        inner_proofs += usize::from(dep[31] != LEAN_SPHINCS);
        let record = direct_record(dep);
        raw.push((record, r.blob()?));
        all.push(record);
    }
    let child_count = r.count()?;
    inner_proofs += child_count;
    if inner_proofs > MAX_INNER_PROOFS_PER_STEP {
        return Err(());
    }
    let mut children = Vec::new();
    for _ in 0..child_count {
        let declared: Vec<Record> = r
            .records()?
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let proof = r.blob()?;
        if declared.is_empty() {
            if !proof.is_empty() {
                return Err(());
            }
            continue;
        }
        children.push((
            decode_child(guest, &declared, proof)?,
            proof,
            declared.clone(),
        ));
        all.extend(declared);
    }
    let discards: HashSet<Record> = r.records()?.into_iter().collect();
    // An optional trailing section carries leaves; it is absent when there are none.
    let mut leaves: Vec<InputLeaf> = Vec::new();
    if !r.bytes.is_empty() {
        let leaf_count = r.number()?;
        inner_proofs += leaf_count;
        if leaf_count == 0 || inner_proofs > MAX_INNER_PROOFS_PER_STEP {
            return Err(());
        }
        for _ in 0..leaf_count {
            let leaf = leaf(&mut r)?;
            all.extend(&leaf.1);
            leaves.push(leaf);
        }
    }
    r.end()?;
    let union: HashSet<_> = all.iter().copied().collect();
    if !discards.is_subset(&union) {
        return Err(());
    }
    let candidates: BTreeSet<Record> = all
        .into_iter()
        .filter(|record| !discards.contains(record))
        .collect();
    let records = select_sources(candidates);
    let deps: Vec<Dep> = records.iter().map(|(dep, _)| *dep).collect();
    if deps.len() > MAX_DEPS {
        return Err(());
    }
    let finalize = if *hash == state_commitment(&records) {
        false
    } else if has_batch_schemes(deps.iter().copied()) && *hash == final_statement(&deps) {
        let present: HashSet<Dep> = deps.iter().copied().collect();
        if records
            .iter()
            .any(|(dep, source)| dep[31] == BATCHED_LEANSTARK_SCHEME && !present.contains(source))
        {
            return Err(());
        }
        true
    } else {
        return Err(());
    };
    let kept: HashSet<Record> = records.iter().copied().collect();
    children.retain(|(_, _, declared)| declared.iter().any(|record| kept.contains(record)));
    let covered: HashSet<Record> = children
        .iter()
        .flat_map(|(_, _, declared)| declared.iter().copied())
        .collect();
    // The guest checks only the witnesses it is given; one that a child covers or a discard drops is checked here,
    // so an invalid witness fails the call whether or not the proof needs it.
    let (raw, unused): (Vec<_>, Vec<_>) = raw
        .into_iter()
        .partition(|(record, _)| kept.contains(record) && !covered.contains(record));
    if unused
        .iter()
        .any(|((dep, _), witness)| !verify_witness(dep, witness))
    {
        return Err(());
    }
    // A leaf proves when one of its records is kept and not yet covered; it publishes only the kept ones. Every other
    // leaf is checked here, so every leaf meets the verifier's bounds even when all its claims are discarded.
    let (leaves, unused): (Vec<_>, Vec<_>) = leaves.into_iter().partition(|(_, established)| {
        established
            .iter()
            .any(|record| kept.contains(record) && !covered.contains(record))
    });
    if unused
        .iter()
        .any(|((claims, vk, witness), _)| !verify_batch_leaf(guest, claims, vk, witness))
    {
        return Err(());
    }
    if records.is_empty() {
        return Ok(vec![]);
    }
    if !finalize
        && let Some((_, bytes, _)) = children
            .iter()
            .find(|(_, _, declared)| *declared == records)
    {
        return Ok(bytes.to_vec());
    }
    // The sources a child carries; a leaf's own the guest's host derives.
    let sources: Vec<([u8; 32], [u8; 32])> = covered
        .iter()
        .filter(|(dep, _)| dep[31] == BATCHED_LEANSTARK_SCHEME)
        .map(|(_, source)| (key(source), data(source)))
        .collect();
    let mut signatures = Vec::new();
    let mut generic: Vec<BatchLeaf> = leaves.into_iter().map(|(leaf, _)| leaf).collect();
    for ((dep, _), witness) in raw {
        if dep[31] == LEAN_SPHINCS {
            let (pk, signature) = parse_sphincs(&key(&dep), witness)?;
            signatures.push((pk, data(&dep), signature));
        } else {
            generic.push((vec![data(&dep)], key(&dep), witness.to_vec()));
        }
    }
    let children: Vec<_> = children.into_iter().map(|(child, ..)| child).collect();
    let declare = state_claims(&records);
    let proof = if finalize {
        rec_aggregation::aggregate_finalized(
            guest,
            &children,
            generic,
            signatures,
            &declare,
            &sources,
            LOG_INV_RATE,
        )
    } else {
        rec_aggregation::aggregate(
            guest,
            &children,
            generic,
            signatures,
            &[],
            Some(&declare),
            LOG_INV_RATE,
        )
    }
    .map_err(|_| ())?
    .proof_bytes();
    if proof.len() > MAX_BYTES {
        return Err(());
    }
    Ok(proof)
}

/// Records deduplicated by dependency (ethereum/EIPs#12664): of a batch claim several verified inputs source, the prover
/// keeps one whose payment is among the retained dependencies, else the least.
fn select_sources(candidates: BTreeSet<Record>) -> Vec<Record> {
    let deps: HashSet<Dep> = candidates.iter().map(|(dep, _)| *dep).collect();
    let mut records: Vec<Record> = Vec::with_capacity(deps.len());
    for (dep, source) in candidates {
        match records.last_mut() {
            Some(last) if last.0 == dep => {
                if !deps.contains(&last.1) && deps.contains(&source) {
                    last.1 = source;
                }
            }
            _ => records.push((dep, source)),
        }
    }
    records
}

/// One leaf of the input's trailing section: its key, claims, the dependencies it establishes, then its witness. Each
/// dependency is on a claim of the leaf under its key, leanSTARK or a batch claim, whose source is the leaf's payment, or
/// that payment itself.
fn leaf(r: &mut Reader) -> Result<InputLeaf, ()> {
    let vk: [u8; 32] = r.take(32)?.try_into().map_err(|_| ())?;
    let claim_count = r.number()?;
    if !(1..=r.guest.max_claims_per_leaf()).contains(&claim_count) {
        return Err(());
    }
    let claims = (0..claim_count)
        .map(|_| r.take(32)?.try_into().map_err(|_| ()))
        .collect::<Result<Vec<[u8; 32]>, ()>>()?;
    if !valid_batch_claims(r.guest, &claims) {
        return Err(());
    }
    let payment = dependency(LEANSTARK_LEAF_PAYMENT_SCHEME, &batch_hash(&claims), &vk);
    let established = r.deps()?;
    let establishes = |dep: &Dep| {
        key(dep) == vk
            && match dep[31] {
                LEAN_STARK | BATCHED_LEANSTARK_SCHEME => claims.binary_search(&data(dep)).is_ok(),
                LEANSTARK_LEAF_PAYMENT_SCHEME => *dep == payment,
                _ => false,
            }
    };
    if established.is_empty() || !established.iter().all(establishes) {
        return Err(());
    }
    let records = established
        .into_iter()
        .map(|dep| {
            let source = if dep[31] == BATCHED_LEANSTARK_SCHEME {
                payment
            } else {
                [0; 96]
            };
            (dep, source)
        })
        .collect();
    Ok(((claims, vk, r.blob()?.to_vec()), records))
}

unsafe fn bytes<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], ()> {
    unsafe { bytes_with_limit(ptr, len, MAX_BYTES) }
}
unsafe fn bytes_with_limit<'a>(ptr: *const u8, len: usize, limit: usize) -> Result<&'a [u8], ()> {
    if len > limit || (ptr.is_null() && len != 0) {
        return Err(());
    }
    if len == 0 {
        Ok(&[])
    } else {
        Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
    }
}
/// Runs one ABI call: returns 1 for accepted, 0 for rejected input and -1 for a contained panic,
/// so callers never read a fault as a verdict. The panic message stays readable through `nlean_last_error`. Every `checked` export shares this contract, including
/// `nlean_aggregated_vk` and `nlean_prove_recursive`, where the C# side accepts only `== 1` as success.
fn checked(f: impl FnOnce() -> Result<bool, ()>) -> i32 {
    static HOOK: OnceLock<()> = OnceLock::new();
    struct CallGuard(bool);
    impl Drop for CallGuard {
        fn drop(&mut self) {
            ACTIVE_ABI_CALLS.fetch_sub(1, Ordering::AcqRel);
            IN_ABI.with(|flag| flag.set(self.0));
        }
    }
    let _guard = CallGuard(IN_ABI.with(|flag| flag.replace(true)));
    ACTIVE_ABI_CALLS.fetch_add(1, Ordering::AcqRel);
    LAST_PANIC.with(|message| message.borrow_mut().clear());
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        HOOK.get_or_init(|| {
            let previous = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                let abi_worker = ACTIVE_ABI_CALLS.load(Ordering::Acquire) != 0
                    && ABI_WORKERS
                        .get()
                        .is_some_and(|workers| workers.contains(&std::thread::current().id()));
                if !IN_ABI.with(Cell::get) && !abi_worker {
                    previous(info);
                }
            }));
        });
        ABI_WORKERS.get_or_init(|| {
            let dispatcher = std::thread::current().id();
            parallel::init();
            let count = parallel::num_threads();
            let barrier = Barrier::new(count);
            let workers = Mutex::new(Vec::new());
            // One blocked task per worker identifies this pinned pool without thread-name assumptions.
            parallel::for_each(count, |_| {
                let id = std::thread::current().id();
                if id != dispatcher {
                    workers.lock().unwrap().push(id);
                }
                barrier.wait();
            });
            workers.into_inner().unwrap()
        });
        f()
    }))
    .map_or_else(
        |payload| {
            let message = payload
                .downcast_ref::<&str>()
                .map(|text| text.to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "non-string panic payload".to_string());
            LAST_PANIC.with(|last| *last.borrow_mut() = message);
            -1
        },
        |verdict| verdict.unwrap_or(false) as i32,
    )
}
#[unsafe(no_mangle)]
pub extern "C" fn nlean_abi_version() -> u32 {
    16
}
/// Copies up to `len` bytes of the calling thread's last contained panic message into `out` and returns its full
/// length; empty unless that thread's latest `checked` call returned -1.
///
/// # Safety
/// `out` must reference `len` writable bytes, or be null with `len` 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nlean_last_error(out: *mut u8, len: usize) -> usize {
    LAST_PANIC.with(|message| {
        let message = message.borrow();
        let copied = message.len().min(len);
        if !out.is_null() {
            // SAFETY: copied <= len, and the caller guarantees `out` holds len writable bytes.
            unsafe { std::ptr::copy_nonoverlapping(message.as_ptr(), out, copied) };
        }
        message.len()
    })
}
/// Writes the seven limits of `guest` ([`guest_of`]): ABI 12's for EIP-8288's guest, whose sixth is its leanSTARK
/// dependencies per list, and for the batch-pricing guest the claims per batch leaf in that place.
///
/// # Safety
/// Output must hold seven writable u32 values.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nlean_limits(guest: u32, out: *mut u32, len: usize) -> i32 {
    if out.is_null() || len != 7 {
        return 0;
    }
    let limits = match guest_of(guest) {
        Ok(Guest::Base) => base::limits(),
        Ok(Guest::Batched) => [
            MAX_BYTES as u32,
            MAX_DEPS as u32,
            MAX_INNER_PROOFS_PER_STEP as u32,
            (lean_sphincs::PUB_KEY_SIZE + lean_sphincs::SIG_SIZE) as u32,
            MAX_INPUT_BYTES as u32,
            MAX_CLAIMS_PER_BATCH_LEAF as u32,
            1 << MAX_GENERIC_BYTECODE_LOG,
        ],
        Err(()) => return 0,
    };
    unsafe {
        std::ptr::copy_nonoverlapping(limits.as_ptr(), out, limits.len());
    }
    1
}
/// Writes the `AGGREGATED_VK` of `guest` ([`guest_of`]).
///
/// # Safety
/// Input pointers must reference their declared lengths; output pointers must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nlean_aggregated_vk(guest: u32, out: *mut u8) -> i32 {
    if out.is_null() {
        return 0;
    }
    checked(|| {
        let key = abi_aggregated_vk(guest_of(guest)?);
        unsafe {
            std::ptr::copy_nonoverlapping(key.as_ptr(), out, 32);
        }
        Ok(true)
    })
}
/// # Safety
/// Input pointers must reference their declared lengths; output pointers must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nlean_verify_leansphincs(
    data: *const u8,
    vk: *const u8,
    witness: *const u8,
    len: usize,
) -> i32 {
    checked(|| {
        Ok(verify_sphincs(
            unsafe { bytes(data, 32)? }.try_into().map_err(|_| ())?,
            unsafe { bytes(vk, 32)? }.try_into().map_err(|_| ())?,
            unsafe { bytes(witness, len)? },
        ))
    })
}
/// Verifies a direct leanSTARK witness as `guest` ([`guest_of`]) takes one: EIP-8288's guest on the bare claim, the
/// batch-pricing guest on `get_claim_hash(claim)`.
///
/// # Safety
/// Input pointers must reference their declared lengths; output pointers must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nlean_verify_leanstark(
    guest: u32,
    data: *const u8,
    vk: *const u8,
    witness: *const u8,
    len: usize,
) -> i32 {
    checked(|| {
        let data: &[u8; 32] = unsafe { bytes(data, 32)? }.try_into().map_err(|_| ())?;
        let vk: &[u8; 32] = unsafe { bytes(vk, 32)? }.try_into().map_err(|_| ())?;
        let witness = unsafe { bytes(witness, len)? };
        Ok(match guest_of(guest)? {
            Guest::Base => rec_aggregation_base::verify_generic(data, vk, witness),
            Guest::Batched => rec_aggregation::verify_generic(data, vk, witness),
        })
    })
}
/// Verifies a proof of `guest` ([`guest_of`]), whose key must be `vk`.
///
/// # Safety
/// Input pointers must reference their declared lengths; output pointers must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nlean_verify_recursive(
    guest: u32,
    hash: *const u8,
    vk: *const u8,
    vk_len: usize,
    proof: *const u8,
    len: usize,
) -> i32 {
    checked(|| {
        let guest = guest_of(guest)?;
        if unsafe { bytes(vk, vk_len)? } != abi_aggregated_vk(guest) {
            return Ok(false);
        }
        let expected = unsafe { bytes(hash, 32)? }.try_into().map_err(|_| ())?;
        abi_verify(guest, expected, unsafe { bytes(proof, len)? })?;
        Ok(true)
    })
}
/// Proves with `guest` ([`guest_of`]), whose key must be `vk`.
///
/// # Safety
/// Input pointers must reference their declared lengths; output pointers must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nlean_prove_recursive(
    guest: u32,
    hash: *const u8,
    vk: *const u8,
    vk_len: usize,
    input: *const u8,
    input_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    checked(|| {
        let guest = guest_of(guest)?;
        if out.is_null()
            || out_len.is_null()
            || unsafe { bytes(vk, vk_len)? } != abi_aggregated_vk(guest)
        {
            return Ok(false);
        }
        let proof = abi_prove(
            guest,
            unsafe { bytes(hash, 32)? }.try_into().map_err(|_| ())?,
            unsafe { bytes_with_limit(input, input_len, MAX_INPUT_BYTES)? },
        )?;
        let boxed = proof.into_boxed_slice();
        let len = boxed.len();
        let ptr = Box::into_raw(boxed) as *mut u8;
        unsafe {
            *out = ptr;
            *out_len = len;
        }
        Ok(true)
    })
}
/// # Safety
/// The pointer and length must be the exact allocation returned by nlean_prove_recursive, freed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nlean_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        unsafe {
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: Guest = Guest::Base;
    const BATCHED: Guest = Guest::Batched;

    fn leanstark_dependency(claim: &[u8; 32], vk: &[u8; 32]) -> Dep {
        let mut dep = [0; 96];
        dep[31] = LEAN_STARK;
        dep[32..64].copy_from_slice(claim);
        dep[64..].copy_from_slice(vk);
        dep
    }
    fn signed(index: u8) -> (Dep, Vec<u8>) {
        let (sk, pk) = lean_sphincs::key_gen_from_seed([index; 32]);
        let message = keccak(&[index]);
        let mut dep = [0; 96];
        dep[31] = 0x10;
        dep[32..64].copy_from_slice(&message);
        dep[64..].copy_from_slice(&verification_key(&pk));
        let signature = lean_sphincs::sign(&sk, &message).unwrap();
        (
            dep,
            [&verification_key(&pk)[..], &signature.to_bytes()[..]].concat(),
        )
    }
    fn put_number(out: &mut Vec<u8>, n: usize) {
        out.extend_from_slice(&(n as u32).to_le_bytes());
    }
    fn input(raw: &[(Dep, Vec<u8>)], children: &[(&[Dep], &[u8])], discards: &[Dep]) -> Vec<u8> {
        input_with_leaves(raw, children, discards, &[])
    }
    /// A leaf in the aggregation input: key, claims, the dependencies it establishes, witness.
    type LeafEntry<'a> = ([u8; 32], &'a [[u8; 32]], Vec<Dep>, &'a [u8]);
    /// A leaf establishing each of its claims' ordinary dependency.
    fn ordinary<'a>(key: [u8; 32], claims: &'a [[u8; 32]], witness: &'a [u8]) -> LeafEntry<'a> {
        (
            key,
            claims,
            claims
                .iter()
                .map(|claim| leanstark_dependency(claim, &key))
                .collect(),
            witness,
        )
    }
    /// Records of dependencies other than batch claims.
    fn plain(deps: &[Dep]) -> Vec<Record> {
        deps.iter().map(|dep| (*dep, [0; 96])).collect()
    }
    /// The aggregation input with its trailing batch-leaf section, children and discards without batch claims.
    fn input_with_leaves(
        raw: &[(Dep, Vec<u8>)],
        children: &[(&[Dep], &[u8])],
        discards: &[Dep],
        leaves: &[LeafEntry],
    ) -> Vec<u8> {
        let children: Vec<(Vec<Record>, &[u8])> = children
            .iter()
            .map(|(deps, proof)| (plain(deps), *proof))
            .collect();
        let children: Vec<(&[Record], &[u8])> = children
            .iter()
            .map(|(records, proof)| (&records[..], *proof))
            .collect();
        input_records(raw, &children, &plain(discards), leaves)
    }
    /// The aggregation input, children and discards as records.
    fn input_records(
        raw: &[(Dep, Vec<u8>)],
        children: &[(&[Record], &[u8])],
        discards: &[Record],
        leaves: &[LeafEntry],
    ) -> Vec<u8> {
        let flat = |records: &[Record]| -> Vec<u8> {
            records
                .iter()
                .flat_map(|(d, s)| d.iter().chain(s).copied())
                .collect()
        };
        let mut out = Vec::new();
        put_number(&mut out, raw.len());
        for (dep, witness) in raw {
            out.extend_from_slice(dep);
            put_number(&mut out, witness.len());
            out.extend_from_slice(witness);
        }
        put_number(&mut out, children.len());
        for (records, proof) in children {
            put_number(&mut out, records.len());
            out.extend(flat(records));
            put_number(&mut out, proof.len());
            out.extend_from_slice(proof);
        }
        put_number(&mut out, discards.len());
        out.extend(flat(discards));
        if !leaves.is_empty() {
            put_number(&mut out, leaves.len());
            for (key, claims, deps, witness) in leaves {
                out.extend_from_slice(key);
                put_number(&mut out, claims.len());
                out.extend(claims.iter().flatten());
                put_number(&mut out, deps.len());
                out.extend(deps.iter().flatten());
                put_number(&mut out, witness.len());
                out.extend_from_slice(witness);
            }
        }
        out
    }
    fn hash_of(deps: &[Dep]) -> [u8; 32] {
        commitment(&canonical(deps.to_vec()))
    }

    #[test]
    fn commitment_is_keccak_of_the_64_byte_entries() {
        let deps = canonical((0..3).map(|i| signed(i).0).collect());
        let entries: Vec<u8> = deps.iter().flat_map(|d| d[32..].iter().copied()).collect();
        assert_eq!(commitment(&deps), keccak(&entries));
        assert_eq!(commitment(&[]), keccak(&[]));
    }

    #[test]
    fn empty_list_has_the_empty_proof_and_never_reaches_the_guest() {
        let hash = commitment(&[]);
        assert!(prove_aggregate(BASE, &hash, &[0; 12]).unwrap().is_empty());
        assert!(prove_aggregate(BASE, &[1; 32], &[0; 12]).is_err());
        assert!(verify_aggregate(BASE, &hash, &[]).is_err());
    }

    fn proven(index: u8) -> (Dep, Vec<u8>) {
        let message = keccak(&[0x51, index]);
        let (witness, key) = prove_stark(BATCHED, ANY_INPUT_PROGRAM, &batch_hash(&[message])).unwrap();
        (leanstark_dependency(&message, &key), witness)
    }

    /// A leaf of `claims` under the accept-all program's key, and that key.
    fn batch(claims: &[[u8; 32]]) -> (Vec<u8>, [u8; 32]) {
        prove_stark(BATCHED, ANY_INPUT_PROGRAM, &batch_hash(claims)).unwrap()
    }

    #[test]
    fn exported_abi_and_limits() {
        assert_eq!(nlean_abi_version(), 16);
        let mut limits = [0u32; 7];
        assert_eq!(unsafe { nlean_limits(1, limits.as_mut_ptr(), 7) }, 1);
        assert_eq!(limits[2], 16, "MAX_INNER_PROOFS_PER_STEP");
        assert_eq!(limits[5], 256, "MAX_CLAIMS_PER_BATCH_LEAF");
        assert_eq!(limits[6], 2048, "leanSTARK instructions");
        assert_eq!(unsafe { nlean_limits(1, limits.as_mut_ptr(), 6) }, 0);
        assert_eq!(unsafe { nlean_limits(2, limits.as_mut_ptr(), 7) }, 0);
        // EIP-8288's guest keeps the ABI 12 package's limits.
        let mut base = [0u32; 7];
        assert_eq!(unsafe { nlean_limits(0, base.as_mut_ptr(), 7) }, 1);
        assert_eq!(base, [8 << 20, 256, 16, base[3], 18 << 20, 16, 2048]);
        // One key per guest, and no third guest.
        let mut keys = [[0u8; 32]; 3];
        let verdicts = [0, 1, 2]
            .map(|guest| unsafe { nlean_aggregated_vk(guest, keys[guest as usize].as_mut_ptr()) });
        assert_eq!(verdicts, [1, 1, 0]);
        assert_eq!(keys[0], base::aggregated_vk());
        assert_eq!(keys[1], aggregated_vk(BATCHED));
        assert_ne!(keys[0], keys[1]);
        // Guest 0 is EIP-8288's guest as the ABI 12 package pins it.
        let base: Vec<u8> = (0..32)
            .map(|i| {
                u8::from_str_radix(
                    &"f7cf74585d02043051f0575c23c6b441b0b08ac9e273f5e989c5984b8a4ac0e5"
                        [2 * i..2 * i + 2],
                    16,
                )
                .unwrap()
            })
            .collect();
        assert_eq!(keys[0].as_slice(), base.as_slice());
    }

    /// A direct leanSTARK witness is checked as the named guest takes it: guest 0 on the bare claim under the flat
    /// table key, as the ABI 12 package did, and guest 1 on `get_claim_hash(claim)` under the committed bytecode key,
    /// which rejects a proof of the bare claim and a flat-keyed witness.
    #[test]
    fn direct_leanstark_witnesses_follow_the_guest() {
        let claim = keccak(b"direct claim");
        let wrapped_claim = batch_hash(&[claim]);
        let (bare, flat_key) = prove_stark(BASE, ANY_INPUT_PROGRAM, &claim).unwrap();
        let (flat_wrapped, _) = prove_stark(BASE, ANY_INPUT_PROGRAM, &wrapped_claim).unwrap();
        let (committed_bare, committed_key) = prove_stark(BATCHED, ANY_INPUT_PROGRAM, &claim).unwrap();
        let (wrapped, _) = prove_stark(BATCHED, ANY_INPUT_PROGRAM, &wrapped_claim).unwrap();
        assert_ne!(flat_key, committed_key);
        let verify = |guest: u32, key: &[u8; 32], witness: &[u8]| unsafe {
            nlean_verify_leanstark(guest, claim.as_ptr(), key.as_ptr(), witness.as_ptr(), witness.len())
        };
        assert_eq!(
            [
                verify(0, &flat_key, &bare),
                verify(0, &flat_key, &flat_wrapped),
                verify(0, &committed_key, &wrapped),
                verify(1, &committed_key, &committed_bare),
                verify(1, &committed_key, &wrapped),
                verify(1, &flat_key, &flat_wrapped),
                verify(2, &committed_key, &wrapped)
            ],
            [1, 0, 0, 0, 1, 0, 0]
        );
    }

    /// EIP-8288 Test Cases 2 and 12, and ethereum/EIPs#12664: a batch leaf and singleton proofs under one key cover
    /// the same dependencies; the leaf's claim list is exact, and a discarded claim cannot come back.
    #[test]
    fn batch_leaf_and_singletons_prove_the_same_dependencies() {
        let (a, b, c) = ([0xa0; 32], [0xb0; 32], [0xc0; 32]);
        let (leaf, key) = batch(&[a, b]);
        let (single_a, key_a) = batch(&[a]);
        let (single_b, _) = batch(&[b]);
        assert_eq!(key, key_a);
        let deps = [
            leanstark_dependency(&a, &key),
            leanstark_dependency(&b, &key),
        ];
        let hash = commitment(&deps);
        assert!(verify_batch_leaf(BATCHED, &[a, b], &key, &leaf));
        let leaves = |entries: &[LeafEntry]| input_with_leaves(&[], &[], &[], entries);
        let batched_proof =
            prove_aggregate(BATCHED, &hash, &leaves(&[ordinary(key, &[a, b], &leaf)])).unwrap();
        let direct = [(deps[1], single_b.clone()), (deps[0], single_a)];
        let singles = prove_aggregate(BATCHED, &hash, &input(&direct, &[], &[])).unwrap();
        for proof in [&batched_proof, &singles] {
            verify_aggregate(BATCHED, &hash, proof).unwrap();
            assert!(
                verify_aggregate(BASE, &hash, proof).is_err(),
                "a proof of one guest is none of the other"
            );
        }
        // EIP-8288's guest takes no multi-claim leaf.
        assert!(prove_aggregate(BASE, &hash, &leaves(&[ordinary(key, &[a, b], &leaf)])).is_err());
        // One singleton alone, or a leaf under another key, does not satisfy both claims.
        assert!(prove_aggregate(BATCHED, &hash, &input(&direct[..1], &[], &[])).is_err());
        let other_key = (key, &[a, b][..], deps.to_vec(), &leaf[..]);
        assert!(
            prove_aggregate(
                BATCHED,
                &hash,
                &leaves(&[([7; 32], other_key.1, other_key.2.clone(), other_key.3)])
            )
            .is_err()
        );
        // The leaf statement binds the exact nonempty, strictly increasing claim list.
        for claims in [&[b, a][..], &[a, a], &[], &[a], &[a, b, c]] {
            assert!(
                prove_aggregate(
                    BATCHED,
                    &hash,
                    &leaves(&[(key, claims, deps.to_vec(), &leaf)])
                )
                .is_err()
            );
        }
        // Union with an overlapping leaf, then discard a: {b, c} is kept; a's proof alone cannot restore b.
        let (bc, _) = batch(&[b, c]);
        let retained = [deps[1], leanstark_dependency(&c, &key)];
        let (ab_claims, bc_claims) = ([a, b], [b, c]);
        let pair = [
            ordinary(key, &ab_claims, &leaf),
            ordinary(key, &bc_claims, &bc),
        ];
        let pruned = prove_aggregate(
            BATCHED,
            &commitment(&retained),
            &input_with_leaves(&[], &[], &deps[..1], &pair),
        )
        .unwrap();
        verify_aggregate(BATCHED, &commitment(&retained), &pruned).unwrap();
        let only_a = prove_aggregate(
            BATCHED,
            &commitment(&deps[..1]),
            &input_with_leaves(&[], &[], &deps[1..], &pair[..1]),
        )
        .unwrap();
        assert!(
            prove_aggregate(BATCHED, &hash, &input(&[], &[(&deps[..1], &only_a)], &[])).is_err()
        );
    }

    /// EIP-8288 `MAX_INNER_PROOFS_PER_STEP` counts direct leanSTARK proofs, batch leaves and children together,
    /// discarded and redundant ones included; leanSPHINCS witnesses do not count.
    #[test]
    fn inner_proofs_per_step_count_every_proof_kind() {
        let (stark, witness) = proven(1);
        let parent = prove_aggregate(
            BASE,
            &hash_of(&[stark]),
            &input(&[(stark, witness.clone())], &[], &[]),
        )
        .unwrap();
        let (leaf, leaf_key) = batch(&[[2; 32]]);
        let discarded = leanstark_dependency(&[2; 32], &leaf_key);
        let sig = signed(3);
        let step = |children: usize| {
            let deps = [stark];
            let children = vec![(&deps[..], &parent[..]); children];
            let raw = [(stark, witness.clone()), sig.clone()];
            let leaves = [ordinary(leaf_key, &[[2; 32]], &leaf)];
            prove_aggregate(
                BASE,
                &hash_of(&[stark]),
                &input_with_leaves(&raw, &children, &[discarded, sig.0], &leaves),
            )
        };
        // A child covering the statement is returned unchanged, so these calls prove nothing.
        assert_eq!(step(MAX_INNER_PROOFS_PER_STEP - 2).unwrap(), parent);
        assert!(step(MAX_INNER_PROOFS_PER_STEP - 1).is_err());
    }

    /// A batch leaf witness at the verifier's resource bounds, and one byte off them.
    fn bounded_witnesses(witness: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
        let mut over = witness.to_vec();
        over[0] = MAX_GENERIC_BYTECODE_LOG as u8 + 1;
        let mut short = witness.to_vec();
        short.remove(1);
        let mut long = witness.to_vec();
        long.push(0);
        vec![
            ("above the instruction bound", over),
            ("table one byte short", short),
            ("trailing byte", long),
        ]
    }

    /// EIP-8288 Test Case 12: every leaf meets the verifier's resource bounds, at direct admission and in aggregation,
    /// even when all its claims are discarded; the program bound counts the padded table, support code included.
    #[test]
    fn resource_bounds_apply_to_discarded_leaves() {
        // 900 multiply-adds fill the 2^11-instruction table.
        let source = format!(
            "def main():\n    h = StackBuf(2)\n    hint_witness(h, \"pi\")\n    acc = h[0]\n{}    p = 1\n    p[1] = h[0]\n    p[GEN] = h[1]\n    return\n",
            "    acc = acc * h[1] + h[0]\n".repeat(900)
        );
        let claim = [0x31; 32];
        let (witness, key) = prove_stark(BATCHED, &source, &batch_hash(&[claim])).unwrap();
        assert_eq!(witness[0] as usize, MAX_GENERIC_BYTECODE_LOG);
        let dep = leanstark_dependency(&claim, &key);
        assert!(verify_witness(&dep, &witness));
        let empty = commitment(&[]);
        let discarded = |witness: &[u8]| {
            let as_leaf = input_with_leaves(&[], &[], &[dep], &[ordinary(key, &[claim], witness)]);
            let as_direct = input(&[(dep, witness.to_vec())], &[], &[dep]);
            [as_leaf, as_direct].map(|input| prove_aggregate(BASE, &empty, &input))
        };
        assert_eq!(discarded(&witness), [Ok(vec![]), Ok(vec![])]);
        for (name, forged) in bounded_witnesses(&witness) {
            assert!(!verify_witness(&dep, &forged), "{name}");
            assert!(discarded(&forged).iter().all(Result::is_err), "{name}");
        }
    }

    #[test]
    fn rejects_bad_witnesses_and_unknown_schemes() {
        let (dep, witness) = signed(1);
        assert!(verify_witness(&dep, &witness));
        let mut forged = witness.clone();
        forged[100] ^= 1;
        assert!(!verify_witness(&dep, &forged));
        assert!(
            prove_aggregate(BASE, &hash_of(&[dep]), &input(&[(dep, forged)], &[], &[])).is_err()
        );
        // A signature is no leanSTARK witness, and the scheme is part of the dependency.
        let mut stark = dep;
        stark[31] = LEAN_STARK;
        assert!(!verify_witness(&stark, &witness));
        assert_ne!(hash_of(&[stark]), hash_of(&[dep]));
        assert!(
            prove_aggregate(
                BASE,
                &hash_of(&[stark]),
                &input(&[(stark, witness.clone())], &[], &[])
            )
            .is_err()
        );
        let mut unknown = dep;
        unknown[31] = 0x12;
        assert!(
            prove_aggregate(
                BASE,
                &hash_of(&[dep]),
                &input(&[(unknown, witness)], &[], &[])
            )
            .is_err()
        );
    }

    #[test]
    fn mixed_commitment_joins_both_lists_under_a_domain() {
        let sphincs = canonical((0..2).map(|i| signed(i).0).collect());
        let mut stark = sphincs[0];
        stark[31] = LEAN_STARK;
        let list = |deps: &[Dep]| {
            keccak(
                &deps
                    .iter()
                    .flat_map(|d| d[32..].iter().copied())
                    .collect::<Vec<u8>>(),
            )
        };
        let mut domain = [0u8; 32];
        domain[..22].copy_from_slice(b"eip8288/leanstark-deps");
        let joined =
            |s: &[Dep], g: &[Dep]| keccak(&[&list(s)[..], &list(g)[..], &domain[..]].concat());
        assert_eq!(
            commitment(&canonical([&sphincs[..], &[stark]].concat())),
            joined(&sphincs, &[stark])
        );
        assert_eq!(commitment(&[stark]), joined(&[], &[stark]));
        assert_ne!(commitment(&[stark]), commitment(&sphincs[..1]));
    }

    #[test]
    fn proves_and_merges_leanstark_with_leansphincs() {
        let (stark, stark_witness) = proven(1);
        let (other, other_witness) = proven(2);
        let (sig, sig_witness) = signed(3);
        assert!(verify_witness(&stark, &stark_witness));
        assert!(!verify_witness(&other, &stark_witness));
        let mut forged = stark_witness.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert!(!verify_witness(&stark, &forged));
        assert!(
            prove_aggregate(
                BASE,
                &hash_of(&[stark]),
                &input(&[(stark, forged)], &[], &[])
            )
            .is_err()
        );

        let mixed = [stark, sig];
        let leaf = prove_aggregate(
            BASE,
            &hash_of(&mixed),
            &input(&[(stark, stark_witness), (sig, sig_witness)], &[], &[]),
        )
        .unwrap();
        assert!(verify_aggregate(BASE, &hash_of(&mixed), &leaf).is_ok());
        assert!(verify_aggregate(BASE, &hash_of(&[sig]), &leaf).is_err());
        assert!(verify_aggregate(BASE, &hash_of(&[stark]), &leaf).is_err());

        // A mixed child plus a raw leanSTARK witness, with the child's signature discarded.
        let declared = canonical(mixed.to_vec());
        let children = [(&declared[..], &leaf[..])];
        let kept = [stark, other];
        let merged = prove_aggregate(
            BASE,
            &hash_of(&kept),
            &input(&[(other, other_witness)], &children, &[sig]),
        )
        .unwrap();
        assert!(verify_aggregate(BASE, &hash_of(&kept), &merged).is_ok());
        assert!(verify_aggregate(BASE, &hash_of(&[stark, other, sig]), &merged).is_err());
    }

    #[test]
    fn proves_merges_and_discards() {
        let raw: Vec<_> = (0..5).map(signed).collect();
        let deps: Vec<Dep> = raw.iter().map(|(dep, _)| *dep).collect();

        let left = canonical(deps[..2].to_vec());
        let left_proof =
            prove_aggregate(BASE, &hash_of(&left), &input(&raw[..2], &[], &[])).unwrap();
        assert!(verify_aggregate(BASE, &hash_of(&left), &left_proof).is_ok());
        assert!(verify_aggregate(BASE, &hash_of(&deps[..3]), &left_proof).is_err());
        let mut tampered = left_proof.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(verify_aggregate(BASE, &hash_of(&left), &tampered).is_err());

        let right = canonical(deps[2..4].to_vec());
        let right_proof =
            prove_aggregate(BASE, &hash_of(&right), &input(&raw[2..4], &[], &[])).unwrap();

        // Two children and one raw signature, with one child dependency discarded.
        let children = [(&left[..], &left_proof[..]), (&right[..], &right_proof[..])];
        let kept = [deps[1], deps[2], deps[3], deps[4]];
        let merged = prove_aggregate(
            BASE,
            &hash_of(&kept),
            &input(&raw[4..], &children, &deps[..1]),
        )
        .unwrap();
        assert!(verify_aggregate(BASE, &hash_of(&kept), &merged).is_ok());
        assert!(verify_aggregate(BASE, &hash_of(&deps), &merged).is_err());

        // A child declared with dependencies it does not prove is refused.
        let lying = [(&right[..], &left_proof[..])];
        assert!(prove_aggregate(BASE, &hash_of(&right), &input(&[], &lying, &[])).is_err());
        // A child that already covers the request is returned as is.
        assert_eq!(
            prove_aggregate(BASE, &hash_of(&left), &input(&[], &children[..1], &[])).unwrap(),
            left_proof
        );
    }

    fn claim_of(claim: &[u8; 32], vk: &[u8; 32]) -> Dep {
        dependency(BATCHED_LEANSTARK_SCHEME, claim, vk)
    }
    fn payment_of(claims: &[[u8; 32]], vk: &[u8; 32]) -> Dep {
        dependency(LEANSTARK_LEAF_PAYMENT_SCHEME, &batch_hash(claims), vk)
    }
    /// A batch claim's record, bound to the payment of the leaf of `claims`.
    fn sourced(claim: &[u8; 32], vk: &[u8; 32], claims: &[[u8; 32]]) -> Record {
        (claim_of(claim, vk), payment_of(claims, vk))
    }
    /// Proves the finalized digest of `deps` from `input`, and checks it verifies under that digest only.
    fn finalized(deps: &[Dep], input: &[u8]) -> Result<Vec<u8>, ()> {
        let deps = canonical(deps.to_vec());
        let hash = final_statement(&deps);
        assert_eq!(
            hash,
            keccak(&[&b"EIP8288:batch-final:v1"[..], &commitment(&deps)].concat())
        );
        let proof = prove_aggregate(BATCHED, &hash, input)?;
        verify_aggregate(BATCHED, &hash, &proof).unwrap();
        assert!(
            verify_aggregate(BATCHED, &commitment(&deps), &proof).is_err(),
            "a finalized proof is no plain one"
        );
        Ok(proof)
    }

    /// ethereum/EIPs#12664 Test Cases: both new schemes take 31 zero bytes, a payment a nonzero digest, and only the
    /// batched guest; a batch claim's digest is finalized, and its intermediate digest binds its source.
    #[test]
    fn new_schemes_are_padded_and_gated() {
        let (claim, vk) = ([0x61; 32], [0x62; 32]);
        let mut padded = claim_of(&claim, &vk);
        padded[30] = 1;
        let mut padded_payment = payment_of(&[claim], &vk);
        padded_payment[0] = 1;
        let cases = [
            claim_of(&claim, &vk),
            payment_of(&[claim], &vk),
            padded,
            padded_payment,
            dependency(LEANSTARK_LEAF_PAYMENT_SCHEME, &[0; 32], &vk),
            dependency(0x14, &claim, &vk),
        ];
        assert_eq!(
            cases.map(|dep| known_scheme(BATCHED, &dep)),
            [true, true, false, false, false, false]
        );
        assert_eq!(cases.map(|dep| known_scheme(BASE, &dep)), [false; 6]);
        let ordinary = leanstark_dependency(&claim, &vk);
        assert_ne!(commitment(&[cases[0]]), commitment(&[ordinary]));
        assert_ne!(
            commitment(&[cases[0]]),
            state_commitment(&[sourced(&claim, &vk, &[claim])])
        );
        assert_ne!(
            state_commitment(&[sourced(&claim, &vk, &[claim])]),
            state_commitment(&[sourced(&claim, &vk, &[claim, [0x63; 32]])])
        );
        // Under EIP-8288's guest both schemes are unknown wherever they appear.
        let (witness, key) = batch(&[claim]);
        let deps = [claim_of(&claim, &key), payment_of(&[claim], &key)];
        let leaf = [(key, &[claim][..], deps.to_vec(), &witness[..])];
        assert!(
            prove_aggregate(
                BASE,
                &hash_of(&deps),
                &input_with_leaves(&[], &[], &[], &leaf)
            )
            .is_err()
        );
        assert!(
            prove_aggregate(
                BASE,
                &hash_of(&deps[..1]),
                &input(&[(deps[0], witness.clone())], &[], &[])
            )
            .is_err()
        );
        finalized(&deps, &input_with_leaves(&[], &[], &[], &leaf)).unwrap();
    }

    /// ethereum/EIPs#12664 Test Cases: 64 members and their payment finalize, and pruned to one member the same leaf and
    /// payment still do; the payment cannot go while a claim it sources stays; with every member and the payment gone
    /// nothing is owed; an unused payment is proved alone.
    #[test]
    fn a_sponsored_leaf_finalizes_and_prunes() {
        let claims: Vec<[u8; 32]> = (0..64u8)
            .map(|i| {
                let mut claim = [0x70; 32];
                claim[31] = i;
                claim
            })
            .collect();
        let (witness, key) = batch(&claims);
        let payment = payment_of(&claims, &key);
        let mut all: Vec<Dep> = claims.iter().map(|claim| claim_of(claim, &key)).collect();
        all.push(payment);
        let leaf =
            |deps: Vec<Dep>| input_with_leaves(&[], &[], &[], &[(key, &claims, deps, &witness)]);
        finalized(&all, &leaf(all.clone())).unwrap();
        // An intermediate statement over every member, pruned at the next step to one member and the payment.
        let records: Vec<Record> = claims
            .iter()
            .map(|claim| sourced(claim, &key, &claims))
            .chain([(payment, [0; 96])])
            .collect();
        let state = state_commitment(&canonical_records(&records));
        let intermediate = prove_aggregate(BATCHED, &state, &leaf(all.clone())).unwrap();
        verify_aggregate(BATCHED, &state, &intermediate).unwrap();
        let children = [(&records[..], &intermediate[..])];
        let one = [claim_of(&claims[0], &key), payment];
        let dropped: Vec<Record> = records[1..64].to_vec();
        finalized(&one, &input_records(&[], &children, &dropped, &[])).unwrap();
        // The payment discarded while a claim stays: an intermediate state, which finalizes only once a verified input
        // restores the payment.
        let unpaid: Vec<Record> = records[1..].to_vec();
        let kept = [records[0]];
        let input = input_records(&[], &children, &unpaid, &[]);
        assert!(prove_aggregate(BATCHED, &final_statement(&one[..1]), &input).is_err());
        let held = prove_aggregate(BATCHED, &state_commitment(&kept), &input).unwrap();
        let held_child = [(&kept[..], &held[..])];
        assert!(
            prove_aggregate(
                BATCHED,
                &final_statement(&one[..1]),
                &input_records(&[], &held_child, &[], &[])
            )
            .is_err()
        );
        let restored = input_records(
            &[],
            &held_child,
            &[],
            &[(key, &claims, vec![payment], &witness)],
        );
        finalized(&one, &restored).unwrap();
        // Every member and the payment omitted: no proof is owed for the leaf.
        assert_eq!(
            prove_aggregate(
                BATCHED,
                &hash_of(&[]),
                &input_records(&[], &children, &records, &[])
            ),
            Ok(vec![])
        );
        // A payment after every member is gone, its leaf still verified; as a plain statement it is an intermediate one, which
        // a block holding the payment does not accept.
        let alone = input_records(&[], &children, &records[..64], &[]);
        let paid = finalized(&[payment], &alone).unwrap();
        let intermediate_only = prove_aggregate(BATCHED, &hash_of(&[payment]), &alone).unwrap();
        assert!(
            verify_aggregate(BATCHED, &final_statement(&[payment]), &intermediate_only).is_err()
        );
        // A finalized proof, payment-only included, is no input to aggregation in either domain.
        let as_child = [(&records[64..], &paid[..])];
        assert!(
            prove_aggregate(
                BATCHED,
                &hash_of(&[payment]),
                &input_records(&[], &as_child, &[], &[])
            )
            .is_err()
        );
        let mut bad = witness.clone();
        *bad.last_mut().unwrap() ^= 1;
        let unused =
            input_with_leaves(&[], &[], &[payment], &[(key, &claims, vec![payment], &bad)]);
        assert!(prove_aggregate(BATCHED, &hash_of(&[]), &unused).is_err());
    }

    /// ethereum/EIPs#12664 Test Cases: singleton leaves under one key need their distinct payments, a union of them cannot
    /// pay as an unproved leaf, a payment for another key or claim list does not source a claim, and overlapping leaves
    /// assign each claim one authenticated source whose payment it needs.
    #[test]
    fn sources_are_verified_leaves() {
        let (a, b, c) = ([0xa5; 32], [0xb5; 32], [0xc5; 32]);
        let (single_a, key) = batch(&[a]);
        let (single_b, _) = batch(&[b]);
        let deps = [
            claim_of(&a, &key),
            claim_of(&b, &key),
            payment_of(&[a], &key),
            payment_of(&[b], &key),
        ];
        let singles = input_with_leaves(
            &[],
            &[],
            &[],
            &[
                (key, &[a][..], vec![deps[0], deps[2]], &single_a),
                (key, &[b][..], vec![deps[1], deps[3]], &single_b),
            ],
        );
        finalized(&deps, &singles).unwrap();
        // Direct witnesses source their claims too, paid through their singleton leaves.
        let direct = input_with_leaves(
            &[(deps[0], single_a.clone()), (deps[1], single_b.clone())],
            &[],
            &[],
            &[
                (key, &[a][..], vec![deps[2]], &single_a),
                (key, &[b][..], vec![deps[3]], &single_b),
            ],
        );
        finalized(&deps, &direct).unwrap();
        let union = [deps[0], deps[1], payment_of(&[a, b], &key)];
        assert!(prove_aggregate(BATCHED, &final_statement(&union), &singles).is_err());
        // Overlapping leaves both establish b: either source, with its own payment.
        let (ab, _) = batch(&[a, b]);
        let (bc, _) = batch(&[b, c]);
        let (pab, pbc) = (payment_of(&[a, b], &key), payment_of(&[b, c], &key));
        let both = |b_from_ab: bool| {
            input_with_leaves(
                &[],
                &[],
                &[],
                &[
                    (
                        key,
                        &[a, b][..],
                        if b_from_ab {
                            vec![claim_of(&b, &key), pab]
                        } else {
                            vec![pab]
                        },
                        &ab,
                    ),
                    (
                        key,
                        &[b, c][..],
                        if b_from_ab {
                            vec![pbc]
                        } else {
                            vec![claim_of(&b, &key), pbc]
                        },
                        &bc,
                    ),
                ],
            )
        };
        for owner in [true, false] {
            finalized(&[claim_of(&b, &key), pab, pbc], &both(owner)).unwrap();
            let unpaid = if owner { pbc } else { pab };
            assert!(
                prove_aggregate(
                    BATCHED,
                    &final_statement(&[claim_of(&b, &key), unpaid]),
                    &both(owner)
                )
                .is_err(),
                "other payment"
            );
        }
        let twice = input_with_leaves(
            &[],
            &[],
            &[],
            &[
                (key, &[a, b][..], vec![claim_of(&b, &key), pab], &ab),
                (key, &[b, c][..], vec![claim_of(&b, &key), pbc], &bc),
            ],
        );
        // Both leaves source b: records are deduplicated by dependency, the prover keeping a paid source.
        finalized(&[claim_of(&b, &key), pab, pbc], &twice).unwrap();
        for (paid, leaves) in [
            (
                pbc,
                [vec![claim_of(&b, &key)], vec![claim_of(&b, &key), pbc]],
            ),
            (
                pab,
                [vec![claim_of(&b, &key), pab], vec![claim_of(&b, &key)]],
            ),
        ] {
            let [from_ab, from_bc] = leaves;
            let one_paid = input_with_leaves(
                &[],
                &[],
                &[],
                &[
                    (key, &[a, b][..], from_ab, &ab),
                    (key, &[b, c][..], from_bc, &bc),
                ],
            );
            finalized(&[claim_of(&b, &key), paid], &one_paid).unwrap();
        }
        // A payment under another key sources nothing.
        let (other_witness, other_key) = prove_stark(
            BATCHED,
            "def main():\n    h = StackBuf(2)\n    hint_witness(h, \"pi\")\n    acc = h[0]\n    acc = acc * h[1] + h[0]\n    p = 1\n    p[1] = h[0]\n    p[GEN] = h[1]\n    return\n",
            &batch_hash(&[a]),
        )
        .unwrap();
        assert_ne!(other_key, key);
        let foreign = input_with_leaves(
            &[],
            &[],
            &[],
            &[
                (key, &[a][..], vec![deps[0]], &single_a),
                (
                    other_key,
                    &[a][..],
                    vec![payment_of(&[a], &other_key)],
                    &other_witness,
                ),
            ],
        );
        assert!(
            prove_aggregate(
                BATCHED,
                &final_statement(&[deps[0], payment_of(&[a], &other_key)]),
                &foreign
            )
            .is_err()
        );
    }

    /// ethereum/EIPs#12664 Test Cases: recursion cannot restore a discarded claim or change its source, and a finalized
    /// proof cannot be imported as an intermediate one.
    #[test]
    fn intermediate_statements_keep_sources() {
        let claims = [[0x81; 32], [0x82; 32], [0x83; 32]];
        let (witness, key) = batch(&claims);
        let payment = payment_of(&claims, &key);
        let deps = vec![
            claim_of(&claims[0], &key),
            claim_of(&claims[1], &key),
            payment,
        ];
        let kept = vec![sourced(&claims[0], &key, &claims), (payment, [0; 96])];
        let discard = [sourced(&claims[1], &key, &claims)];
        let pruned = prove_aggregate(
            BATCHED,
            &state_commitment(&canonical_records(&kept)),
            &input_records(
                &[],
                &[],
                &discard,
                &[(key, &claims, deps.clone(), &witness)],
            ),
        )
        .unwrap();
        let children = [(&kept[..], &pruned[..])];
        let restored = [
            claim_of(&claims[0], &key),
            claim_of(&claims[1], &key),
            payment,
        ];
        assert!(
            prove_aggregate(
                BATCHED,
                &final_statement(&restored),
                &input_records(&[], &children, &[], &[])
            )
            .is_err()
        );
        let resourced = [sourced(&claims[0], &key, &claims[..1]), (payment, [0; 96])];
        let wrong_source = [(&resourced[..], &pruned[..])];
        assert!(
            prove_aggregate(
                BATCHED,
                &final_statement(&[deps[0], payment]),
                &input_records(&[], &wrong_source, &[], &[])
            )
            .is_err()
        );
        let last = finalized(
            &[deps[0], payment],
            &input_records(&[], &children, &[], &[]),
        )
        .unwrap();
        // A finalized proof imported in either domain.
        let as_child = [(&kept[..], &last[..])];
        for hash in [
            final_statement(&[deps[0], payment]),
            state_commitment(&canonical_records(&kept)),
        ] {
            assert!(
                prove_aggregate(BATCHED, &hash, &input_records(&[], &as_child, &[], &[])).is_err()
            );
        }
        // Changing the source takes another verified input authenticating it: the singleton leaf of the claim.
        let (single, _) = batch(&claims[..1]);
        let single_payment = payment_of(&claims[..1], &key);
        let resourced = input_records(
            &[],
            &children,
            &kept,
            &[(key, &claims[..1], vec![deps[0], single_payment], &single)],
        );
        finalized(&[deps[0], single_payment], &resourced).unwrap();
    }

    fn canonical_records(records: &[Record]) -> Vec<Record> {
        records
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}
