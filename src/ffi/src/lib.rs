// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

//! Pinned LeanVM verification and recursive aggregation of complete dependency sets.

use rec_aggregation::{
    BATCHED_LEANSTARK_SCHEME, BatchLeaf, EthereumClaims, EthereumProof, Guest,
    MAX_CLAIMS_PER_BATCH_LEAF, MAX_GENERIC_BYTECODE_LOG, MAX_INNER_PROOFS_PER_STEP,
    valid_batch_claims, verify_batch_leaf,
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
    fn end(self) -> Result<(), ()> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(())
        }
    }
}

/// Whether `dep`'s whole scheme word is one `guest` accepts: leanSPHINCS or leanSTARK with 31 zero bytes, and under
/// [`Guest::Batched`] ethereum/EIPs#12664 `zero[29] ‖ uint16_be(min_batch) ‖ 0x12` with `min_batch` from 1 to
/// `MAX_CLAIMS_PER_BATCH_LEAF`.
fn known_scheme(guest: Guest, dep: &Dep) -> bool {
    match dep[31] {
        LEAN_SPHINCS | LEAN_STARK => dep[..31].iter().all(|b| *b == 0),
        BATCHED_LEANSTARK_SCHEME => {
            guest == Guest::Batched
                && dep[..29].iter().all(|b| *b == 0)
                && (1..=MAX_CLAIMS_PER_BATCH_LEAF).contains(&usize::from(min_batch(dep)))
        }
        _ => false,
    }
}
/// The `min_batch` of a batched dependency, the scheme word's bytes 29 and 30.
fn min_batch(dep: &Dep) -> u16 {
    u16::from_be_bytes([dep[29], dep[30]])
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
/// A leanSTARK list entry's key: the dependency's own for `0x11`, and for `0x12` `rec_aggregation::batched_key`, which
/// binds the whole scheme word.
fn generic_key(dep: &Dep) -> [u8; 32] {
    if dep[31] == BATCHED_LEANSTARK_SCHEME {
        rec_aggregation::batched_key(min_batch(dep), &key(dep))
    } else {
        key(dep)
    }
}
fn claims(deps: &[Dep]) -> EthereumClaims {
    let mut generic: Vec<_> = deps
        .iter()
        .filter(|dep| dep[31] != LEAN_SPHINCS)
        .map(|dep| (data(dep), generic_key(dep)))
        .collect();
    generic.sort();
    EthereumClaims {
        lean_sphincs: deps
            .iter()
            .filter(|dep| dep[31] == LEAN_SPHINCS)
            .map(|dep| (data(dep), public_key(&key(dep))))
            .collect(),
        generic,
        ..Default::default()
    }
}
/// The dependency digest of a canonical list, as the recursive guest commits to it: EIP-8288 `get_deps_hash` for a
/// leanSPHINCS-only list, and the split-domain digest of `rec_aggregation::deps_hash` once it holds a leanSTARK entry,
/// either scheme's, keyed by [`generic_key`] and sorted.
pub fn commitment(ds: &[Dep]) -> [u8; 32] {
    let claims = claims(ds);
    rec_aggregation::deps_hash(&claims.lean_sphincs, &claims.generic)
}
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
/// A direct witness of `dep`: a leanSTARK one is a one-claim leaf, so it proves a batched dependency only at
/// `min_batch` 1.
fn verify_witness(dep: &Dep, witness: &[u8]) -> bool {
    match dep[31] {
        LEAN_SPHINCS => verify_sphincs(&data(dep), &key(dep), witness),
        BATCHED_LEANSTARK_SCHEME if min_batch(dep) != 1 => false,
        _ => rec_aggregation::verify_generic(&data(dep), &key(dep), witness),
    }
}

/// A leanVM program that accepts every public input: the leanSTARK dependency anyone can prove. For tests and fixtures.
pub const ANY_INPUT_PROGRAM: &str = "def main():\n    h = StackBuf(2)\n    hint_witness(h, \"pi\")\n    p = 1\n    p[1] = h[0]\n    p[GEN] = h[1]\n    return\n";

/// Compiles `source`, a leanVM program reading its public input from the `pi` hint, and proves it on `hash`: the
/// leanSTARK witness and verification key of the batch leaf whose `batch_hash(claims)` is `hash`, so of the
/// dependency `(data_hash, key)` for `hash = batch_hash(&[data_hash])`. For tests and fixtures.
pub fn prove_stark(source: &str, hash: &[u8; 32]) -> Result<(Vec<u8>, [u8; 32]), ()> {
    let _guard = begin_proof();
    let mut program = lean_compiler::compile(&lean_compiler::parse(source).map_err(|_| ())?);
    let table: Vec<u64> = leanvm_core::cpu::bytecode_table(program.prog())
        .iter()
        .map(|word| word.0)
        .collect();
    let key = rec_aggregation::generic_verification_key(&table).ok_or(())?;
    let input = fiat_shamir::merkle::hash_to_scalars(hash);
    program.set_witness("pi", vec![input.to_vec()]);
    let (proof, _) = leanvm_core::cpu::prove(&program, input, LOG_INV_RATE).map_err(|_| ())?;
    Ok((
        rec_aggregation::generic_witness(&table, &proof).ok_or(())?,
        key,
    ))
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
fn decode_child(guest: Guest, deps: &[Dep], proof: &[u8]) -> Result<EthereumProof, ()> {
    if proof.is_empty() || proof.len() > MAX_BYTES {
        return Err(());
    }
    let proof = EthereumProof::from_proof_bytes(guest, proof, claims(deps)).map_err(|_| ())?;
    proof.verify().map_err(|_| ())?;
    Ok(proof)
}

/// A leaf of the aggregation input with the dependencies it establishes.
type InputLeaf = (BatchLeaf, Vec<Dep>);

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
    let mut all = Vec::new();
    let mut raw = Vec::new();
    // EIP-8288 MAX_INNER_PROOFS_PER_STEP: every supplied leanSTARK proof, a direct one as a singleton leaf, and every
    // child, discarded or redundant ones included; leanSPHINCS witnesses do not count.
    let mut inner_proofs = 0;
    for _ in 0..r.count()? {
        let dep = r.dep()?;
        // A singleton proof cannot satisfy an already-signed min_batch above 1 (ethereum/EIPs#12664).
        if dep[31] == BATCHED_LEANSTARK_SCHEME && min_batch(&dep) != 1 {
            return Err(());
        }
        inner_proofs += usize::from(dep[31] != LEAN_SPHINCS);
        raw.push((dep, r.blob()?));
        all.push(dep);
    }
    let child_count = r.count()?;
    inner_proofs += child_count;
    if inner_proofs > MAX_INNER_PROOFS_PER_STEP {
        return Err(());
    }
    let mut children = Vec::new();
    for _ in 0..child_count {
        let declared = canonical(r.deps()?);
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
    let discards: HashSet<_> = r.deps()?.into_iter().collect();
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
    let deps: Vec<_> = all
        .into_iter()
        .filter(|dep| !discards.contains(dep))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if deps.len() > MAX_DEPS || commitment(&deps) != *hash {
        return Err(());
    }
    let kept: HashSet<_> = deps.iter().copied().collect();
    children.retain(|(_, _, declared)| declared.iter().any(|dep| kept.contains(dep)));
    let covered: HashSet<_> = children
        .iter()
        .flat_map(|(_, _, declared)| declared.iter().copied())
        .collect();
    // The guest checks only the witnesses it is given; one that a child covers or a discard drops is checked here,
    // so an invalid witness fails the call whether or not the proof needs it.
    let (raw, unused): (Vec<_>, Vec<_>) = raw
        .into_iter()
        .partition(|(dep, _)| kept.contains(dep) && !covered.contains(dep));
    if unused
        .iter()
        .any(|(dep, witness)| !verify_witness(dep, witness))
    {
        return Err(());
    }
    // A leaf proves when one of its dependencies is kept and not yet covered; it publishes only the kept ones. Every
    // other leaf is checked here, so every leaf meets the verifier's bounds even when all its claims are discarded.
    let (leaves, unused): (Vec<_>, Vec<_>) = leaves.into_iter().partition(|(_, established)| {
        established
            .iter()
            .any(|dep| kept.contains(dep) && !covered.contains(dep))
    });
    if unused
        .iter()
        .any(|((claims, vk, witness), _)| !verify_batch_leaf(guest, claims, vk, witness))
    {
        return Err(());
    }
    if deps.is_empty() {
        return Ok(vec![]);
    }
    if let Some((_, bytes, _)) = children.iter().find(|(_, _, declared)| *declared == deps) {
        return Ok(bytes.to_vec());
    }
    let mut signatures = Vec::new();
    let mut generic: Vec<BatchLeaf> = leaves.into_iter().map(|(leaf, _)| leaf).collect();
    for (dep, witness) in raw {
        if dep[31] == LEAN_SPHINCS {
            let (pk, signature) = parse_sphincs(&key(&dep), witness)?;
            signatures.push((pk, data(&dep), signature));
        } else {
            generic.push((vec![data(&dep)], key(&dep), witness.to_vec()));
        }
    }
    let children: Vec<_> = children.into_iter().map(|(child, ..)| child).collect();
    let proof = rec_aggregation::aggregate(
        guest,
        &children,
        generic,
        signatures,
        &[],
        Some(&claims(&deps)),
        LOG_INV_RATE,
    )
    .map_err(|_| ())?
    .proof_bytes();
    if proof.len() > MAX_BYTES {
        return Err(());
    }
    Ok(proof)
}

/// One leaf of the input's trailing section: its key, claims, the dependencies it establishes, then its witness. Each
/// dependency is a leanSTARK one on a claim of the leaf under its key, a batched one with `min_batch` at most the
/// leaf's claim count.
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
    let established = r.deps()?;
    let establishes = |dep: &Dep| {
        key(dep) == vk
            && claims.binary_search(&data(dep)).is_ok()
            && match dep[31] {
                LEAN_STARK => true,
                BATCHED_LEANSTARK_SCHEME => usize::from(min_batch(dep)) <= claim_count,
                _ => false,
            }
    };
    if established.is_empty() || !established.iter().all(establishes) {
        return Err(());
    }
    Ok(((claims, vk, r.blob()?.to_vec()), established))
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
    14
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
/// # Safety
/// Output must hold seven writable u32 values.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nlean_limits(out: *mut u32, len: usize) -> i32 {
    if out.is_null() || len != 7 {
        return 0;
    }
    let limits = [
        MAX_BYTES as u32,
        MAX_DEPS as u32,
        MAX_INNER_PROOFS_PER_STEP as u32,
        (lean_sphincs::PUB_KEY_SIZE + lean_sphincs::SIG_SIZE) as u32,
        MAX_INPUT_BYTES as u32,
        MAX_CLAIMS_PER_BATCH_LEAF as u32,
        1 << MAX_GENERIC_BYTECODE_LOG,
    ];
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
        let key = aggregated_vk(guest_of(guest)?);
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
/// # Safety
/// Input pointers must reference their declared lengths; output pointers must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nlean_verify_leanstark(
    data: *const u8,
    vk: *const u8,
    witness: *const u8,
    len: usize,
) -> i32 {
    checked(|| {
        Ok(rec_aggregation::verify_generic(
            unsafe { bytes(data, 32)? }.try_into().map_err(|_| ())?,
            unsafe { bytes(vk, 32)? }.try_into().map_err(|_| ())?,
            unsafe { bytes(witness, len)? },
        ))
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
        if unsafe { bytes(vk, vk_len)? } != aggregated_vk(guest) {
            return Ok(false);
        }
        let expected = unsafe { bytes(hash, 32)? }.try_into().map_err(|_| ())?;
        verify_aggregate(guest, expected, unsafe { bytes(proof, len)? })?;
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
            || unsafe { bytes(vk, vk_len)? } != aggregated_vk(guest)
        {
            return Ok(false);
        }
        let proof = prove_aggregate(
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
    /// The ethereum/EIPs#12664 dependency on `claim` under `vk` with `min_batch`.
    fn batched(claim: &[u8; 32], vk: &[u8; 32], min_batch: u16) -> Dep {
        let mut dep = leanstark_dependency(claim, vk);
        dep[..32].copy_from_slice(&rec_aggregation::batched_scheme_word(min_batch));
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
    /// The aggregation input with its trailing batch-leaf section.
    fn input_with_leaves(
        raw: &[(Dep, Vec<u8>)],
        children: &[(&[Dep], &[u8])],
        discards: &[Dep],
        leaves: &[LeafEntry],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        put_number(&mut out, raw.len());
        for (dep, witness) in raw {
            out.extend_from_slice(dep);
            put_number(&mut out, witness.len());
            out.extend_from_slice(witness);
        }
        put_number(&mut out, children.len());
        for (deps, proof) in children {
            put_number(&mut out, deps.len());
            out.extend(deps.iter().flatten());
            put_number(&mut out, proof.len());
            out.extend_from_slice(proof);
        }
        put_number(&mut out, discards.len());
        out.extend(discards.iter().flatten());
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
        let (witness, key) = prove_stark(ANY_INPUT_PROGRAM, &batch_hash(&[message])).unwrap();
        (leanstark_dependency(&message, &key), witness)
    }

    /// A leaf of `claims` under the accept-all program's key, and that key.
    fn batch(claims: &[[u8; 32]]) -> (Vec<u8>, [u8; 32]) {
        prove_stark(ANY_INPUT_PROGRAM, &batch_hash(claims)).unwrap()
    }

    #[test]
    fn exported_abi_and_limits() {
        assert_eq!(nlean_abi_version(), 14);
        let mut limits = [0u32; 7];
        assert_eq!(unsafe { nlean_limits(limits.as_mut_ptr(), 7) }, 1);
        assert_eq!(limits[2], 16, "MAX_INNER_PROOFS_PER_STEP");
        assert_eq!(limits[5], 256, "MAX_CLAIMS_PER_BATCH_LEAF");
        assert_eq!(limits[6], 2048, "leanSTARK instructions");
        assert_eq!(unsafe { nlean_limits(limits.as_mut_ptr(), 6) }, 0);
        // One key per guest, and no third guest.
        let mut keys = [[0u8; 32]; 3];
        let verdicts = [0, 1, 2]
            .map(|guest| unsafe { nlean_aggregated_vk(guest, keys[guest as usize].as_mut_ptr()) });
        assert_eq!(verdicts, [1, 1, 0]);
        assert_eq!(keys[0], aggregated_vk(BASE));
        assert_eq!(keys[1], aggregated_vk(BATCHED));
        assert_ne!(keys[0], keys[1]);
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
        let (witness, key) = prove_stark(&source, &batch_hash(&[claim])).unwrap();
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

    /// ethereum/EIPs#12664 Test Cases: `min_batch` 0, 1, 256, 257 and a nonzero reserved bit parse as reject, accept,
    /// accept, reject, reject, and only under the batched guest; the digest binds the whole scheme word.
    #[test]
    fn batched_scheme_words_are_whole_and_gated() {
        let (claim, key) = ([0x61; 32], [0x62; 32]);
        let mut reserved = batched(&claim, &key, 1);
        reserved[3] = 1;
        let mut ordinary_high = leanstark_dependency(&claim, &key);
        ordinary_high[30] = 1;
        let cases = [
            batched(&claim, &key, 0),
            batched(&claim, &key, 1),
            batched(&claim, &key, 256),
            batched(&claim, &key, 257),
            reserved,
            ordinary_high,
        ];
        assert_eq!(
            cases.map(|dep| known_scheme(BATCHED, &dep)),
            [false, true, true, false, false, false]
        );
        assert_eq!(cases.map(|dep| known_scheme(BASE, &dep)), [false; 6]);
        let words = [
            leanstark_dependency(&claim, &key),
            batched(&claim, &key, 1),
            batched(&claim, &key, 2),
        ];
        let hashes = words.map(|dep| commitment(&[dep]));
        assert!(hashes[0] != hashes[1] && hashes[1] != hashes[2] && hashes[0] != hashes[2]);
        // Under EIP-8288's guest a 0x12 dependency is an unknown scheme wherever it appears.
        let (witness, vk) = batch(&[claim]);
        let dep = batched(&claim, &vk, 1);
        let hash = commitment(&[dep]);
        assert!(prove_aggregate(BASE, &hash, &input(&[(dep, witness.clone())], &[], &[])).is_err());
        assert!(
            prove_aggregate(
                BASE,
                &hash,
                &input_with_leaves(&[], &[], &[], &[(vk, &[claim], vec![dep], &witness)])
            )
            .is_err()
        );
        let proof = prove_aggregate(BATCHED, &hash, &input(&[(dep, witness)], &[], &[])).unwrap();
        verify_aggregate(BATCHED, &hash, &proof).unwrap();
    }

    /// ethereum/EIPs#12664 Test Cases: a leaf of 64 claims establishes `min_batch` 64 and not 65, ordinary and batched
    /// dependencies on one claim together, and a singleton or a union of singletons establishes only `min_batch` 1.
    #[test]
    fn min_batch_is_bounded_by_the_leaf() {
        let claims: Vec<[u8; 32]> = (0..64u8)
            .map(|i| {
                let mut claim = [0x70; 32];
                claim[31] = i;
                claim
            })
            .collect();
        let (leaf, key) = batch(&claims);
        let prove = |deps: Vec<Dep>| {
            let hash = commitment(&canonical(deps.clone()));
            prove_aggregate(
                BATCHED,
                &hash,
                &input_with_leaves(&[], &[], &[], &[(key, &claims, deps, &leaf)]),
            )
            .map(|proof| (hash, proof))
        };
        let both = vec![
            batched(&claims[0], &key, 64),
            leanstark_dependency(&claims[0], &key),
            batched(&claims[1], &key, 3),
        ];
        let (hash, proof) = prove(both).unwrap();
        verify_aggregate(BATCHED, &hash, &proof).unwrap();
        assert!(prove(vec![batched(&claims[0], &key, 65)]).is_err());
        assert!(
            prove(vec![batched(&[0x71; 32], &key, 1)]).is_err(),
            "not a claim of the leaf"
        );

        let (a, b) = (claims[0], claims[1]);
        let singles = [a, b].map(|claim| batch(&[claim]).0);
        let one = [batched(&a, &key, 1), batched(&b, &key, 1)];
        let raw = |m: u16| {
            [
                (batched(&a, &key, m), singles[0].clone()),
                (batched(&b, &key, m), singles[1].clone()),
            ]
        };
        let union = prove_aggregate(BATCHED, &hash_of(&one), &input(&raw(1), &[], &[])).unwrap();
        assert!(
            prove_aggregate(
                BATCHED,
                &hash_of(&one.map(|dep| {
                    let mut d = dep;
                    d[30] = 2;
                    d
                })),
                &input(&raw(2), &[], &[])
            )
            .is_err()
        );
        let two = [batched(&a, &key, 2), batched(&b, &key, 2)];
        let children = [(&one[..], &union[..])];
        assert!(
            prove_aggregate(BATCHED, &hash_of(&two), &input(&[], &children, &one)).is_err(),
            "a union qualifies nothing"
        );
    }

    /// ethereum/EIPs#12664 Test Cases: a leaf pruned to one claim keeps its qualifier through recursion; a padded
    /// leaf's discount stands; a discarded triple cannot come back, nor a qualifier rise.
    #[test]
    fn pruned_leaves_keep_exact_qualifiers() {
        let claims = [[0x81; 32], [0x82; 32], [0x83; 32], [0x84; 32]];
        let (leaf, key) = batch(&claims);
        let kept = [batched(&claims[0], &key, 4)];
        let pruned = prove_aggregate(
            BATCHED,
            &hash_of(&kept),
            &input_with_leaves(&[], &[], &[], &[(key, &claims, kept.to_vec(), &leaf)]),
        )
        .unwrap();
        verify_aggregate(BATCHED, &hash_of(&kept), &pruned).unwrap();
        let children = [(&kept[..], &pruned[..])];
        let (other, other_key) = batch(&[[0x90; 32]]);
        let extra = leanstark_dependency(&[0x90; 32], &other_key);
        let merged = prove_aggregate(
            BATCHED,
            &hash_of(&[kept[0], extra]),
            &input(&[(extra, other)], &children, &[]),
        )
        .unwrap();
        verify_aggregate(BATCHED, &hash_of(&[kept[0], extra]), &merged).unwrap();
        for wanted in [
            [batched(&claims[0], &key, 4), batched(&claims[1], &key, 4)],
            [batched(&claims[0], &key, 5), extra],
        ] {
            assert!(
                prove_aggregate(BATCHED, &hash_of(&wanted), &input(&[], &children, &[])).is_err()
            );
        }
    }
}
