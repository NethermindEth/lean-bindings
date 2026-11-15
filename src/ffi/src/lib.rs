// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

//! Pinned LeanVM verification and recursive aggregation of complete dependency sets.

mod base;
pub mod pq;

use rec_aggregation::{
    BatchLeaf, EthereumClaims, EthereumProof, Guest, MAX_CLAIMS_PER_BATCH_LEAF,
    MAX_GENERIC_BYTECODE_LOG, MAX_INNER_PROOFS_PER_STEP, valid_batch_claims, verify_batch_leaf,
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

/// The aggregation program an ABI call names: 0 for EIP-8288's, 1 for the one with ethereum/EIPs#12664 batched generic
/// proof dependencies.
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
        if !known_scheme(&d) {
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

/// Whether `dep` is one the guests accept: 31 zero bytes, then leanSPHINCS or leanSTARK.
fn known_scheme(dep: &Dep) -> bool {
    dep[..31].iter().all(|b| *b == 0) && matches!(dep[31], LEAN_SPHINCS | LEAN_STARK)
}
/// EIP-8288 leanSPHINCS `verification_key_hash`: the key itself, `PK.seed ‖ PK.root`.
pub fn verification_key(pk: &LeanSphincsPublicKey) -> [u8; 32] {
    pk.to_bytes()
}
fn public_key(vk: &[u8; 32]) -> LeanSphincsPublicKey {
    LeanSphincsPublicKey::from_bytes(vk)
}
fn data(dep: &Dep) -> [u8; 32] {
    dep[32..64].try_into().unwrap()
}
fn key(dep: &Dep) -> [u8; 32] {
    dep[64..].try_into().unwrap()
}
fn lean_sphincs_claims(deps: impl Iterator<Item = Dep>) -> Vec<rec_aggregation::LeanSphincsClaim> {
    let mut claims: Vec<_> = deps
        .filter(|dep| dep[31] == LEAN_SPHINCS)
        .map(|dep| (data(&dep), public_key(&key(&dep))))
        .collect();
    claims.sort();
    claims
}
/// The claims of a statement over `deps`.
fn claims(deps: &[Dep]) -> EthereumClaims {
    let mut generic: Vec<_> = deps
        .iter()
        .filter(|dep| dep[31] == LEAN_STARK)
        .map(|dep| (data(dep), key(dep)))
        .collect();
    generic.sort();
    EthereumClaims {
        lean_sphincs: lean_sphincs_claims(deps.iter().copied()),
        generic,
        ..Default::default()
    }
}
/// The dependency digest of a canonical list, `block_deps_hash` as block validation computes it: ethereum/EIPs#12664
/// `get_deps_hash` over the 96-byte triples.
pub fn commitment(ds: &[Dep]) -> [u8; 32] {
    let claims = claims(ds);
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
/// A direct witness of `dep`: a leanSTARK one is a one-claim leaf.
fn verify_witness(dep: &Dep, witness: &[u8]) -> bool {
    match dep[31] {
        LEAN_SPHINCS => verify_sphincs(&data(dep), &key(dep), witness),
        _ => rec_aggregation::verify_generic(&data(dep), &key(dep), witness),
    }
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

/// Proves `hash`, the [`commitment`] of the selected dependencies: the sorted union of the inputs' less the discards.
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
    let mut all: Vec<Dep> = Vec::new();
    let mut raw = Vec::new();
    // EIP-8288 MAX_INNER_PROOFS_PER_STEP: every supplied leanSTARK proof, a direct one as a singleton leaf, and every
    // child, discarded or redundant ones included; leanSPHINCS witnesses do not count.
    let mut inner_proofs = 0;
    for _ in 0..r.count()? {
        let dep = r.dep()?;
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
        let declared: Vec<Dep> = r
            .deps()?
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
    let discards: HashSet<Dep> = r.deps()?.into_iter().collect();
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
    let deps: Vec<Dep> = all
        .into_iter()
        .filter(|dep| !discards.contains(dep))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if deps.len() > MAX_DEPS || *hash != commitment(&deps) {
        return Err(());
    }
    let kept: HashSet<Dep> = deps.iter().copied().collect();
    children.retain(|(_, _, declared)| declared.iter().any(|dep| kept.contains(dep)));
    let covered: HashSet<Dep> = children
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
/// dependency is the leanSTARK one on a claim of the leaf under its key.
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
        dep[31] == LEAN_STARK && key(dep) == vk && claims.binary_search(&data(dep)).is_ok()
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
    18
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
/// dependencies per list, and for the batched guest the claims per batch leaf in that place.
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
/// batched guest on `get_claim_hash(claim)` under `get_vk_hash` of the program commitment.
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
/// A raw signature's input bound: ML-DSA-44's and Falcon-512's keys and signatures, and SLH-DSA-SHAKE-128s's 7,856-byte
/// signature, fit with room to spare, under EIP-8437's 16 KiB raw-entry limit.
const MAX_RAW_PART_BYTES: usize = 16 * 1024;
/// Writes the EIP-8288 verification key hash of recognized program `profile` ([`pq::Profile`]: 1 ML-DSA-44, 2 Falcon-512,
/// 3 SLH-DSA-SHAKE-128s).
///
/// # Safety
/// `out` must reference 32 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nlean_recognized_key(profile: u32, out: *mut u8) -> i32 {
    if out.is_null() {
        return 0;
    }
    checked(|| {
        let key = pq::Profile::from_id(profile).ok_or(())?.key();
        unsafe {
            std::ptr::copy_nonoverlapping(key.as_ptr(), out, 32);
        }
        Ok(true)
    })
}
/// Checks a raw signature over the 32-byte `msg` as recognized program `profile` would, natively, and writes its claim:
/// 1 when both the scheme's reference verification and the leaf's host computation accept, 0 otherwise.
///
/// # Safety
/// Input pointers must reference their declared lengths, `msg` 32 bytes; `claim` must reference 32 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nlean_verify_raw(
    profile: u32,
    pk: *const u8,
    pk_len: usize,
    msg: *const u8,
    sig: *const u8,
    sig_len: usize,
    claim: *mut u8,
) -> i32 {
    if claim.is_null() {
        return 0;
    }
    checked(|| {
        let profile = pq::Profile::from_id(profile).ok_or(())?;
        let msg: [u8; 32] = unsafe { bytes(msg, 32)? }.try_into().map_err(|_| ())?;
        let pk = unsafe { bytes_with_limit(pk, pk_len, MAX_RAW_PART_BYTES)? };
        let sig = unsafe { bytes_with_limit(sig, sig_len, MAX_RAW_PART_BYTES)? };
        let Some(found) = profile.verify(pk, &msg, sig) else {
            return Ok(false);
        };
        unsafe {
            std::ptr::copy_nonoverlapping(found.as_ptr(), claim, 32);
        }
        Ok(true)
    })
}
/// Proves one leaf of recognized program `profile` over raw signatures and returns its witness, which the batched guest
/// verifies under [`nlean_recognized_key`] against `get_batch_hash` of the signatures' sorted claims. The input is a u32
/// count, then per signature a u32-length public key, the 32-byte message and a u32-length signature, little-endian.
/// Every signature must pass [`nlean_verify_raw`]'s check and have a distinct claim.
///
/// # Safety
/// Input pointers must reference their declared lengths; output pointers must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nlean_prove_raw_leaf(
    profile: u32,
    input: *const u8,
    input_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if out.is_null() || out_len.is_null() {
        return 0;
    }
    checked(|| {
        let profile = pq::Profile::from_id(profile).ok_or(())?;
        let signatures = raw_signatures(unsafe { bytes_with_limit(input, input_len, MAX_INPUT_BYTES)? })?;
        let _guard = begin_proof();
        let leaf = profile.prove(&signatures)?;
        let boxed = leaf.witness.into_boxed_slice();
        let len = boxed.len();
        let ptr = Box::into_raw(boxed) as *mut u8;
        unsafe {
            *out = ptr;
            *out_len = len;
        }
        Ok(true)
    })
}
fn raw_signatures(mut bytes: &[u8]) -> Result<Vec<pq::RawSignature<'_>>, ()> {
    fn take<'a>(bytes: &mut &'a [u8], n: usize) -> Result<&'a [u8], ()> {
        if n > bytes.len() {
            return Err(());
        }
        let (head, tail) = bytes.split_at(n);
        *bytes = tail;
        Ok(head)
    }
    fn length(bytes: &mut &[u8]) -> Result<usize, ()> {
        let n = u32::from_le_bytes(take(bytes, 4)?.try_into().map_err(|_| ())?) as usize;
        if n > MAX_RAW_PART_BYTES { Err(()) } else { Ok(n) }
    }
    let count = u32::from_le_bytes(take(&mut bytes, 4)?.try_into().map_err(|_| ())?) as usize;
    if count == 0 || count > MAX_CLAIMS_PER_BATCH_LEAF {
        return Err(());
    }
    let mut signatures = Vec::with_capacity(count);
    for _ in 0..count {
        let n = length(&mut bytes)?;
        let pk = take(&mut bytes, n)?;
        let msg: [u8; 32] = take(&mut bytes, 32)?.try_into().map_err(|_| ())?;
        let n = length(&mut bytes)?;
        signatures.push((pk, msg, take(&mut bytes, n)?));
    }
    if bytes.is_empty() { Ok(signatures) } else { Err(()) }
}
/// # Safety
/// The pointer and length must be the exact allocation returned by nlean_prove_recursive or nlean_prove_raw_leaf, freed
/// once.
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

    fn raw_input(signatures: &[pq::RawSignature]) -> Vec<u8> {
        let mut input = (signatures.len() as u32).to_le_bytes().to_vec();
        for (pk, msg, sig) in signatures {
            input.extend((pk.len() as u32).to_le_bytes());
            input.extend(*pk);
            input.extend(msg);
            input.extend((sig.len() as u32).to_le_bytes());
            input.extend(*sig);
        }
        input
    }

    #[test]
    fn raw_signature_input_parses_exactly() {
        let signature: pq::RawSignature = (&[1, 2, 3], [7; 32], &[4, 5]);
        let input = raw_input(&[signature, signature]);
        assert_eq!(raw_signatures(&input).unwrap(), vec![signature, signature]);
        assert!(raw_signatures(&[&input[..], &[0]].concat()).is_err());
        assert!(raw_signatures(&input[..input.len() - 1]).is_err());
        assert!(raw_signatures(&raw_input(&[])).is_err());
        let oversized = vec![0; MAX_RAW_PART_BYTES + 1];
        assert!(raw_signatures(&raw_input(&[(&oversized, [0; 32], &[])])).is_err());
    }

    #[test]
    fn recognized_program_abi_reaches_every_vector_verdict() {
        for v in pq::vectors() {
            let mut claim = [0; 32];
            let verdict = unsafe {
                nlean_verify_raw(v.profile as u32, v.pk.as_ptr(), v.pk.len(), v.msg.as_ptr(), v.sig.as_ptr(), v.sig.len(), claim.as_mut_ptr())
            };
            assert_eq!(verdict, i32::from(v.claim.is_some()), "{}: {}", v.profile.name(), v.label);
            if let Some(expected) = v.claim {
                assert_eq!(claim, expected);
            }
        }
        let mut key = [0; 32];
        for profile in pq::Profile::ALL {
            assert_eq!(unsafe { nlean_recognized_key(profile as u32, key.as_mut_ptr()) }, 1);
            assert_eq!(key, profile.key());
        }
        assert_eq!(unsafe { nlean_recognized_key(0, key.as_mut_ptr()) }, 0);
        assert_eq!(unsafe { nlean_recognized_key(4, key.as_mut_ptr()) }, 0);
    }

    #[test]
    fn a_one_signature_raw_leaf_is_a_direct_witness_of_its_dependency() {
        let honest = pq::vectors().into_iter().find(|v| v.profile == pq::Profile::SlhDsa128s && v.claim.is_some()).unwrap();
        let input = raw_input(&[(&honest.pk, honest.msg, &honest.sig)]);
        let (mut out, mut len) = (std::ptr::null_mut(), 0);
        assert_eq!(unsafe { nlean_prove_raw_leaf(3, input.as_ptr(), input.len(), &mut out, &mut len) }, 1);
        let witness = unsafe { std::slice::from_raw_parts(out, len) }.to_vec();
        unsafe { nlean_free(out, len) };
        let dep = leanstark_dependency(&honest.claim.unwrap(), &pq::Profile::SlhDsa128s.key());
        assert!(verify_witness(&dep, &witness));
        let mut other = honest.claim.unwrap();
        other[0] ^= 1;
        assert!(!verify_witness(&leanstark_dependency(&other, &pq::Profile::SlhDsa128s.key()), &witness));
    }

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

    /// ethereum/EIPs#12664: `get_deps_hash` is the hash of the canonical 96-byte triples, scheme word included.
    #[test]
    fn commitment_is_keccak_of_the_96_byte_triples() {
        let deps = canonical((0..3).map(|i| signed(i).0).collect());
        assert_eq!(commitment(&deps), keccak(&deps.concat()));
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
        let (witness, key) =
            prove_stark(BATCHED, ANY_INPUT_PROGRAM, &batch_hash(&[message])).unwrap();
        (leanstark_dependency(&message, &key), witness)
    }

    /// A leaf of `claims` under the accept-all program's key, and that key.
    fn batch(claims: &[[u8; 32]]) -> (Vec<u8>, [u8; 32]) {
        prove_stark(BATCHED, ANY_INPUT_PROGRAM, &batch_hash(claims)).unwrap()
    }

    #[test]
    fn exported_abi_and_limits() {
        assert_eq!(nlean_abi_version(), 18);
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
                    &"f6f37690cf7241c9ea24392f349867acc1c8e06034e8ce149e2f11a25eec56f9"
                        [2 * i..2 * i + 2],
                    16,
                )
                .unwrap()
            })
            .collect();
        assert_eq!(keys[0].as_slice(), base.as_slice());
    }

    /// A direct leanSTARK witness is checked as the named guest takes it: guest 0 on the bare claim under the flat
    /// table key, as the ABI 12 package did, and guest 1 on `get_claim_hash(claim)` under `get_vk_hash` of the committed
    /// bytecode key, which rejects a proof of the bare claim, a flat-keyed witness and the bare commitment as the key.
    #[test]
    fn direct_leanstark_witnesses_follow_the_guest() {
        let claim = keccak(b"direct claim");
        let wrapped_claim = batch_hash(&[claim]);
        let (bare, flat_key) = prove_stark(BASE, ANY_INPUT_PROGRAM, &claim).unwrap();
        let (flat_wrapped, _) = prove_stark(BASE, ANY_INPUT_PROGRAM, &wrapped_claim).unwrap();
        let (committed_bare, committed_key) =
            prove_stark(BATCHED, ANY_INPUT_PROGRAM, &claim).unwrap();
        let (wrapped, _) = prove_stark(BATCHED, ANY_INPUT_PROGRAM, &wrapped_claim).unwrap();
        assert_ne!(flat_key, committed_key);
        let program =
            lean_compiler::compile(&lean_compiler::parse(ANY_INPUT_PROGRAM).unwrap()).committed();
        let commitment = program.bytecode_commitment().unwrap().key;
        assert_eq!(committed_key, rec_aggregation::vk_hash(&commitment));
        let verify = |guest: u32, key: &[u8; 32], witness: &[u8]| unsafe {
            nlean_verify_leanstark(
                guest,
                claim.as_ptr(),
                key.as_ptr(),
                witness.as_ptr(),
                witness.len(),
            )
        };
        assert_eq!(
            [
                verify(0, &flat_key, &bare),
                verify(0, &flat_key, &flat_wrapped),
                verify(0, &committed_key, &wrapped),
                verify(1, &committed_key, &committed_bare),
                verify(1, &committed_key, &wrapped),
                verify(1, &flat_key, &flat_wrapped),
                verify(1, &commitment, &wrapped),
                verify(2, &committed_key, &wrapped)
            ],
            [1, 0, 0, 0, 1, 0, 0, 0]
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

    /// EIP-8288 lays a leanSPHINCS key out as `PK.seed ‖ PK.root`; the former `PK.root ‖ PK.seed` names another key.
    #[test]
    fn sphincs_key_is_seed_then_root() {
        let (dep, witness) = signed(1);
        let (_, pk) = lean_sphincs::key_gen_from_seed([1; 32]);
        assert_eq!(key(&dep), [pk.public_param, pk.root].concat()[..]);
        assert!(verify_witness(&dep, &witness));
        let mut swapped = dep;
        swapped[64..80].copy_from_slice(&pk.root);
        swapped[80..].copy_from_slice(&pk.public_param);
        let swapped_witness = [&swapped[64..], &witness[32..]].concat();
        assert!(!verify_witness(&swapped, &swapped_witness));
        let swapped_input = input(&[(swapped, swapped_witness)], &[], &[]);
        assert!(base::prove_aggregate(&hash_of(&[swapped]), &swapped_input).is_err());
        assert!(prove_aggregate(BATCHED, &hash_of(&[swapped]), &swapped_input).is_err());
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
        // ethereum/EIPs#12664 Test Case: nonzero scheme padding or an unsupported scheme, the former batch-pricing ones
        // included, is rejected by both guests.
        let mut padded = dep;
        padded[30] = 1;
        for scheme in [0x12, 0x13, 0x14] {
            let mut unknown = dep;
            unknown[31] = scheme;
            for (bad, guest) in [
                (unknown, BASE),
                (unknown, BATCHED),
                (padded, BASE),
                (padded, BATCHED),
            ] {
                assert!(!known_scheme(&bad));
                assert!(
                    prove_aggregate(
                        guest,
                        &hash_of(&[dep]),
                        &input(&[(bad, witness.clone())], &[], &[])
                    )
                    .is_err()
                );
            }
        }
    }

    /// ethereum/EIPs#12664 Test Case: the same claim and key under different schemes are distinct triples with distinct
    /// digests, leanSPHINCS ones first in a mixed list.
    #[test]
    fn mixed_commitment_hashes_the_sorted_triples() {
        let sphincs = canonical((0..2).map(|i| signed(i).0).collect());
        let mut stark = sphincs[0];
        stark[31] = LEAN_STARK;
        let mixed = canonical([&sphincs[..], &[stark]].concat());
        assert_eq!(mixed.last(), Some(&stark));
        assert_eq!(commitment(&mixed), keccak(&mixed.concat()));
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

    /// `n` strictly increasing claims, `first` repeated, then the index in the last two bytes.
    fn claims_from(first: u8, n: usize) -> Vec<[u8; 32]> {
        (0..n as u16)
            .map(|i| {
                let mut claim = [first; 32];
                claim[30..].copy_from_slice(&i.to_be_bytes());
                claim
            })
            .collect()
    }

    /// ethereum/EIPs#12664 Test Cases: a 256-claim leaf folded into a wrapper covering 64 of its claims, then pruned to one,
    /// keeps exactly the selected dependencies with the same leaf; a 257-claim leaf is rejected before verification; and a
    /// member dropped from the aggregate leaves the others provable with the same leaf.
    #[test]
    fn a_full_leaf_folds_and_prunes() {
        let claims = claims_from(0x70, MAX_CLAIMS_PER_BATCH_LEAF);
        let (witness, key) = batch(&claims);
        let deps: Vec<Dep> = claims
            .iter()
            .map(|claim| leanstark_dependency(claim, &key))
            .collect();
        let selected = &deps[..64];
        let leaf = [(key, &claims[..], selected.to_vec(), &witness[..])];
        let wrapper = prove_aggregate(
            BATCHED,
            &hash_of(selected),
            &input_with_leaves(&[], &[], &[], &leaf),
        )
        .unwrap();
        verify_aggregate(BATCHED, &hash_of(selected), &wrapper).unwrap();
        let children = [(selected, &wrapper[..])];
        let one = prove_aggregate(
            BATCHED,
            &hash_of(&deps[..1]),
            &input(&[], &children, &selected[1..]),
        )
        .unwrap();
        verify_aggregate(BATCHED, &hash_of(&deps[..1]), &one).unwrap();
        // A pruned claim cannot come back from the pruned proof.
        let pruned = [(&deps[..1], &one[..])];
        assert!(prove_aggregate(BATCHED, &hash_of(&deps[..2]), &input(&[], &pruned, &[])).is_err());
        // One member omitted, the others still proved from the same leaf.
        let rest = &deps[1..64];
        let reaggregated = [(key, &claims[..], rest.to_vec(), &witness[..])];
        let omitted = prove_aggregate(
            BATCHED,
            &hash_of(rest),
            &input_with_leaves(&[], &[], &[], &reaggregated),
        )
        .unwrap();
        verify_aggregate(BATCHED, &hash_of(rest), &omitted).unwrap();
        // 257 claims exceed MAX_CLAIMS_PER_BATCH_LEAF: rejected before any verification.
        let over = claims_from(0x71, MAX_CLAIMS_PER_BATCH_LEAF + 1);
        let over_deps = vec![leanstark_dependency(&over[0], &key)];
        let too_many = [(key, &over[..], over_deps.clone(), &witness[..])];
        assert!(
            prove_aggregate(
                BATCHED,
                &hash_of(&over_deps),
                &input_with_leaves(&[], &[], &[], &too_many)
            )
            .is_err()
        );
    }

    /// ethereum/EIPs#12664 Test Case: overlapping leaves and recursive inputs deduplicate identical triples and keep the same
    /// claim under different keys distinct; a leaf cannot establish its claim under another key.
    #[test]
    fn overlapping_inputs_deduplicate_and_keep_keys_apart() {
        let (a, b) = ([0xa7; 32], [0xb7; 32]);
        let (ab, key) = batch(&[a, b]);
        let (single_a, _) = batch(&[a]);
        let source = "def main():\n    h = StackBuf(2)\n    hint_witness(h, \"pi\")\n    q = h[0] * h[1]\n    p = 1\n    p[1] = h[0]\n    p[GEN] = h[1]\n    return\n";
        let (other_a, other_key) = prove_stark(BATCHED, source, &batch_hash(&[a])).unwrap();
        assert_ne!(key, other_key);
        let deps = canonical(vec![
            leanstark_dependency(&a, &key),
            leanstark_dependency(&b, &key),
            leanstark_dependency(&a, &other_key),
        ]);
        let (pair, one) = ([a, b], [a]);
        let leaves = [
            ordinary(key, &pair, &ab),
            ordinary(key, &one, &single_a),
            ordinary(other_key, &one, &other_a),
        ];
        let proof = prove_aggregate(
            BATCHED,
            &hash_of(&deps),
            &input_with_leaves(&[], &[], &[], &leaves),
        )
        .unwrap();
        verify_aggregate(BATCHED, &hash_of(&deps), &proof).unwrap();
        let child = [(&deps[..], &proof[..])];
        let again = prove_aggregate(
            BATCHED,
            &hash_of(&deps),
            &input_with_leaves(&[], &child, &[], &leaves[..1]),
        )
        .unwrap();
        assert_eq!(again, proof, "a child covering the statement is reused");
        let stolen = [(
            key,
            &[a][..],
            vec![leanstark_dependency(&a, &other_key)],
            &single_a[..],
        )];
        assert!(
            prove_aggregate(
                BATCHED,
                &hash_of(&[leanstark_dependency(&a, &other_key)]),
                &input_with_leaves(&[], &[], &[], &stolen)
            )
            .is_err()
        );
    }
}
