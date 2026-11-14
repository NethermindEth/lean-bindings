//! leanSTARK (scheme `0x11`) dependencies: "the leanVM program `vk` commits to accepts `data_hash`".
//!
//! # Leaves
//!
//! A leanSTARK proof is a leaf: its public input is `get_batch_hash(claims) = keccak256(b"EIP8288:batch:v1" ‖ claims)`
//! ([`batch_hash`]) over 1 to [`Guest::max_claims_per_leaf`] strictly increasing 32-byte claims, EIP-8288's
//! `get_claim_hash` for one claim. A direct dependency on `data_hash` is the singleton leaf `[data_hash]`. The
//! aggregation guest checks the claims' order; the leaf program need not.
//!
//! Each claim establishes the dependency `(0x11, claim, vk)` (ethereum/EIPs#12664); a claim list entry is `claim ‖ vk`.
//!
//! # Verification key
//!
//! `vk = get_vk_hash(c) = keccak256(b"EIP8288:vk:v1" ‖ c)` ([`vk_hash`]) of the program commitment
//! `c = verifier::committed_key(kgen, root, ood) = keccak256(verifier::COMMITTED_TAG ‖ u8 kgen ‖ root ‖ ood)`,
//! `root` the commitment to the program's stacked bytecode table ([`leanvm_core::cpu::bytecode_table`],
//! `16 · 2^kgen` words, `kgen ≤` [`MAX_GENERIC_BYTECODE_LOG`]) that [`leanvm_core::cpu::Program::committed`] makes:
//! the table zero-padded to a `2^16`-word stack, Reed-Solomon encoded at rate 1/16 and Merkle-hashed. `ood` is the
//! table's value at an out-of-domain point drawn from the root (`verifier::committed_ood_point`), as two cells
//! (`verifier::committed_ood_encoding`): it pins the one codeword near the root the key names. `c` is also the
//! Fiat-Shamir IV every proof of the program is made under, so the root binds the transcript before its first
//! challenge.
//!
//! A proof of a committed program sends the table's value at the bus's point and opens the commitment there and at
//! the out-of-domain point. The guest rehashes the hinted `kgen`, root and `ood` into `c`, checks the claim's `vk` names
//! it, seeds the dependency's transcript with `c`, and verifies that opening against the root: a cost that does not grow with the
//! program. The guest and [`verify_generic`] accept the same claims.
//!
//! # Witness
//!
//! `u8 kgen ‖ root (32 bytes) ‖ ood (32 bytes) ‖ proof`, the proof in [`leanvm_core::cpu::Proof::to_bytes`]'s
//! encoding, of an execution of the committed program on the public input `get_batch_hash(claims)` (two 16-byte
//! halves).

use super::cells::{count, exponent_bytes, pack_16_bytes};
use super::error::AggregationError;
use super::guest::Guest;
use super::hints::SubHints;
use leanvm_core::cpu::{Proof, from_scalar, scalar_proof};
use primitives::field::{F64, F192};

/// The most instructions, as a log, of a leanSTARK dependency's program.
pub const MAX_GENERIC_BYTECODE_LOG: usize = 11;
/// ethereum/EIPs#12664 `MAX_CLAIMS_PER_BATCH_LEAF` (provisional): the most claims one leaf of [`Guest::Batched`]
/// proves. A guest constant, so changing it changes that guest's `AGGREGATED_VK`.
pub const MAX_CLAIMS_PER_BATCH_LEAF: usize = 256;

/// EIP-8288 `LEANSPHINCS_SCHEME`.
pub const LEAN_SPHINCS_SCHEME: u8 = 0x10;

/// EIP-8288 `LEANSTARK_SCHEME`, enabled by ethereum/EIPs#12664.
pub const LEAN_STARK_SCHEME: u8 = 0x11;

/// EIP-8288 `get_batch_hash`'s domain, one 16-byte cell.
pub const BATCH_DOMAIN: [u8; 16] = *b"EIP8288:batch:v1";

/// ethereum/EIPs#12664 `get_vk_hash`'s tag.
pub const VK_TAG: &[u8; 13] = b"EIP8288:vk:v1";

/// ethereum/EIPs#12664 `get_vk_hash(program_commitment) = keccak256(b"EIP8288:vk:v1" ‖ program_commitment)`: the
/// leanSTARK verification key a dependency names.
pub fn vk_hash(program_commitment: &[u8; 32]) -> [u8; 32] {
    primitives::hash::hash(&[&VK_TAG[..], program_commitment].concat())
}

/// Stacked table words a row of the bytecode: the table is `16 · 2^kgen` words.
const ROW_WORDS: usize = 16;

/// A parsed leanSTARK witness.
pub(super) struct GenericWitness {
    pub(super) kgen: usize,
    pub(super) root: [u8; 32],
    pub(super) ood: [u8; 32],
    pub(super) proof: Proof,
}

/// `kgen` of a table length `16 · 2^kgen`, within the cap.
fn table_log(len: usize) -> Option<usize> {
    let rows = len / ROW_WORDS;
    let kgen = rows.trailing_zeros() as usize;
    (len == rows * ROW_WORDS && rows.is_power_of_two() && kgen <= MAX_GENERIC_BYTECODE_LOG).then_some(kgen)
}

/// The commitment of a stacked bytecode table ([`leanvm_core::cpu::bytecode_table`]'s words) within the cap.
fn commitment(table_words: &[u64]) -> Option<leanvm_core::pcs::BytecodeCommitment> {
    let kgen = table_log(table_words.len())?;
    let table: Vec<F64> = table_words.iter().map(|&word| F64(word)).collect();
    Some(leanvm_core::pcs::BytecodeCommitment::new(&table, kgen))
}

/// The verification key of a program, from its stacked bytecode table ([`leanvm_core::cpu::bytecode_table`]'s
/// words): [`vk_hash`] of its committed key, the IV of [`leanvm_core::cpu::Program::committed`]. `None` if the table is
/// not `16 · 2^kgen` words with `kgen ≤` [`MAX_GENERIC_BYTECODE_LOG`].
pub fn generic_verification_key(table_words: &[u64]) -> Option<[u8; 32]> {
    Some(vk_hash(&commitment(table_words)?.key))
}

/// The witness of a leanSTARK dependency on `table_words` with `proof`, a proof of the committed program.
pub fn generic_witness(table_words: &[u64], proof: &Proof) -> Option<Vec<u8>> {
    let commitment = commitment(table_words)?;
    let mut out = vec![commitment.log_instructions as u8];
    out.extend(commitment.root);
    out.extend(commitment.ood);
    out.extend(proof.to_bytes());
    Some(out)
}

pub(super) fn parse_witness(witness: &[u8]) -> Option<GenericWitness> {
    let (&kgen, rest) = witness.split_first()?;
    let kgen = kgen as usize;
    if kgen > MAX_GENERIC_BYTECODE_LOG {
        return None;
    }
    let (root, rest) = rest.split_first_chunk::<32>()?;
    let (ood, proof) = rest.split_first_chunk::<32>()?;
    Some(GenericWitness {
        kgen,
        root: *root,
        ood: *ood,
        proof: Proof::from_bytes(proof)?,
    })
}

/// EIP-8288 `get_batch_hash`: a batch leaf's public statement over its claims.
pub fn batch_hash(claims: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = primitives::hash::Hasher::new();
    hasher.update(&BATCH_DOMAIN);
    for claim in claims {
        hasher.update(claim);
    }
    hasher.finalize()
}

/// Whether `claims` is a leaf's claim list under `guest`: 1 to [`Guest::max_claims_per_leaf`] claims, strictly
/// increasing in byte-lexicographic order.
pub fn valid_batch_claims(guest: Guest, claims: &[[u8; 32]]) -> bool {
    (1..=guest.max_claims_per_leaf()).contains(&claims.len()) && claims.is_sorted_by(|a, b| a < b)
}

/// A scheme's 32-byte word: 31 zero bytes, then the scheme.
pub fn scheme_word(scheme: u8) -> [u8; 32] {
    let mut word = [0; 32];
    word[31] = scheme;
    word
}

/// A digest as the two canonical cells the VM takes it in.
pub(super) fn digest_cells(digest: &[u8; 32]) -> [F192; 2] {
    [pack_16_bytes(&digest[..16]), pack_16_bytes(&digest[16..])]
}

/// The verifier's verdict on a parsed witness for public input `statement`, with what the guest's witness is built from.
pub(super) fn check(
    statement: &[u8; 32],
    vk: &[u8; 32],
    w: &GenericWitness,
) -> Option<(verifier::Bytecode, verifier::Summary)> {
    let bytecode = verifier::Bytecode::committed(w.kgen, w.root, w.ood).ok()?;
    if vk_hash(&bytecode.fiat_shamir_iv()) != *vk {
        return None;
    }
    let summary = verifier::verify_execution(&bytecode, statement, &scalar_proof(&w.proof)).ok()?;
    Some((bytecode, summary))
}

/// Native check of a leanSTARK dependency on `data_hash`: the singleton batch leaf `[data_hash]`
/// ([`verify_batch_leaf`]).
pub fn verify_generic(data_hash: &[u8; 32], vk: &[u8; 32], witness: &[u8]) -> bool {
    verify_batch_leaf(Guest::Base, &[*data_hash], vk, witness)
}

/// Native check of a leaf under `guest`: `claims` is a valid claim list ([`valid_batch_claims`]), `witness` parses,
/// its size, root and `ood` rehash to the commitment `vk` names ([`vk_hash`]), and its proof shows an execution of the committed program on
/// `get_batch_hash(claims)`. Accepts exactly what the aggregation guest accepts.
///
/// Also builds the guest's hints, so a proof the native verifier accepts but the guest's fixed capacities
/// (`gen_verify`'s fit check) cannot take is rejected here rather than when the block is proved.
pub fn verify_batch_leaf(guest: Guest, claims: &[[u8; 32]], vk: &[u8; 32], witness: &[u8]) -> bool {
    let statement = batch_hash(claims);
    valid_batch_claims(guest, claims)
        && parse_witness(witness).is_some_and(|w| {
            check(&statement, vk, &w).is_some_and(|(_, summary)| sub_hints(&w, &w, &statement, &summary).is_ok())
        })
}

/// The guest's hints for one batch leaf's proof (`verify_generic` in the guest), whose public input is
/// `statement`: `kgen`, the root and `ood`, the commitment's bytes `get_vk_hash` re-cuts, then the sub-proof's witness,
/// the commitment's opening included.
pub(super) fn generic_hints(statement: &[u8; 32], vk: &[u8; 32], witness: &[u8]) -> Result<SubHints, AggregationError> {
    let w = parse_witness(witness).ok_or(AggregationError::InvalidGenericWitness)?;
    // Test builds only: the sub-proof's hints come from an honest witness, the size and root from `witness`.
    #[cfg(test)]
    if let Some((honest_hash, honest)) = super::hints::HONEST_GENERIC.with(|h| h.borrow().clone()) {
        let h = parse_witness(&honest).ok_or(AggregationError::InvalidGenericWitness)?;
        let honest_vk = vk_hash(&verifier::committed_key(h.kgen, &h.root, &h.ood));
        let (_, summary) = check(&honest_hash, &honest_vk, &h).ok_or(AggregationError::InvalidGenericWitness)?;
        return sub_hints(&w, &h, &honest_hash, &summary);
    }
    #[cfg(test)]
    if let Some(iv) = super::hints::FORGED_IV.get() {
        let bytecode = verifier::Bytecode::committed(w.kgen, w.root, w.ood)
            .map_err(|_| AggregationError::InvalidGenericWitness)?
            .forge_fiat_shamir_iv(iv);
        let summary = verifier::replay_unchecked(&bytecode, statement, &scalar_proof(&w.proof))
            .map_err(|_| AggregationError::InvalidGenericWitness)?;
        return sub_hints(&w, &w, statement, &summary);
    }
    let unchecked = cfg!(feature = "forge") && std::env::var_os("EIP8288_NO_HOST_SIGCHECK").is_some();
    let summary = match check(statement, vk, &w) {
        Some((_, summary)) => summary,
        None if unchecked => {
            let bytecode = verifier::Bytecode::committed(w.kgen, w.root, w.ood)
                .map_err(|_| AggregationError::InvalidGenericWitness)?;
            verifier::replay_unchecked(&bytecode, statement, &scalar_proof(&w.proof))
                .map_err(|_| AggregationError::InvalidGenericWitness)?
        }
        None => return Err(AggregationError::InvalidGenericWitness),
    };
    sub_hints(&w, &w, statement, &summary)
}

/// The hints of `shown`'s size, root and `ood` around the sub-proof hints of `proved`'s proof.
fn sub_hints(
    shown: &GenericWitness,
    proved: &GenericWitness,
    statement: &[u8; 32],
    summary: &verifier::Summary,
) -> Result<SubHints, AggregationError> {
    // The witness depends on the program's sizes only, so any program of its length stands in.
    let stand_in = leanvm_core::cpu::Program::assemble(
        vec![leanvm_core::cpu::Op::Xor { a: 0, b: 0, c: 0 }; 1 << proved.kgen],
        Default::default(),
        0,
    );
    let value = from_scalar(summary.bytecode_value);
    let (sub, _) = super::child::gen_verify(&stand_in, digest_cells(statement), &proved.proof, summary, value)?;
    let mut hints: SubHints = vec![
        ("gen_kbc", vec![count(shown.kgen)]),
        ("gen_root", digest_cells(&shown.root).to_vec()),
        ("gen_ood", digest_cells(&shown.ood).to_vec()),
        ("batch_bytes", exponent_bytes(&verifier::committed_key(shown.kgen, &shown.root, &shown.ood))),
    ];
    hints.extend(sub);
    Ok(hints)
}
