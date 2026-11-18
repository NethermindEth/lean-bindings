//! The aggregate, its wire format and its native verification.

use super::cells::cell_bytes;
use super::deferred::{DeferredBytecodeClaim, bytecode_vars};
use super::guest::unified_guest;
use super::statement::{deps_digest, statement_digest, statement_digest_of};
use super::{GenericClaim, LeanSphincsClaim};
use fiat_shamir_prover::merkle::hash_to_scalars;
use lean_vm_core::cpu::public_input_bytes;
use primitives::field::F128;

/// What an [`AggregateProof`] proves: every `(data_hash, vk)` leanSTARK claim is backed by a valid leanVM execution
/// proof of the program `vk` commits to on public input `data_hash` ([`super::verify_generic`]), every
/// `(message, pubkey)` leanSPHINCS claim had a valid signature, and, optionally, a commitment is the root of a
/// well-formed matrix of blobs (see [`lean_da::BlobMatrix`]).
///
/// Each list is strictly sorted (so without duplicates), and may be empty.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AggregateClaims {
    pub generic: Vec<GenericClaim>,
    pub lean_sphincs: Vec<LeanSphincsClaim>,
    /// `None` for no blobs.
    pub da_commitment: Option<[u8; 32]>,
}

/// Which covered claims [`aggregate`](super::aggregate) proves.
#[derive(Clone, Copy, Debug)]
pub enum OutputClaims<'a> {
    /// Every covered signature claim. The DA root is `blobs`' if any, otherwise the first
    /// child's that has one, otherwise none.
    All,
    /// Exactly these, each covered by the inputs.
    Only(&'a AggregateClaims),
}

/// A proof of some [`AggregateClaims`], which travel separately: [`Self::verify`] checks it against
/// the claims the receiver expects.
#[derive(Clone, Debug)]
pub struct AggregateProof {
    /// The point of the deferred bytecode claim, `bytecode_vars()` long; its value is computed from it.
    pub(super) bytecode_point: Vec<F128>,
    pub(super) proof: verifier::Proof,
}

// Wire format: the deferred point (a u64 count, then each element as two u64 limbs, all little-endian),
// then the VM proof. The encoding is canonical: the VM proof's decoder rejects trailing bytes.

pub(super) fn encode(point: &[F128], proof: &[u8]) -> Vec<u8> {
    let mut out = (point.len() as u64).to_le_bytes().to_vec();
    out.extend(point.iter().flat_map(|x| x.to_limbs()).flat_map(u64::to_le_bytes));
    out.extend(proof);
    out
}

/// The deferred point and the VM proof's bytes. A forged count allocates nothing.
pub(super) fn decode(bytes: &[u8]) -> Option<(Vec<F128>, &[u8])> {
    let (count, rest) = bytes.split_first_chunk::<8>()?;
    let count = usize::try_from(u64::from_le_bytes(*count)).ok()?;
    let (limbs, proof) = rest.split_at_checked(count.checked_mul(16)?)?;
    let limb = |bytes: &[u8; 8]| u64::from_le_bytes(*bytes);
    let pairs = limbs.as_chunks::<8>().0.as_chunks::<2>().0;
    let point = pairs.iter().map(|[c0, c1]| F128::new(limb(c0), limb(c1))).collect();
    Some((point, proof))
}

/// Whether each list is strictly sorted, so that no claim counts twice.
pub(super) fn is_sorted(claims: &AggregateClaims) -> bool {
    claims.generic.windows(2).all(|w| w[0] < w[1]) && claims.lean_sphincs.windows(2).all(|w| w[0] < w[1])
}

impl AggregateClaims {
    /// The number of `(pubkey, message)` claims, not of distinct signers: a pubkey may sign
    /// several messages.
    pub fn num_signature_claims(&self) -> usize {
        self.generic.len() + self.lean_sphincs.len()
    }
}

impl AggregateProof {
    pub fn to_bytes(&self) -> Vec<u8> {
        encode(&self.bytecode_point, &self.proof.to_bytes())
    }

    /// Decode a proof, `None` if the bytes are not one. This does not verify: call [`Self::verify`].
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (bytecode_point, proof) = decode(bytes)?;
        if bytecode_point.len() != bytecode_vars() {
            return None;
        }
        let proof = verifier::Proof::from_bytes(proof)?;
        Some(Self { bytecode_point, proof })
    }

    /// Whether this proves `claims`: the lists are sorted, the deferred claim holds, and the stark
    /// proof is valid.
    pub fn verify(&self, claims: &AggregateClaims) -> bool {
        // The cheap check first: the rest evaluates the bytecode at a point the sender chose.
        if !is_sorted(claims) {
            return false;
        }
        let defer = DeferredBytecodeClaim::recompute(self.bytecode_point.clone());
        let pi = statement_digest(claims, &defer);
        let verdict = verifier::verify_execution(unified_guest().bytecode(), &public_input_bytes(&pi), &self.proof);
        if let Err(error) = &verdict {
            tracing::debug!(%error, "the proof does not verify");
        }
        verdict.is_ok()
    }
}

/// EIP-8288 `get_deps_hash` with `DEPS_HASH` = Keccak-256 over each list's 64-byte entries, in the order given:
/// `S` ([`LeanSphincsClaim`]s) alone without leanSTARK dependencies, else `keccak256(S ‖ G ‖
/// LEANSTARK_DEPS_DOMAIN)`, `G` over the [`GenericClaim`]s. The caller canonicalizes (sorts, deduplicates) each list.
pub fn deps_hash(lean_sphincs: &[LeanSphincsClaim], generic: &[GenericClaim]) -> [u8; 32] {
    cell_bytes(deps_digest(lean_sphincs, generic))
        .try_into()
        .expect("two 16-byte cells")
}

/// What stands for EIP-8288 `AGGREGATED_VK`: the guest's Fiat-Shamir IV, which seeds every transcript and leads the
/// statement.
pub fn aggregated_vk() -> [u8; 32] {
    unified_guest().bytecode().fiat_shamir_iv()
}

/// EIP-8288 verification of a dependency-only aggregate (no DA root), holding only the dependency digest and the
/// proof's bytes ([`AggregateProof::to_bytes`]).
pub fn verify_deps_hash(deps_hash: &[u8; 32], proof_bytes: &[u8]) -> bool {
    let Some(proof) = AggregateProof::from_bytes(proof_bytes) else {
        return false;
    };
    let defer = DeferredBytecodeClaim::recompute(proof.bytecode_point.clone());
    let pi = statement_digest_of(hash_to_scalars(deps_hash), verifier::da::digest(None), &defer);
    let verdict = verifier::verify_execution(unified_guest().bytecode(), &public_input_bytes(&pi), &proof.proof);
    if let Err(error) = &verdict {
        tracing::debug!(%error, "the proof does not verify");
    }
    verdict.is_ok()
}
