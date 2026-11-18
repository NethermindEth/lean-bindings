//! Claim-list digests and a node's public statement.

use super::cells::{cell_bytes, count, pack_16_bytes};
use super::deferred::DeferredBytecodeClaim;
use super::generic::LEANSTARK_DEPS_DOMAIN;
use super::guest::fs_seed;
use super::proof::AggregateClaims;
use super::{GenericClaim, LeanSphincsClaim};
use fiat_shamir_prover::merkle::hash_to_scalars;
use primitives::field::F128;

/// Claims the guest hashes a loop frame: 68 cells, four whole block pairs.
pub(super) const CLAIM_GROUP: usize = 17;
const _: () = assert!((CLAIM_GROUP * 64).is_multiple_of(2 * keccak256::RATE));
/// Groups of [`CLAIM_GROUP`] the guest's main list loop hashes a frame.
pub(super) const BIG_GROUPS: usize = 8;
const CLAIM_BIG: usize = CLAIM_GROUP * BIG_GROUPS;

/// How the guest splits a list of `n` claims: the whole frames of [`CLAIM_BIG`], then
/// the whole groups of [`CLAIM_GROUP`], then the claims after them. Its own product
/// identity and range checks pin all three, so this only has to agree with them
/// (`list_split` in the guest). A list is never empty here: both claim lists are
/// guarded at the call, since the guest hashes an empty one without a split at all.
pub(super) fn list_split(n: usize) -> Vec<F128> {
    assert!(n > 0, "an empty list has no split");
    let rest = n % CLAIM_BIG;
    vec![
        count(n / CLAIM_BIG),
        count(rest / CLAIM_GROUP),
        count(rest % CLAIM_GROUP),
    ]
}

/// One scheme's declared claims, hashed plainly: 64 bytes a claim, its EIP-8288 entry
/// ([`claim_cells`]), and an empty list hashes the empty string. The guest
/// computes this same digest [`CLAIM_GROUP`] claims at a time (`claim_list_digest`).
pub(super) fn claim_list_digest(claims: impl IntoIterator<Item = [F128; 4]>) -> [F128; 2] {
    cell_hash(claims.into_iter().flatten())
}

/// A claim as the four cells the guest hashes and its verifier reads: its EIP-8288 entry, `data_hash`
/// then the key, each as two halves.
fn claim_cells(data_hash: &[u8; 32], key: &[u8; 32]) -> [F128; 4] {
    [
        pack_16_bytes(&data_hash[..16]),
        pack_16_bytes(&data_hash[16..]),
        pack_16_bytes(&key[..16]),
        pack_16_bytes(&key[16..]),
    ]
}

pub(super) fn generic_claim_cells((data_hash, vk): &GenericClaim) -> [F128; 4] {
    claim_cells(data_hash, vk)
}

pub(super) fn lean_sphincs_claim_cells((message, pk): &LeanSphincsClaim) -> [F128; 4] {
    claim_cells(message, &pk.to_bytes())
}

/// The EIP-8288 dependency digest of the two lists: the leanSPHINCS list's digest alone (`get_deps_hash`) when
/// there is no leanSTARK claim, else `keccak256(S ‖ G ‖ LEANSTARK_DEPS_DOMAIN)` (the guest's `deps_digest`).
pub(super) fn deps_digest(lean_sphincs: &[LeanSphincsClaim], generic: &[GenericClaim]) -> [F128; 2] {
    let lean_sphincs_digest = claim_list_digest(lean_sphincs.iter().map(lean_sphincs_claim_cells));
    if generic.is_empty() {
        return lean_sphincs_digest;
    }
    let generic_digest = claim_list_digest(generic.iter().map(generic_claim_cells));
    let mut preimage = cell_bytes(lean_sphincs_digest.into_iter().chain(generic_digest));
    preimage.extend(LEANSTARK_DEPS_DOMAIN);
    hash_to_scalars(&keccak256::hash(&preimage))
}

/// The statement's fixed header, ahead of the deferred cells: the seed, the dependency digest of
/// the two claim lists ([`deps_digest`]), and the DA digest ([`verifier::da::digest`]).
/// Fed to the guest as `STMT_HEADER`, which pins where its deferred cells start;
/// the header cells themselves are written out again there, and only the
/// end-to-end statement check holds the two spellings together.
pub(super) const STATEMENT_HEADER: usize = 6;

/// A plain hash over cells: what the guest gets from `keccak_cells` over the same cells.
fn cell_hash(cells: impl IntoIterator<Item = F128>) -> [F128; 2] {
    hash_to_scalars(&keccak256::hash(&cell_bytes(cells)))
}

/// A node's public statement, hashed to the two words the VM publishes as its public input. The
/// guest's `statement_digest` computes exactly this, both for itself and when it
/// rebuilds a child's, which is what forces a whole tree onto one bytecode and
/// each child's claims, bound by the two list digests, onto its parent's lists.
///
/// Fixed-length preimage, so a plain hash, with no domain tag of its own: every
/// field has a fixed width, and the header leads with the environment digest, which
/// binds this bytecode and the proof system's version and so already separates the
/// preimage from every other use of the hash here. The header cells, then the
/// deferred cells, each hashed as its two lanes. Each claim list's digest binds its
/// own length through the hash's padding, so the dependency digest binds both lists whole.
pub(super) fn statement_digest(claims: &AggregateClaims, defer: &DeferredBytecodeClaim) -> [F128; 2] {
    let deps = deps_digest(&claims.lean_sphincs, &claims.generic);
    statement_digest_of(deps, verifier::da::digest(claims.da_commitment), defer)
}

/// [`statement_digest`] from the dependency digest: all a holder of `deps_hash` alone needs.
pub(super) fn statement_digest_of(deps: [F128; 2], da_digest: [u8; 32], defer: &DeferredBytecodeClaim) -> [F128; 2] {
    let header: [[F128; 2]; STATEMENT_HEADER / 2] = [fs_seed(), deps, hash_to_scalars(&da_digest)];
    cell_hash(header.into_iter().flatten().chain(defer.cells()))
}
