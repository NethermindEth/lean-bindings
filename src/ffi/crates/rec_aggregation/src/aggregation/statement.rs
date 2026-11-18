//! Claim-list digests and a node's public statement.

use super::cells::{cell_bytes, count, pack_16_bytes};
use super::deferred::DeferredBytecodeClaim;
use super::guest::unified_guest;
use super::generic::{LEANSTARK_DEPS_DOMAIN, digest_cells};
use super::{GenericClaim, LeanSphincsClaim};
use fiat_shamir::merkle::hash_to_scalars;
use primitives::field::F128;

/// Claims the guest hashes a loop frame: 68 cells, four whole block pairs.
pub(super) const CLAIM_GROUP: usize = 17;
const _: () = assert!((CLAIM_GROUP * 64).is_multiple_of(2 * primitives::hash::RATE));
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

/// One scheme's declared claims, hashed plainly: 64 bytes a claim, its pubkey then
/// the message it signed, and an empty list hashes the empty string. The guest
/// computes this same digest [`CLAIM_GROUP`] claims at a time (`claim_list_digest`).
pub(super) fn claim_list_digest(claims: impl IntoIterator<Item = [F128; 4]>) -> [F128; 2] {
    hash_to_scalars(&primitives::hash::hash(&cell_bytes(claims.into_iter().flatten())))
}

/// EIP-8288 entry order: `data_hash ‖ vk`, as the guest's `verify_generic` reads its slot.
pub(super) fn generic_claim_cells((data_hash, vk): &GenericClaim) -> [F128; 4] {
    let [d0, d1] = digest_cells(data_hash);
    let [k0, k1] = digest_cells(vk);
    [d0, d1, k0, k1]
}

/// The EIP-8288 dependency digest of the two lists' digests: the leanSPHINCS one alone when there
/// is no leanSTARK claim, else `keccak256(S ‖ G ‖ LEANSTARK_DEPS_DOMAIN)` (the guest's `deps_digest`).
pub(super) fn deps_digest_of(lean_sphincs_digest: [F128; 2], generic_digest: [F128; 2], has_generic: bool) -> [F128; 2] {
    if !has_generic {
        return lean_sphincs_digest;
    }
    let mut preimage = cell_bytes(lean_sphincs_digest.into_iter().chain(generic_digest));
    preimage.extend(LEANSTARK_DEPS_DOMAIN);
    hash_to_scalars(&primitives::hash::hash(&preimage))
}

/// EIP-8288 entry order: `data_hash ‖ pkSeed ‖ pkRoot`, so the list digest is `get_deps_hash`.
pub(super) fn lean_sphincs_claim_cells((message, pk): &LeanSphincsClaim) -> [F128; 4] {
    [
        pack_16_bytes(&message[..16]),
        pack_16_bytes(&message[16..]),
        pack_16_bytes(lean_sphincs::internals::pk_seed(pk)),
        pack_16_bytes(lean_sphincs::internals::pk_root(pk)),
    ]
}

/// The statement's fixed header, ahead of the deferred cells: the seed, the dependency digest of
/// the two claim lists ([`deps_digest_of`]), and the DA digest ([`verifier::da::digest`]).
/// Fed to the guest as `STMT_HEADER`, which pins where its deferred cells start;
/// the header cells themselves are written out again there, and only the
/// end-to-end statement check holds the two spellings together.
pub(super) const STATEMENT_HEADER: usize = 6;

/// A plain hash over cells: what the guest gets from `keccak_cells` over the same cells.
fn cell_hash(cells: impl IntoIterator<Item = F128>) -> [F128; 2] {
    hash_to_scalars(&primitives::hash::hash(&cell_bytes(cells)))
}

/// A node's public statement, hashed to the two words the VM publishes. The
/// guest's `statement_digest` computes exactly this, both for itself and when it
/// rebuilds a child's, which is what forces a whole tree onto one bytecode and
/// each child's claims, bound by the two list digests, onto its parent's lists.
///
/// Fixed-length preimage, so a plain hash, with no domain tag of its own: every
/// field has a fixed width, and the header leads with the environment digest, which
/// binds this bytecode and the proof system's version and so already separates the
/// preimage from every other use of the hash here. The header cells, then the
/// deferred cells, each hashed as its two lanes. Each claim
/// list's digest binds its own length through the hash's padding, so the pair binds
/// both lists whole.
pub(super) fn statement_digest(
    generic: &[GenericClaim],
    lean_sphincs_signers: &[LeanSphincsClaim],
    da_digest: [u8; 32],
    defer: &DeferredBytecodeClaim,
) -> [F128; 2] {
    statement_digest_of(deps_digest_cells(lean_sphincs_signers, generic), da_digest, defer)
}

/// The dependency digest of the two lists as two cells.
pub(super) fn deps_digest_cells(lean_sphincs: &[LeanSphincsClaim], generic: &[GenericClaim]) -> [F128; 2] {
    deps_digest_of(
        claim_list_digest(lean_sphincs.iter().map(lean_sphincs_claim_cells)),
        claim_list_digest(generic.iter().map(generic_claim_cells)),
        !generic.is_empty(),
    )
}

/// [`statement_digest`] from the dependency digest: all a holder of `deps_hash` alone needs.
pub(super) fn statement_digest_of(
    deps_digest: [F128; 2],
    da_digest: [u8; 32],
    defer: &DeferredBytecodeClaim,
) -> [F128; 2] {
    let seed = leanvm_core::cpu::fs_seed(unified_guest());
    let da_digest = hash_to_scalars(&da_digest);
    let header: [F128; STATEMENT_HEADER] = [
        seed[0],
        seed[1],
        deps_digest[0],
        deps_digest[1],
        da_digest[0],
        da_digest[1],
    ];
    cell_hash(header.into_iter().chain(defer.cells()))
}
