//! Claim-list digests and a node's public statement.

use super::cells::{cell_bytes, count, pack_16_bytes};
use super::deferred::DeferredClaim;
use super::guest::{Guest, unified_guest};
use super::generic::{LEAN_SPHINCS_SCHEME, LEAN_STARK_SCHEME, digest_cells, scheme_word};
use super::{GenericClaim, LeanSphincsClaim};
use fiat_shamir::merkle::hash_to_scalars;
use primitives::field::F192;

/// Dependencies the guest hashes a loop frame: 102 cells, six whole block pairs.
pub(super) const CLAIM_GROUP: usize = 17;
const _: () = assert!((CLAIM_GROUP * DEPENDENCY_BYTES).is_multiple_of(2 * primitives::hash::RATE));
/// EIP-8288's dependency triple: the scheme word, `data_hash`, then the key.
const DEPENDENCY_BYTES: usize = 96;
/// Groups of [`CLAIM_GROUP`] the guest's main list loop hashes a frame.
pub(super) const BIG_GROUPS: usize = 8;
const CLAIM_BIG: usize = CLAIM_GROUP * BIG_GROUPS;

/// How the guest splits a list of `n` dependencies: the whole frames of [`CLAIM_BIG`], then
/// the whole groups of [`CLAIM_GROUP`], then the dependencies after them. Its own product
/// identity and range checks pin all three, so this only has to agree with them
/// (`list_split` in the guest). A list is never empty here: the guest hashes an empty one
/// without a split at all, so the call is guarded.
pub(super) fn list_split(n: usize) -> Vec<F192> {
    assert!(n > 0, "an empty list has no split");
    let rest = n % CLAIM_BIG;
    vec![
        count(n / CLAIM_BIG),
        count(rest / CLAIM_GROUP),
        count(rest % CLAIM_GROUP),
    ]
}

/// EIP-8288 entry order: `data_hash ‖ vk`, as the guest's `verify_generic` reads its slot.
pub(super) fn generic_claim_cells((data_hash, vk): &GenericClaim) -> [F192; 4] {
    let [d0, d1] = digest_cells(data_hash);
    let [k0, k1] = digest_cells(vk);
    [d0, d1, k0, k1]
}

/// EIP-8288 `get_deps_hash` as ethereum/EIPs#12664 replaces it: the hash of the dependencies' canonical 96-byte triples,
/// scheme word included, leanSPHINCS (`0x10`) ones first as the triples sort, each list in the order given. An empty
/// list hashes the empty string. The guest computes this same digest [`CLAIM_GROUP`] triples at a time
/// (`deps_list_digest`).
pub(super) fn deps_digest_cells(lean_sphincs: &[LeanSphincsClaim], generic: &[GenericClaim]) -> [F192; 2] {
    let mut bytes = Vec::with_capacity(DEPENDENCY_BYTES * (lean_sphincs.len() + generic.len()));
    let entries = (lean_sphincs.iter().map(|claim| (LEAN_SPHINCS_SCHEME, lean_sphincs_claim_cells(claim))))
        .chain(generic.iter().map(|claim| (LEAN_STARK_SCHEME, generic_claim_cells(claim))));
    for (scheme, cells) in entries {
        bytes.extend(scheme_word(scheme));
        bytes.extend(cell_bytes(cells));
    }
    hash_to_scalars(&primitives::hash::hash(&bytes))
}

/// EIP-8288 entry order: `data_hash ‖ pkSeed ‖ pkRoot`, so the list digest is `get_deps_hash`.
pub(super) fn lean_sphincs_claim_cells((message, pk): &LeanSphincsClaim) -> [F192; 4] {
    [
        pack_16_bytes(&message[..16]),
        pack_16_bytes(&message[16..]),
        pack_16_bytes(&pk.public_param),
        pack_16_bytes(&pk.root),
    ]
}

/// The statement's fixed header, ahead of the deferred cells: the seed, the dependency digest
/// ([`deps_digest_cells`]), and the DA digest ([`verifier::da::digest`]).
/// Fed to the guest as `STMT_HEADER`, which pins where its deferred cells start;
/// the header cells themselves are written out again there, and only the
/// end-to-end statement check holds the two spellings together.
pub(super) const STATEMENT_HEADER: usize = 6;

/// A plain hash over a lane stream, two lanes a 128-bit cell: what the guest gets
/// from `keccak_cells` over the same cells.
fn lane_hash(lanes: impl Iterator<Item = u64>) -> [F192; 2] {
    let bytes: Vec<u8> = lanes.flat_map(u64::to_le_bytes).collect();
    hash_to_scalars(&primitives::hash::hash(&bytes))
}

/// A node's public statement, hashed to the two words the VM publishes. The
/// guest's `statement_digest` computes exactly this, both for itself and when it
/// rebuilds a child's, which is what forces a whole tree onto one bytecode and
/// each child's claims, bound by the two list digests, onto its parent's lists.
///
/// Fixed-length preimage, so a plain hash, with no domain tag of its own: every
/// field has a fixed width, and the header leads with the environment digest, which
/// binds this bytecode and the proof system's version and so already separates the
/// preimage from every other use of the hash here. The header is hashed as the
/// canonical cells it already is (two lanes each, whence the assert, the guest being
/// unable to hash a third), then all three lanes of each deferred cell. The dependency
/// digest binds its list's length through the hash's padding, and each triple's scheme word
/// which scheme verified it.
pub(super) fn statement_digest(
    guest: Guest,
    generic: &[GenericClaim],
    lean_sphincs_signers: &[LeanSphincsClaim],
    da_digest: [u8; 32],
    defer: &DeferredClaim,
) -> [F192; 2] {
    statement_digest_of(guest, deps_digest_cells(lean_sphincs_signers, generic), da_digest, defer)
}

/// [`statement_digest`] from the dependency digest: all a holder of `deps_hash` alone needs.
pub(super) fn statement_digest_of(
    guest: Guest,
    deps_digest: [F192; 2],
    da_digest: [u8; 32],
    defer: &DeferredClaim,
) -> [F192; 2] {
    let seed = leanvm_core::cpu::fs_seed(unified_guest(guest));
    let da_digest = hash_to_scalars(&da_digest);
    let header: [F192; STATEMENT_HEADER] = [
        seed[0],
        seed[1],
        deps_digest[0],
        deps_digest[1],
        da_digest[0],
        da_digest[1],
    ];
    let mut cells = defer.cells();
    if !cells.len().is_multiple_of(2) {
        cells.push(F192::ZERO); // the guest pairs the odd cell with a zero scalar
    }
    let head = header.iter().flat_map(|x| {
        assert_eq!(x.c2, 0, "a header value is a canonical cell");
        [x.c0, x.c1]
    });
    lane_hash(head.chain(cells.iter().flat_map(|x| x.to_limbs())))
}
