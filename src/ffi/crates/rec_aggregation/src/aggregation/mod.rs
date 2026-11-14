//! Recursive proofs of leanSTARK (`0x11`) and leanSPHINCS (`0x10`) dependency claims and LeanDA blob
//! well-formedness. One bytecode (`guests/lean_ethereum.py`, compiled as either [`Guest`]) serves every node of an aggregation tree.
//!
//! A node verifies `n_raw_generic` leanVM execution proofs of other programs, each an EIP-8288 batch
//! leaf ([`verify_batch_leaf`]), `n_raw_lean_sphincs` leanSPHINCS signatures and `n_children` sub-proofs
//! **of this same bytecode**, and by default publishes the sorted deduplicated union of their claim sets. A leanSTARK claim is
//! a `(data_hash, vk)` pair, a leanSPHINCS one a `(message, pubkey)` pair. Coverage is what carries the
//! security claim: a write-once slot per declared claim, written once by each raw
//! signature and each child claim, plus a final count, so every declared claim is
//! backed by a real signature or a verified child.
//!
//! Those slots are one contiguous region per scheme, so the one range check a write
//! already needs also keeps a signature off the other scheme's declared claims: that
//! is what makes the published split mean which scheme verified which claim, at
//! every level of the tree.
//!
//! A duplicate slot sits outside the prefix the digest hashes, so a claim in one is
//! covered and not published. `aggregate`'s `declare` rests on that. A slot holds
//! four cells, the pubkey and its message, so the guest reads each signature's message
//! out of the slot it verifies.
//!
//! The bytecode is compiled to a fixed point on its own size
//! ([`unified_guest`]): the recursion placeholders depend on the inner bytecode
//! size, and here the inner bytecode is this one. Its digest does not need a
//! fixed point, riding the statement instead of the code.
//!
//! One fixed polynomial, the stacked bytecode, is too
//! big to evaluate in-circuit, so each node exports one deferred claim on it
//! and batches its children's carried claims with the fresh ones its
//! verifications raise (`doc/leanvm/main.tex` §Deferred evaluation claims). Only
//! the root's is discharged natively, by [`EthereumProof::verify`].
//!
//! `gen_verify` derives the guest's whole witness for a child from the real
//! `cpu::layout` of the inner program and the summary the `verifier` crate
//! reads out of the child's proof, so there is no hand-mirrored copy of the
//! protocol to drift.

mod cells;
mod child;
mod claim_pool;
mod coverage;
mod deferred;
mod error;
mod generic;
mod guest;
mod hints;
mod node;
mod placeholders;
mod proof;
mod statement;
#[cfg(test)]
mod generic_tests;
#[cfg(test)]
mod tests;

pub use error::{AggregateVerifyError, AggregationError, SnarkProveError, SnarkVerifyError};
pub use generic::{
    BATCH_DOMAIN, LEAN_SPHINCS_SCHEME, LEAN_STARK_SCHEME, MAX_CLAIMS_PER_BATCH_LEAF, MAX_GENERIC_BYTECODE_LOG, VK_TAG,
    batch_hash, generic_verification_key, generic_witness, scheme_word, valid_batch_claims, verify_batch_leaf,
    verify_generic, vk_hash,
};
pub use guest::{Guest, unified_guest, warm_up};
pub use node::{aggregate, aggregate_with_stats};
pub use proof::{
    EthereumClaims, EthereumProof, aggregated_vk, deps_hash, deps_public_input_bytes, verify_deps_hash,
};
use signatures::lean_sphincs;
use signatures::lean_sphincs::LeanSphincsPublicKey;

/// One leanSTARK (`0x11`) claim, an EIP-8288 dependency without its scheme word: `data_hash`,
/// then the program's verification key ([`generic_verification_key`]), in the EIP's bytewise order.
pub type GenericClaim = ([u8; 32], [u8; 32]);

/// One raw leanSTARK dependency: `data_hash`, the key, and the witness ([`generic_witness`]).
pub type RawGeneric = ([u8; 32], [u8; 32], Vec<u8>);

/// One leaf: its claims, the key, and the witness ([`generic_witness`]) of a proof of [`batch_hash`]`(claims)`.
/// [`aggregate`] says which dependencies it establishes.
pub type BatchLeaf = (Vec<[u8; 32]>, [u8; 32], Vec<u8>);

/// A direct leanSTARK dependency as the singleton batch leaf `[data_hash]` (EIP-8288).
pub fn singleton_leaf((data_hash, vk, witness): RawGeneric) -> BatchLeaf {
    (vec![data_hash], vk, witness)
}

/// One leanSPHINCS claim, an EIP-8288 dependency without its scheme word: `data_hash`, then
/// the key (`pkSeed ‖ pkRoot`). The tuple's order is the EIP's bytewise order of the 64-byte entry.
pub type LeanSphincsClaim = (lean_sphincs::Message, LeanSphincsPublicKey);

/// The most earlier aggregates one [`aggregate`] call can take, so the arity of
/// an aggregation tree.
pub const MAX_RECURSIONS: usize = 16;

/// EIP-8288 `MAX_INNER_PROOFS_PER_STEP` (provisional, 16 in the EIP): the most batch leaves and earlier aggregates one
/// [`aggregate`] call verifies together. Raw leanSPHINCS signatures do not count.
///
/// Chosen with the leaf bounds, as ethereum/EIPs#12664 requires: under the committed bytecode key, a step of
/// 16 maximum-resource leaves (2^11 instructions, 256 claims, distinct keys) commits 2^27.6 of the outer proof's 2^30
/// witness bound, and 16 children 2^26.8 (`guests/BATCHING.md`).
pub const MAX_INNER_PROOFS_PER_STEP: usize = 16;
