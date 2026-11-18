//! Recursive aggregation of signature claims and LeanDA blobs, on either prover: everything here is generic over
//! [`isa::Prover`], which each prover tree implements.
//!
//! One bytecode (`guests/lean_ethereum.py`) serves every node of an aggregation tree.
//!
//! A node verifies `n_raw_generic` leanVM execution proofs of other programs ([`verify_generic`]),
//! `n_raw_lean_sphincs` leanSPHINCS signatures and `n_children` sub-proofs **of this same bytecode**,
//! and by default publishes the sorted deduplicated union of their claim sets. A leanSTARK (`0x11`)
//! claim is a `(data_hash, vk)` pair, a leanSPHINCS (`0x10`) one a `(message, pubkey)` pair, and the
//! statement commits to both lists with the EIP-8288 dependency digest ([`deps_hash`]). Coverage is what carries the
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
//! covered and not published. `aggregate`'s `OutputClaims::Only` rests on that. A slot holds
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
//! the root's is discharged natively, by [`AggregateProof::verify`].
//!
//! `gen_verify` derives the guest's whole witness for a child from the layout
//! of the inner program (the stable prover's `cpu::layout`) and the summary the `verifier`
//! crate reads out of the child's proof.

mod cells;
mod child;
mod claim_pool;
mod coverage;
mod deferred;
mod error;
mod generic;
#[cfg(test)]
mod generic_tests;
mod guest;
mod hints;
mod node;
mod placeholders;
mod proof;
#[cfg(any(test, feature = "signers-cache"))]
pub mod signers_cache;
mod statement;
#[cfg(test)]
mod tests;

pub use error::AggregateError;
pub use generic::{
    LEANSTARK_DEPS_DOMAIN, MAX_GENERIC_BYTECODE_LOG, MAX_GENERIC_DEPENDENCIES, generic_verification_key,
    generic_witness, verify_generic,
};
pub use guest::unified_guest;
use lean_sphincs::LeanSphincsPublicKey;
pub use node::aggregate;
pub use proof::{AggregateClaims, AggregateProof, OutputClaims, aggregated_vk, deps_hash, verify_deps_hash};

/// One leanSTARK (`0x11`) claim, an EIP-8288 dependency without its scheme word: `data_hash`,
/// then the program's verification key ([`generic_verification_key`]), in the EIP's bytewise order.
pub type GenericClaim = ([u8; 32], [u8; 32]);

/// One raw leanSTARK dependency: `data_hash`, the key, and the witness ([`generic_witness`]).
pub type RawGeneric = ([u8; 32], [u8; 32], Vec<u8>);

/// One leanSPHINCS claim, an EIP-8288 dependency without its scheme word: the message (`data_hash`),
/// then the key (`PK.seed ‖ PK.root`), in the EIP's bytewise order of the 64-byte entry.
pub type LeanSphincsClaim = (lean_sphincs::Message, LeanSphincsPublicKey);

/// The maximum number of child proofs one [`aggregate`] call can take.
pub const MAX_RECURSIONS: usize = 16;

pub use verifier::{MAX_LOG_INV_RATE, MIN_LOG_INV_RATE};
