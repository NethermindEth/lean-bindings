pub mod aggregation;
/// The Keccak hash chain, proven end to end. A `src` module rather than its own
/// test binary so it shares the process with the other workloads.
#[cfg(test)]
mod hash_chain;
#[cfg(any(test, feature = "signers-cache"))]
pub mod signers_cache;

pub use aggregation::{
    AggregateVerifyError, AggregationError, BatchLeaf, EthereumClaims, EthereumProof, Guest, LeanSphincsClaim,
    GenericClaim, RawGeneric, BATCH_DOMAIN, LEAN_SPHINCS_SCHEME, LEAN_STARK_SCHEME, VK_TAG,
    MAX_CLAIMS_PER_BATCH_LEAF, MAX_GENERIC_BYTECODE_LOG, batch_hash,
    generic_verification_key, generic_witness, scheme_word, singleton_leaf, valid_batch_claims, verify_batch_leaf, verify_generic, vk_hash,
    MAX_INNER_PROOFS_PER_STEP, MAX_RECURSIONS, SnarkProveError, SnarkVerifyError, aggregate, aggregated_vk, deps_hash, deps_public_input_bytes, verify_deps_hash, aggregate_with_stats, warm_up,
};
