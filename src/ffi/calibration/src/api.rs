//! One interface over the library revisions the suite builds against.
//!
//! `main` (ABI 12) proves one-claim generic dependencies under EIP-8288's guest. With the `batch` feature the
//! revision has ethereum/EIPs#12664's `Guest`, multi-claim leaves, leaf payments and finalization. Scenarios that
//! need something the build lacks get [`Unsupported`] and are reported as skipped.

use rec_aggregation::{EthereumClaims, EthereumProof};
use signatures::lean_sphincs::{LeanSphincsPublicKey, LeanSphincsSignature, Message};

pub type Stats = leanvm_core::cpu::Stats;
pub type RawSig = (LeanSphincsPublicKey, Message, LeanSphincsSignature);

/// The outer aggregation proof's `log_inv_rate`, as the library proves blocks.
pub const OUTER_LOG_INV_RATE: usize = 1;

/// What this build can do, printed by every binary so results carry it.
pub const BATCH: bool = cfg!(feature = "batch");
pub const COMMITTED: bool = cfg!(feature = "committed");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsupported(pub String);

impl std::fmt::Display for Unsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which aggregation guest proves a node: EIP-8288's, or the batch-pricing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestKind {
    Base,
    Batched,
}

impl GuestKind {
    pub fn index(self) -> u8 {
        match self {
            GuestKind::Base => 0,
            GuestKind::Batched => 1,
        }
    }

    pub fn from_index(i: u8) -> Option<Self> {
        match i {
            0 => Some(GuestKind::Base),
            1 => Some(GuestKind::Batched),
            _ => None,
        }
    }
}

/// A generic leaf: its sorted claims, the program key and the witness of a proof of [`leaf_statement`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leaf {
    pub claims: Vec<[u8; 32]>,
    pub vk: [u8; 32],
    pub witness: Vec<u8>,
}

/// The public statement a leaf's inner proof proves: EIP-8288's claim for one claim on `main`, `get_batch_hash`
/// otherwise (which equals it for one claim).
pub fn leaf_statement(claims: &[[u8; 32]]) -> [u8; 32] {
    #[cfg(feature = "batch")]
    {
        rec_aggregation::batch_hash(claims)
    }
    #[cfg(not(feature = "batch"))]
    {
        claims[0]
    }
}

/// `MAX_INNER_PROOFS_PER_STEP` as this library revision enforces it.
pub fn library_max_inner_proofs_per_step() -> usize {
    #[cfg(feature = "batch")]
    {
        rec_aggregation::MAX_INNER_PROOFS_PER_STEP
    }
    #[cfg(not(feature = "batch"))]
    {
        rec_aggregation::MAX_RECURSIONS.min(rec_aggregation::MAX_GENERIC_DEPENDENCIES)
    }
}

/// The most claims one leaf may carry under `guest`.
pub fn max_claims_per_leaf(guest: GuestKind) -> usize {
    #[cfg(feature = "batch")]
    {
        match guest {
            GuestKind::Base => rec_aggregation::Guest::Base.max_claims_per_leaf(),
            GuestKind::Batched => rec_aggregation::Guest::Batched.max_claims_per_leaf(),
        }
    }
    #[cfg(not(feature = "batch"))]
    {
        let _ = guest;
        1
    }
}

#[cfg(feature = "batch")]
fn guest(kind: GuestKind) -> rec_aggregation::Guest {
    match kind {
        GuestKind::Base => rec_aggregation::Guest::Base,
        GuestKind::Batched => rec_aggregation::Guest::Batched,
    }
}

fn unsupported_batched(kind: GuestKind) -> Result<(), Unsupported> {
    if kind == GuestKind::Batched && !BATCH {
        return Err(Unsupported(
            "the batch-pricing guest (ethereum/EIPs#12664) is not in this library revision".into(),
        ));
    }
    Ok(())
}

/// Compiles the guests this build has and proves an untimed one-signature step under each, so no timed step pays
/// first-use costs.
pub fn warm_up() {
    leanvm_core::init_prover();
    #[cfg(feature = "batch")]
    let kinds = [GuestKind::Base, GuestKind::Batched];
    #[cfg(not(feature = "batch"))]
    let kinds = [GuestKind::Base];
    for kind in kinds {
        #[cfg(feature = "batch")]
        rec_aggregation::warm_up(guest(kind));
        #[cfg(not(feature = "batch"))]
        rec_aggregation::warm_up();
        prove(
            kind,
            &[],
            vec![],
            crate::inputs::signatures(u64::MAX, 1),
            None,
        )
        .expect("the warm-up step proves");
    }
}

/// Proves one aggregation step. `declare` names the output's claims; `None` takes the union of what the inputs establish.
pub fn prove(
    kind: GuestKind,
    children: &[EthereumProof],
    leaves: Vec<Leaf>,
    sigs: Vec<RawSig>,
    declare: Option<&EthereumClaims>,
) -> Result<(EthereumProof, Stats), String> {
    unsupported_batched(kind).map_err(|e| e.0)?;
    #[cfg(feature = "batch")]
    {
        let leaves = leaves
            .into_iter()
            .map(|l| (l.claims, l.vk, l.witness))
            .collect();
        rec_aggregation::aggregate_with_stats(
            guest(kind),
            children,
            leaves,
            sigs,
            &[],
            declare,
            OUTER_LOG_INV_RATE,
        )
        .map_err(|e| format!("{e:?}"))
    }
    #[cfg(not(feature = "batch"))]
    {
        let mut raw = Vec::with_capacity(leaves.len());
        for l in leaves {
            if l.claims.len() != 1 {
                return Err("multi-claim leaves need the batch-pricing guest".into());
            }
            raw.push((l.claims[0], l.vk, l.witness));
        }
        rec_aggregation::aggregate_with_stats(children, raw, sigs, &[], declare, OUTER_LOG_INV_RATE)
            .map_err(|e| format!("{e:?}"))
    }
}

/// Proves a finalizing step (ethereum/EIPs#12664): `sources` are `(vk, leaf digest)` for batch claims a child carries.
pub fn finalize(
    children: &[EthereumProof],
    leaves: Vec<Leaf>,
    sigs: Vec<RawSig>,
    declare: &EthereumClaims,
    sources: &[([u8; 32], [u8; 32])],
) -> Result<(EthereumProof, Stats), String> {
    unsupported_batched(GuestKind::Batched).map_err(|e| e.0)?;
    #[cfg(feature = "batch")]
    {
        let leaves = leaves
            .into_iter()
            .map(|l| (l.claims, l.vk, l.witness))
            .collect();
        rec_aggregation::aggregate_finalized_with_stats(
            rec_aggregation::Guest::Batched,
            children,
            leaves,
            sigs,
            declare,
            sources,
            OUTER_LOG_INV_RATE,
        )
        .map_err(|e| format!("{e:?}"))
    }
    #[cfg(not(feature = "batch"))]
    {
        let _ = (children, leaves, sigs, declare, sources);
        unreachable!()
    }
}

/// The wire form of a proof; its claims travel separately.
pub fn proof_bytes(proof: &EthereumProof) -> Vec<u8> {
    proof.proof_bytes()
}

/// A proof received from another worker. Parsing recomputes the deferred claim; it does not verify.
pub fn proof_from_bytes(
    kind: GuestKind,
    bytes: &[u8],
    claims: EthereumClaims,
) -> Result<EthereumProof, String> {
    #[cfg(feature = "batch")]
    {
        EthereumProof::from_proof_bytes(guest(kind), bytes, claims).map_err(|e| format!("{e:?}"))
    }
    #[cfg(not(feature = "batch"))]
    {
        let _ = kind;
        EthereumProof::from_proof_bytes(bytes, claims).map_err(|e| format!("{e:?}"))
    }
}

/// A validator's check of a block proof against the block's dependency digest alone: EIP-8288's `deps_hash`, or
/// ethereum/EIPs#12664's `get_batch_final_hash` of it for a finalized proof.
pub fn verify_block(
    kind: GuestKind,
    finalized: bool,
    claims: &EthereumClaims,
    bytes: &[u8],
) -> Result<(), String> {
    #[cfg(feature = "batch")]
    {
        let hash = if finalized {
            rec_aggregation::final_deps_hash(&claims.lean_sphincs, &claims.generic)
        } else {
            rec_aggregation::deps_hash(&claims.lean_sphincs, &claims.generic)
        };
        rec_aggregation::verify_deps_hash(guest(kind), &hash, bytes).map_err(|e| format!("{e:?}"))
    }
    #[cfg(not(feature = "batch"))]
    {
        let _ = (kind, finalized);
        let hash = rec_aggregation::deps_hash(&claims.lean_sphincs, &claims.generic);
        rec_aggregation::verify_deps_hash(&hash, bytes).map_err(|e| format!("{e:?}"))
    }
}

/// The payment, batch-claim and finalized-claim keys of ethereum/EIPs#12664, for building `declare` lists.
pub mod batch {
    use super::*;

    /// `(claim, batch_claim_key(vk, leaf digest))` for each retained claim, then the leaf's payment.
    pub fn sponsored(
        leaf: &Leaf,
        retained: &[[u8; 32]],
    ) -> Result<Vec<rec_aggregation::GenericClaim>, Unsupported> {
        #[cfg(feature = "batch")]
        {
            let digest = rec_aggregation::batch_hash(&leaf.claims);
            let mut out: Vec<_> = retained
                .iter()
                .map(|c| (*c, rec_aggregation::batch_claim_key(&leaf.vk, &digest)))
                .collect();
            out.push((digest, rec_aggregation::payment_key(&leaf.vk)));
            Ok(out)
        }
        #[cfg(not(feature = "batch"))]
        {
            let _ = (leaf, retained);
            Err(Unsupported(
                "leaf payments need the batch-pricing guest".into(),
            ))
        }
    }

    /// The finalization source of a leaf: `(vk, leaf digest)`.
    pub fn source(leaf: &Leaf) -> ([u8; 32], [u8; 32]) {
        (leaf.vk, leaf_statement(&leaf.claims))
    }
}
