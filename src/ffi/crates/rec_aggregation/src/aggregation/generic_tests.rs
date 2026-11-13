//! leanSTARK (`0x11`) dependencies: proving, recursion, the digest, and the guest's rejections.

use super::cells::count;
use super::error::AggregationError;
use super::hints::{FORGE, Hints, SKIP_LEAF_CHECKS};
use super::node::aggregate;
use super::proof::{EthereumClaims, EthereumProof};
use super::*;
use crate::signers_cache::get_lean_sphincs_signers;
use fiat_shamir::merkle::hash_to_scalars;
use lean_compiler::{compile, parse};
use leanvm_core::cpu::{Program, bytecode_table, prove};
use primitives::field::F192;
use signatures::lean_sphincs::{LeanSphincsPublicKey, LeanSphincsSignature};
use std::sync::OnceLock;

const RATE: usize = leanvm_core::pcs::TEST_LOG_INV_RATE;

/// Publishes `keccak256` of a hinted 48-byte preimage: it accepts exactly the hashes of preimages, so the batch
/// hash of any one claim, `keccak256(BATCH_DOMAIN ‖ claim)`.
const PREIMAGE: &str = "\
def main():
    pre = StackBuf(3)
    hint_witness(pre, \"pre\")
    c = StackBuf(2)
    keccak_cells([pre[0], pre[1], pre[2]], c)
    p = 1
    p[1] = c[0]
    p[GEN] = c[1]
    return
";

/// Accepts any canonical public input, after `steps` multiply-adds: [`WIDE_STEPS`] bring it near the cap.
fn any_input_source(steps: usize) -> String {
    let mut src = String::from("def main():\n    h = StackBuf(2)\n    hint_witness(h, \"pi\")\n    acc = h[0]\n");
    for _ in 0..steps {
        src += "    acc = acc * h[1] + h[0]\n";
    }
    src += "    p = 1\n    p[1] = h[0]\n    p[GEN] = h[1]\n    return\n";
    src
}
const WIDE_STEPS: usize = 900;

struct Generic {
    program: Program,
    table: Vec<u64>,
    vk: [u8; 32],
}

fn generic(src: &str) -> Generic {
    let program = compile(&parse(src).expect("parse"));
    let table: Vec<u64> = bytecode_table(program.prog()).iter().map(|w| w.0).collect();
    let vk = generic_verification_key(&table).expect("within the cap");
    Generic { program, table, vk }
}

fn preimage_program() -> &'static Generic {
    static P: OnceLock<Generic> = OnceLock::new();
    P.get_or_init(|| generic(PREIMAGE))
}

fn wide_program() -> &'static Generic {
    static P: OnceLock<Generic> = OnceLock::new();
    P.get_or_init(|| generic(&any_input_source(WIDE_STEPS)))
}

fn any_input_program() -> &'static Generic {
    static P: OnceLock<Generic> = OnceLock::new();
    P.get_or_init(|| generic(&any_input_source(0)))
}

fn cells(digest: &[u8; 32]) -> [F192; 2] {
    hash_to_scalars(digest)
}

/// A preimage-check dependency on the claim `seed` repeated 32 times: a proof that
/// `batch_hash([data_hash]) = keccak256(BATCH_DOMAIN ‖ data_hash)`.
fn preimage_dep(seed: u8) -> RawGeneric {
    let g = preimage_program();
    let data_hash = [seed; 32];
    let pre = [&BATCH_DOMAIN[..], &data_hash].concat();
    let mut program = g.program.clone();
    let pre_cells: Vec<F192> = pre.chunks(16).map(super::cells::pack_16_bytes).collect();
    program.set_witness("pre", vec![pre_cells]);
    let statement = batch_hash(&[data_hash]);
    let (proof, _) = prove(&program, cells(&statement), RATE).expect("the preimage program proves");
    (data_hash, g.vk, generic_witness(&g.table, &proof).expect("a witness"))
}

/// A witness of `g`, an any-input program, on the public input `statement`.
fn any_input_witness(g: &Generic, statement: &[u8; 32]) -> Vec<u8> {
    let mut program = g.program.clone();
    program.set_witness("pi", vec![cells(statement).to_vec()]);
    let (proof, _) = prove(&program, cells(statement), RATE).expect("the any-input program proves");
    generic_witness(&g.table, &proof).expect("a witness")
}

/// A dependency on the near-cap program, for any `data_hash`.
fn wide_dep(data_hash: [u8; 32]) -> RawGeneric {
    let g = wide_program();
    (data_hash, g.vk, any_input_witness(g, &batch_hash(&[data_hash])))
}

/// A batch leaf of `claims`, in the given order, under the small any-input program's key.
fn leaf(claims: &[[u8; 32]]) -> BatchLeaf {
    let g = any_input_program();
    (claims.to_vec(), g.vk, any_input_witness(g, &batch_hash(claims)))
}

/// `n` distinct claims, strictly increasing.
fn claims_from(first: u8, n: usize) -> Vec<[u8; 32]> {
    (0..n).map(|i| [first + i as u8; 32]).collect()
}

type RawSphincs = (LeanSphincsPublicKey, lean_sphincs::Message, LeanSphincsSignature);

fn sphincs(n: usize) -> Vec<RawSphincs> {
    get_lean_sphincs_signers(n)
}

fn claim(raw: &RawGeneric) -> GenericClaim {
    (raw.0, raw.1)
}

/// Direct dependencies as singleton leaves.
fn singles<'a>(deps: impl IntoIterator<Item = &'a RawGeneric>) -> Vec<BatchLeaf> {
    deps.into_iter().cloned().map(singleton_leaf).collect()
}

/// The D6 digest, from raw bytes: each list's 64-byte entries hashed, then combined.
fn independent_deps_hash(sphincs: &[LeanSphincsClaim], generic: &[GenericClaim]) -> [u8; 32] {
    let s_bytes: Vec<u8> = sphincs
        .iter()
        .flat_map(|(m, pk)| m.iter().chain(&pk.root).chain(&pk.public_param).copied())
        .collect();
    let s = primitives::hash::hash(&s_bytes);
    if generic.is_empty() {
        return s;
    }
    let g_bytes: Vec<u8> = generic.iter().flat_map(|(d, vk)| d.iter().chain(vk).copied()).collect();
    let g = primitives::hash::hash(&g_bytes);
    primitives::hash::hash(&[s.as_slice(), &g, b"eip8288/leanstark-deps\0\0\0\0\0\0\0\0\0\0"].concat())
}

/// A proof verifies as an aggregate and under its digest alone.
fn check(proof: &EthereumProof) {
    proof.verify().expect("verifies");
    let claims = proof.claims();
    let hash = deps_hash(&claims.lean_sphincs, &claims.generic);
    assert_eq!(hash, independent_deps_hash(&claims.lean_sphincs, &claims.generic));
    if claims.da_commitment.is_none() {
        verify_deps_hash(&hash, &proof.proof_bytes()).expect("verifies under its digest");
    }
}

#[test]
fn programs_have_the_intended_sizes() {
    assert!(preimage_program().program.prog().len() <= 1 << 6);
    let wide = wide_program().program.prog().len();
    assert_eq!(
        wide,
        1 << MAX_GENERIC_BYTECODE_LOG,
        "near the cap: {}",
        wide_program().program.code_len()
    );
}

#[test]
fn native_verifier_accepts_and_rejects() {
    let (data_hash, vk, witness) = preimage_dep(1);
    assert!(verify_generic(&data_hash, &vk, &witness));
    let mut other = data_hash;
    other[0] ^= 1;
    assert!(!verify_generic(&other, &vk, &witness));
    let mut bad_vk = vk;
    bad_vk[31] ^= 1;
    assert!(!verify_generic(&data_hash, &bad_vk, &witness));
    for at in [0, 1, 33, 33 + 8 * 3, witness.len() - 1] {
        let mut tampered = witness.clone();
        tampered[at] ^= 1;
        assert!(!verify_generic(&data_hash, &vk, &tampered), "byte {at}");
    }
    let mut over = witness.clone();
    over[0] = (MAX_GENERIC_BYTECODE_LOG + 1) as u8;
    assert!(!verify_generic(&data_hash, &vk, &over));
    assert!(generic_verification_key(&vec![0; 16 << (MAX_GENERIC_BYTECODE_LOG + 1)]).is_none());
}

#[test]
fn generic_only_leaf() {
    leanvm_core::init_prover();
    let dep = preimage_dep(2);
    let proof = aggregate(&[], singles([&dep]), vec![], &[], None, RATE).expect("proves");
    assert_eq!(proof.claims().generic, vec![claim(&dep)]);
    check(&proof);
}

#[test]
fn mixed_leaf_with_a_near_cap_program() {
    leanvm_core::init_prover();
    let deps = [preimage_dep(3), wide_dep([9; 32])];
    let proof = aggregate(&[], singles(&deps), sphincs(2), &[], None, RATE).expect("proves");
    assert_eq!(
        (proof.claims().generic.len(), proof.claims().lean_sphincs.len()),
        (2, 2)
    );
    check(&proof);
}

#[test]
fn pure_lean_sphincs_digest_is_unchanged() {
    let claims: Vec<LeanSphincsClaim> = sphincs(3).iter().map(|(pk, m, _)| (*m, *pk)).collect();
    assert_eq!(deps_hash(&claims, &[]), independent_deps_hash(&claims, &[]));
    let entries: Vec<u8> = claims
        .iter()
        .flat_map(|(m, pk)| m.iter().chain(&pk.root).chain(&pk.public_param).copied())
        .collect();
    assert_eq!(deps_hash(&claims, &[]), primitives::hash::hash(&entries));
}

/// The same 64 bytes as a leanSPHINCS and as a leanSTARK claim are two dependencies: the digests differ,
/// and each list's claims are covered only by its own scheme.
#[test]
fn the_same_bytes_under_both_schemes_are_distinct() {
    let (message, pk) = sphincs(1).iter().map(|(pk, m, _)| (*m, *pk)).next().unwrap();
    let mut key = [0; 32];
    key[..16].copy_from_slice(&pk.root);
    key[16..].copy_from_slice(&pk.public_param);
    let as_sphincs = deps_hash(&[(message, pk)], &[]);
    let as_generic = deps_hash(&[], &[(message, key)]);
    let both = deps_hash(&[(message, pk)], &[(message, key)]);
    assert!(as_sphincs != as_generic && as_sphincs != both && as_generic != both);
}

#[test]
fn recursion_mixes_schemes_dedups_and_discards() {
    leanvm_core::init_prover();
    let (a, b) = (preimage_dep(4), preimage_dep(5));
    let signers = sphincs(2);
    // A child with both lists, and a generic-only child sharing one of its generic claims.
    let mixed = aggregate(&[], singles([&a, &b]), signers.clone(), &[], None, RATE).expect("mixed leaf");
    let generic_leaf = aggregate(&[], singles([&a]), vec![], &[], None, RATE).expect("generic leaf");
    let sphincs_leaf = aggregate(&[], vec![], signers[..1].to_vec(), &[], None, RATE).expect("sphincs leaf");
    let merged = aggregate(
        &[mixed.clone(), generic_leaf.clone(), sphincs_leaf],
        vec![],
        vec![],
        &[],
        None,
        RATE,
    )
    .expect("merges");
    let mut want = vec![claim(&a), claim(&b)];
    want.sort();
    assert_eq!(merged.claims().generic, want, "the shared claim is published once");
    assert_eq!(merged.claims().lean_sphincs.len(), 2);
    check(&merged);
    // Discard b: a node may publish less than its children cover.
    let declare = EthereumClaims {
        generic: vec![claim(&a)],
        lean_sphincs: mixed.claims().lean_sphincs.clone(),
        da_commitment: None,
    };
    let discarded = aggregate(&[mixed, generic_leaf], vec![], vec![], &[], Some(&declare), RATE).expect("discards");
    assert_eq!(discarded.claims(), &declare);
    check(&discarded);
    // A generic leaf merged with a raw generic dependency at the same node.
    let c = preimage_dep(6);
    let raw_and_child = aggregate(&[discarded], singles([&c]), vec![], &[], None, RATE).expect("raw and child");
    assert!(raw_and_child.claims().generic.contains(&claim(&c)));
    check(&raw_and_child);
}

/// EIP-8288 `MAX_INNER_PROOFS_PER_STEP` counts batch leaves and children together.
#[test]
fn inner_proofs_over_the_cap_are_refused() {
    leanvm_core::init_prover();
    let leaves: Vec<BatchLeaf> = (0..=MAX_INNER_PROOFS_PER_STEP as u8)
        .map(|i| leaf(&[[100 + i; 32]]))
        .collect();
    assert_eq!(
        aggregate(&[], leaves.clone(), vec![], &[], None, RATE).err(),
        Some(AggregationError::TooManyInnerProofs)
    );
    let child = aggregate(&[], leaves[..1].to_vec(), vec![], &[], None, RATE).expect("proves");
    let with_child = || {
        aggregate(
            std::slice::from_ref(&child),
            leaves[1..].to_vec(),
            vec![],
            &[],
            None,
            RATE,
        )
    };
    assert_eq!(with_child().err(), Some(AggregationError::TooManyInnerProofs));
    // The guest refuses them too.
    SKIP_LEAF_CHECKS.with(|skip| skip.set(true));
    let results = [aggregate(&[], leaves.clone(), vec![], &[], None, RATE), with_child()];
    SKIP_LEAF_CHECKS.with(|skip| skip.set(false));
    for (name, result) in ["17 leaves", "16 leaves and a child"].into_iter().zip(results) {
        refused_by_the_guest(name, result);
    }
}

/// A leaf holds at most `MAX_CLAIMS_PER_BATCH_LEAF` claims; a list of leanSTARK claims may hold more.
#[test]
fn a_full_leaf_proves_and_unions_past_the_leaf_bound() {
    leanvm_core::init_prover();
    let full = leaf(&claims_from(1, MAX_CLAIMS_PER_BATCH_LEAF));
    assert!(verify_batch_leaf(&full.0, &full.1, &full.2));
    let extra = preimage_dep(200);
    let proof = aggregate(&[], vec![full, singleton_leaf(extra.clone())], vec![], &[], None, RATE).expect("proves");
    assert_eq!(proof.claims().generic.len(), MAX_CLAIMS_PER_BATCH_LEAF + 1);
    assert!(proof.claims().generic.contains(&claim(&extra)));
    check(&proof);
    // The digest, not the length, bounds a received list.
    let claims = proof.claims().clone();
    EthereumProof::from_proof_bytes(&proof.proof_bytes(), claims)
        .expect("decodes")
        .verify()
        .expect("verifies");

    let over = leaf(&claims_from(1, MAX_CLAIMS_PER_BATCH_LEAF + 1));
    assert!(!verify_batch_leaf(&over.0, &over.1, &over.2));
    assert_eq!(
        aggregate(&[], vec![over.clone()], vec![], &[], None, RATE).err(),
        Some(AggregationError::InvalidGenericWitness)
    );
    SKIP_LEAF_CHECKS.with(|skip| skip.set(true));
    let result = aggregate(&[], vec![over], vec![], &[], None, RATE);
    SKIP_LEAF_CHECKS.with(|skip| skip.set(false));
    refused_by_the_guest("one claim over", result);
}

/// EIP-8288 Test Case 12: the leaf statement is `get_batch_hash(claims)` over the exact, nonempty, strictly increasing
/// claim list, and a direct dependency is the singleton leaf.
#[test]
fn batch_leaf_statement() {
    let (a, b, c) = ([0xa0; 32], [0xb0; 32], [0xc0; 32]);
    assert_eq!(
        batch_hash(&[a, b]),
        primitives::hash::hash(&[&b"EIP8288:batch:v1"[..], &a, &b].concat())
    );
    let (claims, vk, witness) = leaf(&[a, b]);
    assert!(verify_batch_leaf(&claims, &vk, &witness));
    for other in [&[b, a][..], &[a], &[a, b, c], &[], &[a, a]] {
        assert!(!verify_batch_leaf(other, &vk, &witness), "{other:?}");
    }
    let mut wrong = vk;
    wrong[0] ^= 1;
    assert!(!verify_batch_leaf(&claims, &wrong, &witness));
    let g = any_input_program();
    assert!(verify_generic(&a, &g.vk, &any_input_witness(g, &batch_hash(&[a]))));
    assert!(
        !verify_generic(&a, &g.vk, &any_input_witness(g, &a)),
        "a proof of the bare data_hash"
    );
}

/// EIP-8288 Test Cases 2 and 12: a batch leaf and singleton leaves under one key prove the same dependencies, and
/// overlapping leaves union and discard like any other inputs.
#[test]
fn batch_leaf_and_singletons_prove_the_same_dependencies() {
    leanvm_core::init_prover();
    let (a, b, c) = ([0xa0; 32], [0xb0; 32], [0xc0; 32]);
    let vk = any_input_program().vk;
    let batched = aggregate(&[], vec![leaf(&[a, b])], vec![], &[], None, RATE).expect("a batch leaf proves");
    let singletons = aggregate(&[], vec![leaf(&[b]), leaf(&[a])], vec![], &[], None, RATE).expect("singletons prove");
    assert_eq!(batched.claims().generic, vec![(a, vk), (b, vk)]);
    assert_eq!(batched.claims(), singletons.claims());
    check(&batched);
    check(&singletons);
    // Overlapping leaves, with a discarded: {b, c} is published, a is checked and dropped.
    let declare = EthereumClaims {
        generic: vec![(b, vk), (c, vk)],
        ..Default::default()
    };
    let leaves = vec![leaf(&[a, b]), leaf(&[b, c])];
    let pruned = aggregate(&[], leaves, vec![], &[], Some(&declare), RATE).expect("prunes");
    assert_eq!(pruned.claims(), &declare);
    check(&pruned);
    // A batch leaf beside a child.
    let merged = aggregate(&[pruned], vec![leaf(&[a])], vec![], &[], None, RATE).expect("merges");
    assert_eq!(merged.claims().generic, vec![(a, vk), (b, vk), (c, vk)]);
    check(&merged);
}

/// EIP-8288 Test Case 12: the guest rejects repeated or non-byte-lexicographic claims even when the leaf proves their
/// digest, and decides the order at the first differing byte.
#[test]
fn the_guest_checks_claim_order() {
    leanvm_core::init_prover();
    let (a, b) = ([0xa0; 32], [0xb0; 32]);
    let (mut low, mut high) = (a, a);
    low[17] = 0x01;
    high[17] = 0x02;
    high[31] = 0x00;
    let ordered = leaf(&[low, high]);
    check(&aggregate(&[], vec![ordered], vec![], &[], None, RATE).expect("ordered at byte 17"));
    let unordered = [leaf(&[b, a]), leaf(&[a, a]), leaf(&[high, low])];
    for bad in &unordered {
        assert!(!verify_batch_leaf(&bad.0, &bad.1, &bad.2));
        assert_eq!(
            aggregate(&[], vec![bad.clone()], vec![], &[], None, RATE).err(),
            Some(AggregationError::InvalidGenericWitness)
        );
    }
    SKIP_LEAF_CHECKS.with(|skip| skip.set(true));
    let mut results: Vec<_> = unordered
        .iter()
        .map(|bad| aggregate(&[], vec![bad.clone()], vec![], &[], None, RATE))
        .collect();
    // The order is read off bytes that must be the slots' claims: sorted bytes do not hide unsorted claims.
    FORGE.with(|forge| {
        *forge.borrow_mut() = Some(Box::new(|h: &mut Hints| {
            let first = h.entry_mut("batch_bytes", 0).clone();
            let second = std::mem::replace(h.entry_mut("batch_bytes", 1), first);
            *h.entry_mut("batch_bytes", 0) = second;
        }))
    });
    results.push(aggregate(&[], vec![unordered[0].clone()], vec![], &[], None, RATE));
    SKIP_LEAF_CHECKS.with(|skip| skip.set(false));
    let names = [
        "descending",
        "repeated",
        "descending at byte 17",
        "sorted bytes for descending claims",
    ];
    for (name, result) in names.into_iter().zip(results) {
        refused_by_the_guest(name, result);
    }
}

/// Every claim of a leaf is under the leaf's key: a leaf cannot cover another key's claim with the same bytes, even
/// where a child covers it too.
#[test]
fn a_leaf_covers_claims_under_its_own_key_only() {
    leanvm_core::init_prover();
    let a = [0x0a; 32];
    let other = preimage_dep(0xc0);
    let c = other.0;
    let child = aggregate(&[], singles([&other]), vec![], &[], None, RATE).expect("the child proves");
    let pair = leaf(&[a, c]);
    // Published: (a, K1) and (c, K2). Honestly the leaf's c takes the duplicate slot 2, as (c, K1), and the child's
    // (c, K2) slot 1. The forgery hands the leaf slot 1 and the child a duplicate slot holding (c, K2).
    let declare = EthereumClaims {
        generic: vec![(a, pair.1), claim(&other)],
        ..Default::default()
    };
    let run = |forge: bool| {
        if forge {
            let child_claim = super::statement::generic_claim_cells(&claim(&other)).to_vec();
            FORGE.with(|f| {
                *f.borrow_mut() = Some(Box::new(move |h: &mut Hints| {
                    *h.entry_mut("raw_index", 1) = vec![count(1)];
                    *h.entry_mut("child_claim_gap", 0) = vec![count(2)];
                    *h.entry_mut("dup_claims", 0) = child_claim;
                }))
            });
        }
        aggregate(
            std::slice::from_ref(&child),
            vec![pair.clone()],
            vec![],
            &[],
            Some(&declare),
            RATE,
        )
    };
    check(&run(false).expect("the honest node proves"));
    refused_by_the_guest("a claim under another key", run(true));
}

/// A batch leaf's hints edited after the host built them: every run must fail.
#[test]
fn forged_leaf_hints_are_rejected() {
    leanvm_core::init_prover();
    let pair = leaf(&[[0xa0; 32], [0xb0; 32]]);
    let forgeries: Vec<(&str, Box<dyn Fn(&mut Hints)>)> = vec![
        (
            "claim byte out of range",
            Box::new(|h| h.entry_mut("batch_bytes", 0)[0] = count(0xa0 ^ 0x100)),
        ),
        (
            "the other claim's bytes",
            Box::new(|h| {
                let other = h.entry_mut("batch_bytes", 1).clone();
                *h.entry_mut("batch_bytes", 0) = other;
            }),
        ),
        (
            "claim count above the cap",
            Box::new(|h| *h.entry_mut("leaf_claims", 0) = vec![count(MAX_CLAIMS_PER_BATCH_LEAF)]),
        ),
        (
            "a claim dropped",
            Box::new(|h| *h.entry_mut("leaf_claims", 0) = vec![count(0)]),
        ),
        (
            "both claims on one slot",
            Box::new(|h| {
                let first = h.entry_mut("raw_index", 0).clone();
                *h.entry_mut("raw_index", 1) = first;
            }),
        ),
    ];
    for (name, forgery) in forgeries {
        FORGE.with(|forge| *forge.borrow_mut() = Some(Box::new(move |h: &mut Hints| forgery(h))));
        refused_by_the_guest(name, aggregate(&[], vec![pair.clone()], vec![], &[], None, RATE));
    }
}

#[test]
fn an_invalid_witness_is_refused_natively() {
    leanvm_core::init_prover();
    let (data_hash, vk, witness) = preimage_dep(8);
    let mut other = data_hash;
    other[5] ^= 1;
    for dep in [
        (other, vk, witness.clone()),
        (data_hash, [7; 32], witness.clone()),
        (data_hash, vk, witness[..40].to_vec()),
    ] {
        assert_eq!(
            aggregate(&[], singles([&dep]), vec![], &[], None, RATE).err(),
            Some(AggregationError::InvalidGenericWitness)
        );
    }
}

fn refused_by_the_guest(name: &str, result: Result<EthereumProof, AggregationError>) {
    assert!(
        matches!(result, Err(AggregationError::ProofError(_))),
        "{name}: {:?}",
        result.map(|_| ())
    );
}

/// False claims and witnesses the host's native check refuses, handed to the guest with an honest
/// proof's sub-proof hints: every run must fail.
#[test]
fn the_guest_refuses_false_generic_claims() {
    leanvm_core::init_prover();
    let (data_hash, vk, witness) = preimage_dep(9);
    let signer = sphincs(1);
    let (message, pk) = (signer[0].1, signer[0].0);
    let mut sphincs_bytes = [0; 32];
    sphincs_bytes[..16].copy_from_slice(&pk.root);
    sphincs_bytes[16..].copy_from_slice(&pk.public_param);
    let flip = |mut bytes: [u8; 32]| {
        bytes[0] ^= 1;
        bytes
    };
    let table_word = {
        let mut w = witness.clone();
        w[1 + 8 * 5] ^= 1;
        w
    };
    // The reviewer's attack: P's proof shown with another program's table of the same size, under P's
    // key (the rehash of the table misses the key) or under that table's own key (the transcript,
    // seeded with that key, is not the one P's proof was made under).
    let other = generic(&PREIMAGE.replace("[pre[0], pre[1], pre[2]]", "[pre[1], pre[0], pre[2]]"));
    assert_eq!(other.table.len(), preimage_program().table.len());
    assert_ne!(other.table, preimage_program().table);
    let end = 1 + 8 * other.table.len();
    let swapped = [
        &witness[..1],
        &other.table.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<_>>(),
        &witness[end..],
    ]
    .concat();
    let cases: Vec<(&str, RawGeneric)> = vec![
        ("another table under P's key", (data_hash, vk, swapped.clone())),
        ("another table under its own key", (data_hash, other.vk, swapped)),
        ("wrong data_hash", (flip(data_hash), vk, witness.clone())),
        ("wrong vk", (data_hash, flip(vk), witness.clone())),
        ("tampered table word", (data_hash, vk, table_word)),
        ("0x10 claim in the 0x11 list", (message, sphincs_bytes, witness.clone())),
    ];
    super::hints::HONEST_GENERIC.with(|h| *h.borrow_mut() = Some((batch_hash(&[data_hash]), witness.clone())));
    // The honest dependency itself proves under the switch: only the false ones below must fail.
    aggregate(
        &[],
        singles([&(data_hash, vk, witness.clone())]),
        vec![],
        &[],
        None,
        RATE,
    )
    .expect("the honest claim proves");
    for (name, dep) in cases {
        refused_by_the_guest(name, aggregate(&[], singles([&dep]), vec![], &[], None, RATE));
    }
    super::hints::HONEST_GENERIC.with(|h| *h.borrow_mut() = None);
}

/// A leanSTARK claim's bytes presented as a leanSPHINCS claim have no signature: the host refuses it.
#[test]
fn a_generic_claim_is_no_lean_sphincs_claim() {
    let (data_hash, vk, _) = preimage_dep(10);
    let mut signer = sphincs(1).remove(0);
    signer.0 = LeanSphincsPublicKey {
        root: vk[..16].try_into().unwrap(),
        public_param: vk[16..].try_into().unwrap(),
    };
    signer.1 = data_hash;
    assert_eq!(
        aggregate(&[], vec![], vec![signer], &[], None, RATE).err(),
        Some(AggregationError::MalformedRawSignature)
    );
}

/// Hints edited after the host built them: every run must fail.
#[test]
fn forged_generic_hints_are_rejected() {
    leanvm_core::init_prover();
    let dep = preimage_dep(11);
    let flip = |hints: &mut Hints, name: &str, at: usize| {
        let entry = hints.entry_mut(name, 0);
        entry[at] += F192::ONE;
    };
    let forgeries: Vec<(&str, Box<dyn Fn(&mut Hints)>)> = vec![
        ("tampered proof scalar", Box::new(move |h| flip(h, "stream", 40))),
        (
            "kgen above the cap",
            Box::new(|h| *h.entry_mut("gen_kbc", 0) = vec![count(MAX_GENERIC_BYTECODE_LOG + 1)]),
        ),
        // The generic program's bytecode claim is settled in the guest: a false value is not deferred.
        ("smuggled bytecode value", Box::new(move |h| flip(h, "bytecode_val", 0))),
        // The first word's bytes split another way, (b0 + x^8, b1 + 1): the same field value, other
        // bytes. The first piece is out of the byte table's range.
        (
            "forged byte split",
            Box::new(|h| {
                let word = preimage_program().table[0];
                let (b0, b1) = ((word & 0xff) as usize, (word >> 8 & 0xff) as usize);
                let row = h.entry_mut("gen_bytes", 0);
                row[0] = count(b0 ^ 0x100);
                row[1] = count(b1 ^ 1);
            }),
        ),
    ];
    for (name, forgery) in forgeries {
        FORGE.with(|forge| *forge.borrow_mut() = Some(Box::new(move |h: &mut Hints| forgery(h))));
        refused_by_the_guest(name, aggregate(&[], singles([&dep]), vec![], &[], None, RATE));
    }
}
