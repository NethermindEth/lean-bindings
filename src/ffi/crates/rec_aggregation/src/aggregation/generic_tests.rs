//! leanSTARK (`0x11`) dependencies: proving, recursion, the digest, and the guest's rejections.

use super::cells::count;
use super::error::AggregationError;
use super::generic::parse_witness;
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
    let program = compile(&parse(src).expect("parse")).committed();
    let table: Vec<u64> = bytecode_table(program.prog()).iter().map(|w| w.0).collect();
    let vk = generic_verification_key(&table).expect("within the cap");
    assert_eq!(
        program.bytecode_commitment().map(|c| c.key),
        Some(vk),
        "the key is the prover's IV"
    );
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

/// `n` distinct claims, strictly increasing: `first` repeated, then the index in the last two bytes.
fn claims_from(first: u8, n: usize) -> Vec<[u8; 32]> {
    (0..n as u16)
        .map(|i| {
            let mut claim = [first; 32];
            claim[30..].copy_from_slice(&i.to_be_bytes());
            claim
        })
        .collect()
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
        verify_deps_hash(proof.guest(), &hash, &proof.proof_bytes()).expect("verifies under its digest");
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
    let proof = aggregate(Guest::Base, &[], singles([&dep]), vec![], &[], None, RATE).expect("proves");
    assert_eq!(proof.claims().generic, vec![claim(&dep)]);
    check(&proof);
}

#[test]
fn mixed_leaf_with_a_near_cap_program() {
    leanvm_core::init_prover();
    let deps = [preimage_dep(3), wide_dep([9; 32])];
    let proof = aggregate(Guest::Base, &[], singles(&deps), sphincs(2), &[], None, RATE).expect("proves");
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
    let mixed = aggregate(Guest::Base, &[], singles([&a, &b]), signers.clone(), &[], None, RATE).expect("mixed leaf");
    let generic_leaf = aggregate(Guest::Base, &[], singles([&a]), vec![], &[], None, RATE).expect("generic leaf");
    let sphincs_leaf = aggregate(Guest::Base, &[], vec![], signers[..1].to_vec(), &[], None, RATE).expect("sphincs leaf");
    let merged = aggregate(Guest::Base, &[mixed.clone(), generic_leaf.clone(), sphincs_leaf],
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
    let discarded = aggregate(Guest::Base, &[mixed, generic_leaf], vec![], vec![], &[], Some(&declare), RATE).expect("discards");
    assert_eq!(discarded.claims(), &declare);
    check(&discarded);
    // A generic leaf merged with a raw generic dependency at the same node.
    let c = preimage_dep(6);
    let raw_and_child = aggregate(Guest::Base, &[discarded], singles([&c]), vec![], &[], None, RATE).expect("raw and child");
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
        aggregate(Guest::Base, &[], leaves.clone(), vec![], &[], None, RATE).err(),
        Some(AggregationError::TooManyInnerProofs)
    );
    let child = aggregate(Guest::Base, &[], leaves[..1].to_vec(), vec![], &[], None, RATE).expect("proves");
    let with_child = || {
        aggregate(Guest::Base, std::slice::from_ref(&child),
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
    let results = [aggregate(Guest::Base, &[], leaves.clone(), vec![], &[], None, RATE), with_child()];
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
    assert!(verify_batch_leaf(Guest::Batched, &full.0, &full.1, &full.2));
    let extra = preimage_dep(200);
    let proof = aggregate(Guest::Batched, &[], vec![full, singleton_leaf(extra.clone())], vec![], &[], None, RATE).expect("proves");
    assert_eq!(proof.claims().generic.len(), MAX_CLAIMS_PER_BATCH_LEAF + 1);
    assert!(proof.claims().generic.contains(&claim(&extra)));
    check(&proof);
    // The digest, not the length, bounds a received list.
    let claims = proof.claims().clone();
    EthereumProof::from_proof_bytes(Guest::Batched, &proof.proof_bytes(), claims)
        .expect("decodes")
        .verify()
        .expect("verifies");

    let over = leaf(&claims_from(1, MAX_CLAIMS_PER_BATCH_LEAF + 1));
    assert!(!verify_batch_leaf(Guest::Batched, &over.0, &over.1, &over.2));
    assert_eq!(
        aggregate(Guest::Batched, &[], vec![over.clone()], vec![], &[], None, RATE).err(),
        Some(AggregationError::InvalidGenericWitness)
    );
    SKIP_LEAF_CHECKS.with(|skip| skip.set(true));
    let result = aggregate(Guest::Batched, &[], vec![over], vec![], &[], None, RATE);
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
    assert!(verify_batch_leaf(Guest::Batched, &claims, &vk, &witness));
    for other in [&[b, a][..], &[a], &[a, b, c], &[], &[a, a]] {
        assert!(!verify_batch_leaf(Guest::Batched, other, &vk, &witness), "{other:?}");
    }
    let mut wrong = vk;
    wrong[0] ^= 1;
    assert!(!verify_batch_leaf(Guest::Batched, &claims, &wrong, &witness));
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
    let batched = aggregate(Guest::Batched, &[], vec![leaf(&[a, b])], vec![], &[], None, RATE).expect("a batch leaf proves");
    let singletons = aggregate(Guest::Batched, &[], vec![leaf(&[b]), leaf(&[a])], vec![], &[], None, RATE).expect("singletons prove");
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
    let pruned = aggregate(Guest::Batched, &[], leaves, vec![], &[], Some(&declare), RATE).expect("prunes");
    assert_eq!(pruned.claims(), &declare);
    check(&pruned);
    // A batch leaf beside a child.
    let merged = aggregate(Guest::Batched, &[pruned], vec![leaf(&[a])], vec![], &[], None, RATE).expect("merges");
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
    check(&aggregate(Guest::Batched, &[], vec![ordered], vec![], &[], None, RATE).expect("ordered at byte 17"));
    let unordered = [leaf(&[b, a]), leaf(&[a, a]), leaf(&[high, low])];
    for bad in &unordered {
        assert!(!verify_batch_leaf(Guest::Batched, &bad.0, &bad.1, &bad.2));
        assert_eq!(
            aggregate(Guest::Batched, &[], vec![bad.clone()], vec![], &[], None, RATE).err(),
            Some(AggregationError::InvalidGenericWitness)
        );
    }
    SKIP_LEAF_CHECKS.with(|skip| skip.set(true));
    let mut results: Vec<_> = unordered
        .iter()
        .map(|bad| aggregate(Guest::Batched, &[], vec![bad.clone()], vec![], &[], None, RATE))
        .collect();
    // The order is read off bytes that must be the slots' claims: sorted bytes do not hide unsorted claims.
    FORGE.with(|forge| {
        *forge.borrow_mut() = Some(Box::new(|h: &mut Hints| {
            let first = h.entry_mut("batch_bytes", 0).clone();
            let second = std::mem::replace(h.entry_mut("batch_bytes", 1), first);
            *h.entry_mut("batch_bytes", 0) = second;
        }))
    });
    results.push(aggregate(Guest::Batched, &[], vec![unordered[0].clone()], vec![], &[], None, RATE));
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

/// Every dependency of a leaf is on one of its claims under the leaf's key: a leaf cannot cover another key's claim with
/// the same bytes, nor a dependency on another of its claims.
#[test]
fn a_leaf_covers_claims_under_its_own_key_only() {
    leanvm_core::init_prover();
    let a = [0x0a; 32];
    let other = preimage_dep(0xc0);
    let c = other.0;
    let pair = leaf(&[a, c]);
    let declare = EthereumClaims {
        generic: vec![(a, pair.1), claim(&other)],
        ..Default::default()
    };
    let run = |children: &[EthereumProof]| aggregate(Guest::Batched, children, vec![pair.clone()], vec![], &[], Some(&declare), RATE);
    assert_eq!(run(&[]).err(), Some(AggregationError::NotCovered), "(c, K2) under the leaf's key K1");
    let child = aggregate(Guest::Batched, &[], singles([&other]), vec![], &[], None, RATE).expect("the child proves");
    check(&run(std::slice::from_ref(&child)).expect("the honest node proves"));
    FORGE.with(|f| *f.borrow_mut() = Some(Box::new(|h: &mut Hints| *h.entry_mut("leaf_claim_index", 0) = vec![count(1)])));
    refused_by_the_guest("(a, K1) proved by claim c", run(std::slice::from_ref(&child)));
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
        refused_by_the_guest(name, aggregate(Guest::Batched, &[], vec![pair.clone()], vec![], &[], None, RATE));
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
            aggregate(Guest::Base, &[], singles([&dep]), vec![], &[], None, RATE).err(),
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
    // The witness is `kgen ‖ root ‖ ood ‖ proof`.
    let with_root = |kgen: u8, root: &[u8]| [&[kgen][..], root, &witness[33..]].concat();
    let kgen = witness[0];
    let root = &witness[1..33];
    let ood: [u8; 32] = witness[33..65].try_into().unwrap();
    // P's proof shown with another program's root, of the same size, under P's key (the rehash of
    // the root misses the key) or under that root's own key (the transcript, seeded with that key,
    // is not the one P's proof was made under, and the opening is against the other table).
    let other = generic(&PREIMAGE.replace("[pre[0], pre[1], pre[2]]", "[pre[1], pre[0], pre[2]]"));
    assert_eq!(other.table.len(), preimage_program().table.len());
    assert_ne!(other.table, preimage_program().table);
    let other_root = generic_witness(&other.table, &parse_witness(&witness).unwrap().proof).unwrap()[1..33].to_vec();
    let mut flipped_root = root.to_vec();
    flipped_root[3] ^= 1;
    // The same root under a size one larger: its own key, so only the transcript and layout catch it.
    let root_bytes: [u8; 32] = root.try_into().unwrap();
    let wider_vk = verifier::committed_key(kgen as usize + 1, &root_bytes, &ood);
    let cases: Vec<(&str, RawGeneric)> = vec![
        (
            "another root under P's key",
            (data_hash, vk, with_root(kgen, &other_root)),
        ),
        (
            "another root under its own key",
            (data_hash, other.vk, with_root(kgen, &other_root)),
        ),
        ("tampered root", (data_hash, vk, with_root(kgen, &flipped_root))),
        (
            "P's root at another size, under that key",
            (data_hash, wider_vk, with_root(kgen + 1, root)),
        ),
        ("wrong data_hash", (flip(data_hash), vk, witness.clone())),
        ("wrong vk", (data_hash, flip(vk), witness.clone())),
        ("0x10 claim in the 0x11 list", (message, sphincs_bytes, witness.clone())),
    ];
    super::hints::HONEST_GENERIC.with(|h| *h.borrow_mut() = Some((batch_hash(&[data_hash]), witness.clone())));
    // The honest dependency itself proves under the switch: only the false ones below must fail.
    aggregate(Guest::Base, &[],
        singles([&(data_hash, vk, witness.clone())]),
        vec![],
        &[],
        None,
        RATE,
    )
    .expect("the honest claim proves");
    for (name, dep) in cases {
        refused_by_the_guest(name, aggregate(Guest::Base, &[], singles([&dep]), vec![], &[], None, RATE));
    }
    super::hints::HONEST_GENERIC.with(|h| *h.borrow_mut() = None);
}

/// A prover choosing its own IV: program Q (accepting any input) proved under P's key, with Q's root and a valid
/// opening of Q's table. Only the guest's rehash of `kgen ‖ root` into the key rejects it; natively, the IV the root
/// derives is not the one the proof was made under.
#[test]
fn a_proof_under_another_programs_key_is_rejected() {
    leanvm_core::init_prover();
    let p = preimage_program();
    let q = wide_program();
    let data_hash = [0x5a; 32];
    let statement = batch_hash(&[data_hash]);
    let mut forged = q.program.clone().forge_fiat_shamir_iv(p.vk);
    forged.set_witness("pi", vec![cells(&statement).to_vec()]);
    let (proof, _) = prove(&forged, cells(&statement), RATE).expect("Q proves under P's IV");
    let witness = generic_witness(&q.table, &proof).expect("a witness");
    assert!(!verify_generic(&data_hash, &p.vk, &witness));
    assert!(!verify_generic(&data_hash, &q.vk, &witness));
    super::hints::FORGED_IV.set(Some(p.vk));
    let result = aggregate(Guest::Base, &[], singles([&(data_hash, p.vk, witness)]), vec![], &[], None, RATE);
    super::hints::FORGED_IV.set(None);
    refused_by_the_guest("Q's proof and root under P's key", result);
}

/// A key whose out-of-domain value is not the table's, with a proof made under that key: only the opening's
/// out-of-domain claim tells it apart, natively and in the guest. The honest value on the same path proves.
#[test]
fn a_key_must_carry_the_tables_out_of_domain_value() {
    leanvm_core::init_prover();
    let p = preimage_program();
    let commitment = p.program.bytecode_commitment().unwrap();
    let data_hash = [13u8; 32];
    let pre = [&BATCH_DOMAIN[..], &data_hash].concat();
    let statement = batch_hash(&[data_hash]);
    for wrong in [false, true] {
        let mut ood = commitment.ood;
        if wrong {
            ood[0] ^= 1;
        }
        let vk = verifier::committed_key(commitment.log_instructions, &commitment.root, &ood);
        let mut program = p.program.clone().forge_fiat_shamir_iv(vk);
        program.set_witness("pre", vec![pre.chunks(16).map(super::cells::pack_16_bytes).collect()]);
        let (proof, _) = prove(&program, cells(&statement), RATE).expect("proves under the key");
        let kgen = [commitment.log_instructions as u8];
        let witness = [&kgen[..], &commitment.root, &ood, &proof.to_bytes()].concat();
        assert_eq!(verify_generic(&data_hash, &vk, &witness), !wrong);
        super::hints::FORGED_IV.set(Some(vk));
        let result = aggregate(Guest::Base, &[], singles([&(data_hash, vk, witness)]), vec![], &[], None, RATE);
        super::hints::FORGED_IV.set(None);
        if wrong {
            refused_by_the_guest("a key with a wrong out-of-domain value", result);
        } else {
            check(&result.expect("the honest value proves"));
        }
    }
}

/// A committed program's bytecode value comes from its proof's stream: the deferred-value hint the
/// guest still pops for it is ignored, so a node proves with it changed.
#[test]
fn a_committed_program_ignores_the_hinted_bytecode_value() {
    leanvm_core::init_prover();
    let dep = preimage_dep(12);
    FORGE.with(|forge| {
        *forge.borrow_mut() = Some(Box::new(|h: &mut Hints| h.entry_mut("bytecode_val", 0)[0] += F192::ONE))
    });
    let result = aggregate(Guest::Base, &[], singles([&dep]), vec![], &[], None, RATE);
    FORGE.with(|forge| *forge.borrow_mut() = None);
    result.expect("proves");
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
        aggregate(Guest::Base, &[], vec![], vec![signer], &[], None, RATE).err(),
        Some(AggregationError::MalformedRawSignature)
    );
}

/// Hints edited after the host built them: every run must fail.
#[test]
fn forged_generic_hints_are_rejected() {
    leanvm_core::init_prover();
    let dep = preimage_dep(11);
    // Where the proof's stream carries the bytecode value, and its last scalar, the bytecode opening's.
    let parsed = parse_witness(&dep.2).unwrap();
    let (_, summary) = super::generic::check(&batch_hash(&[dep.0]), &dep.1, &parsed).unwrap();
    let value = leanvm_core::cpu::from_scalar(summary.bytecode_value);
    let value_at = parsed
        .proof
        .stream
        .iter()
        .position(|x| *x == value)
        .expect("the value rides the stream");
    let last_at = parsed.proof.stream.len() - 1;
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
        // The bytecode value the proof sends, and the opening that follows the main one.
        (
            "bytecode value in the stream",
            Box::new(move |h| flip(h, "stream", value_at)),
        ),
        (
            "bytecode opening's last scalar",
            Box::new(move |h| flip(h, "stream", last_at)),
        ),
        ("root hint", Box::new(move |h| flip(h, "gen_root", 0))),
        ("out-of-domain value hint", Box::new(move |h| flip(h, "gen_ood", 1))),
        // The same 16 bytes, but a cell with a nonzero top limb.
        (
            "root hint with a top limb",
            Box::new(|h| h.entry_mut("gen_root", 0)[0] += F192::new(0, 0, 1)),
        ),
        (
            "bytecode opening's last leaf",
            Box::new(|h| {
                let last = h.len("merkle_leaf_rows") - 1;
                h.entry_mut("merkle_leaf_rows", last)[0] += F192::ONE;
            }),
        ),
        (
            "bytecode opening's last cap",
            Box::new(|h| {
                let last = h.len("merkle_caps") - 1;
                h.entry_mut("merkle_caps", last)[2] += F192::ONE;
            }),
        ),
    ];
    for (name, forgery) in forgeries {
        FORGE.with(|forge| *forge.borrow_mut() = Some(Box::new(move |h: &mut Hints| forgery(h))));
        refused_by_the_guest(name, aggregate(Guest::Base, &[], singles([&dep]), vec![], &[], None, RATE));
    }
}

/// A leaf's batch claim entries for `claims` (ethereum/EIPs#12664), bound to the leaf.
fn batch_claims(leaf: &BatchLeaf, claims: &[[u8; 32]]) -> Vec<GenericClaim> {
    let digest = batch_hash(&leaf.0);
    claims.iter().map(|claim| (*claim, batch_claim_key(&leaf.1, &digest))).collect()
}

/// A leaf's payment entry.
fn payment(leaf: &BatchLeaf) -> GenericClaim {
    (batch_hash(&leaf.0), payment_key(&leaf.1))
}

fn declaring(mut generic: Vec<GenericClaim>) -> EthereumClaims {
    generic.sort();
    EthereumClaims { generic, ..Default::default() }
}

/// The finalized list of a leaf's retained claims and its payment.
fn finalized(leaf: &BatchLeaf, claims: &[[u8; 32]]) -> Vec<GenericClaim> {
    let mut list: Vec<_> = claims.iter().map(|claim| (*claim, finalized_claim_key(&leaf.1))).collect();
    list.push(payment(leaf));
    list.sort();
    list
}

/// A finalized proof verifies natively and under `final_deps_hash` of its list.
fn check_final(proof: &EthereumProof, expected: &[GenericClaim]) {
    assert!(proof.finalized());
    assert_eq!(proof.claims().generic, expected);
    proof.verify().expect("verifies");
    let hash = final_deps_hash(&proof.claims().lean_sphincs, expected);
    let g_bytes: Vec<u8> = expected.iter().flat_map(|(d, k)| d.iter().chain(k).copied()).collect();
    let s = primitives::hash::hash(&[]);
    let plain = primitives::hash::hash(
        &[s.as_slice(), &primitives::hash::hash(&g_bytes), b"eip8288/leanstark-deps\0\0\0\0\0\0\0\0\0\0"].concat(),
    );
    let independent = primitives::hash::hash(&[&b"EIP8288:batch-final:v1"[..], &plain].concat());
    assert_eq!(hash, independent);
    verify_deps_hash(proof.guest(), &hash, &proof.proof_bytes()).expect("verifies under its digest");
    assert!(verify_deps_hash(proof.guest(), &deps_hash(&[], expected), &proof.proof_bytes()).is_err());
}

/// ethereum/EIPs#12664: the new keys bind their whole scheme words, a batch claim's its source too, and a one-claim
/// leaf's statement is EIP-8288's `get_claim_hash`.
#[test]
fn batch_keys_bind_scheme_and_source() {
    let (a, vk, d) = ([0xa0; 32], [0x5a; 32], [0xd0; 32]);
    assert_eq!(batch_hash(&[a]), primitives::hash::hash(&[&b"EIP8288:batch:v1"[..], &a].concat()));
    let word = |scheme: u8| [[0u8; 31].as_slice(), &[scheme]].concat();
    assert_eq!(batch_claim_key(&vk, &d), primitives::hash::hash(&[&word(0x12)[..], &vk, &d].concat()));
    assert_eq!(finalized_claim_key(&vk), primitives::hash::hash(&[&word(0x12)[..], &vk].concat()));
    assert_eq!(payment_key(&vk), primitives::hash::hash(&[&word(0x13)[..], &vk].concat()));
    let keys = [vk, batch_claim_key(&vk, &d), batch_claim_key(&vk, &[0xd1; 32]), finalized_claim_key(&vk), payment_key(&vk)];
    assert!(keys.iter().enumerate().all(|(i, k)| keys[i + 1..].iter().all(|other| other != k)));
    assert_ne!(deps_hash(&[], &[(a, keys[3])]), final_deps_hash(&[], &[(a, keys[3])]));
    assert_ne!(verifier::TAG[0], 0, "a program key's preimage starts nonzero, the batch keys' with zeros");
}

/// ethereum/EIPs#12664 Test Cases: 64 members and their payment finalize; pruned to one member, the same leaf and payment
/// still do; an unused payment finalizes alone; a retained claim without its payment does not.
#[test]
fn sponsored_leaves_finalize_with_their_payment() {
    leanvm_core::init_prover();
    let claims = claims_from(1, 64);
    let full = leaf(&claims);
    let mut all = batch_claims(&full, &claims);
    all.push(payment(&full));
    let state = aggregate(Guest::Batched, &[], vec![full.clone()], vec![], &[], Some(&declaring(all.clone())), RATE)
        .expect("an intermediate statement");
    check(&state);
    let finalize = |children: &[EthereumProof], leaves: Vec<BatchLeaf>, declare: &EthereumClaims, sources: &[([u8; 32], [u8; 32])]| {
        aggregate_finalized(Guest::Batched, children, leaves, vec![], declare, sources, RATE)
    };
    check_final(&finalize(&[], vec![full.clone()], &declaring(all.clone()), &[]).expect("finalizes"), &finalized(&full, &claims));
    // Pruned from the intermediate statement to one member and the payment.
    let one = declaring(vec![batch_claims(&full, &claims[..1])[0], payment(&full)]);
    let source = [(full.1, batch_hash(&full.0))];
    let pruned = finalize(std::slice::from_ref(&state), vec![], &one, &source).expect("prunes and finalizes");
    check_final(&pruned, &finalized(&full, &claims[..1]));
    // An unused payment, alone.
    let unused = declaring(vec![payment(&full)]);
    check_final(&finalize(std::slice::from_ref(&state), vec![], &unused, &source).expect("an unused payment"), &[payment(&full)]);
    // A retained claim without its payment is an intermediate state; it does not finalize, nor without a known source.
    let unpaid = declaring(batch_claims(&full, &claims[..1]));
    check(&aggregate(Guest::Batched, std::slice::from_ref(&state), vec![], vec![], &[], Some(&unpaid), RATE).expect("an unpaid state"));
    assert_eq!(finalize(std::slice::from_ref(&state), vec![], &unpaid, &source).err(), Some(AggregationError::UnpaidClaim));
    // Without its source the claim stays bound: the statement is none a block computes.
    let unnamed = finalize(std::slice::from_ref(&state), vec![], &one, &[]).expect("finalizes as is");
    let block = final_deps_hash(&[], &finalized(&full, &claims[..1]));
    assert!(verify_deps_hash(Guest::Batched, &block, &unnamed.proof_bytes()).is_err());
    // The guest checks the payment: pointed at the claim itself, the run fails.
    let entries = declaring(vec![batch_claims(&full, &claims[..1])[0], payment(&full)]);
    let claim_first = entries.generic[0].0 == claims[0];
    FORGE.with(|f| {
        *f.borrow_mut() = Some(Box::new(move |h: &mut Hints| {
            *h.entry_mut("final_payment_index", 0) = vec![count(usize::from(!claim_first))];
        }))
    });
    refused_by_the_guest("a claim paid by itself", finalize(std::slice::from_ref(&state), vec![], &entries, &source));
    // Nor by an entry with the payment's digest under another scheme's key: an ordinary claim on the digest.
    let digest = batch_hash(&full.0);
    let decoy = leaf(&[digest]);
    let mut generic = vec![batch_claims(&full, &claims[..1])[0], payment(&full), (digest, decoy.1)];
    generic.sort();
    let (decoy_at, payment_at) = (
        generic.iter().position(|e| *e == (digest, decoy.1)).unwrap(),
        generic.iter().position(|e| *e == payment(&full)).unwrap(),
    );
    let with_decoy = EthereumClaims { generic, ..Default::default() };
    let run = || finalize(std::slice::from_ref(&state), vec![decoy.clone()], &with_decoy, &source);
    let mut expected = finalized(&full, &claims[..1]);
    expected.push((digest, decoy.1));
    expected.sort();
    check_final(&run().expect("the decoy is an ordinary claim"), &expected);
    assert_ne!(decoy_at, payment_at);
    FORGE.with(|f| *f.borrow_mut() = Some(Box::new(move |h: &mut Hints| *h.entry_mut("final_payment_index", 0) = vec![count(decoy_at)])));
    refused_by_the_guest("a claim paid by an ordinary claim on the digest", run());
}

/// ethereum/EIPs#12664 Test Cases: singleton leaves under one key need their distinct payments, a union cannot claim the
/// payment of an unproved leaf, and overlapping leaves assign each claim one authenticated source whose payment it needs.
#[test]
fn sources_come_from_verified_leaves() {
    leanvm_core::init_prover();
    let (a, b, c) = ([0xa3; 32], [0xb3; 32], [0xc3; 32]);
    let (la, lb) = (leaf(&[a]), leaf(&[b]));
    let singles = declaring([batch_claims(&la, &[a]), batch_claims(&lb, &[b]), vec![payment(&la), payment(&lb)]].concat());
    let run = |leaves: Vec<BatchLeaf>, declare: &EthereumClaims| {
        aggregate_finalized(Guest::Batched, &[], leaves, vec![], declare, &[], RATE)
    };
    run(vec![la.clone(), lb.clone()], &singles).expect("two singletons with their payments");
    let ab = leaf(&[a, b]);
    let union = declaring([batch_claims(&ab, &[a, b]), vec![payment(&ab)]].concat());
    assert_eq!(run(vec![la.clone(), lb.clone()], &union).err(), Some(AggregationError::NotCovered));
    // Overlapping leaves both establish b: either source alone, with its own payment.
    let bc = leaf(&[b, c]);
    for (owner, other) in [(&ab, &bc), (&bc, &ab)] {
        let mut generic = batch_claims(owner, &[b]);
        generic.extend([payment(owner), payment(other)]);
        let proof = run(vec![ab.clone(), bc.clone()], &declaring(generic)).expect("one source");
        assert!(proof.claims().generic.contains(&(b, finalized_claim_key(&owner.1))));
    }
    let both = declaring([batch_claims(&ab, &[b]), batch_claims(&bc, &[b]), vec![payment(&ab), payment(&bc)]].concat());
    assert_eq!(run(vec![ab.clone(), bc.clone()], &both).err(), Some(AggregationError::UnpaidClaim), "one dependency twice");
    let wrong = declaring([batch_claims(&ab, &[b]), vec![payment(&bc)]].concat());
    assert_eq!(run(vec![ab.clone(), bc.clone()], &wrong).err(), Some(AggregationError::UnpaidClaim), "another leaf's payment");
    // The guest binds the key to the leaf: a claim hinted as batched under another leaf's source fails.
    let foreign = declaring(batch_claims(&bc, &[b]));
    SKIP_LEAF_CHECKS.with(|skip| skip.set(true));
    let result = aggregate(Guest::Batched, &[], vec![ab.clone()], vec![], &[], Some(&foreign), RATE);
    SKIP_LEAF_CHECKS.with(|skip| skip.set(false));
    refused_by_the_guest("b under bc's source from ab", result);
}

/// ethereum/EIPs#12664 Test Cases: pruning cannot restore a discarded claim or change its source, and a finalized proof is
/// no child, so its claims never re-enter recursion without their sources.
#[test]
fn recursion_keeps_sources() {
    leanvm_core::init_prover();
    let claims = claims_from(0x40, 4);
    let four = leaf(&claims);
    let kept = declaring(vec![batch_claims(&four, &claims[..1])[0], payment(&four)]);
    let pruned = aggregate(Guest::Batched, &[], vec![four.clone()], vec![], &[], Some(&kept), RATE).expect("prunes");
    check(&pruned);
    let other = leaf(&claims[..1]);
    for (name, generic) in [
        ("restored", [batch_claims(&four, &claims[..2]), vec![payment(&four)]].concat()),
        ("resourced", vec![batch_claims(&other, &claims[..1])[0], payment(&four)]),
    ] {
        let result = aggregate(Guest::Batched, std::slice::from_ref(&pruned), vec![], vec![], &[], Some(&declaring(generic)), RATE);
        assert_eq!(result.err(), Some(AggregationError::NotCovered), "{name}");
    }
    let source = [(four.1, batch_hash(&four.0))];
    let last = aggregate_finalized(Guest::Batched, std::slice::from_ref(&pruned), vec![], vec![], &kept, &source, RATE)
        .expect("finalizes");
    assert_eq!(
        aggregate(Guest::Batched, std::slice::from_ref(&last), vec![], vec![], &[], None, RATE).err(),
        Some(AggregationError::InvalidChild(AggregateVerifyError::MalformedClaim))
    );
    // In the guest: the leaf that covers a second claim is made to cover nothing.
    let extra = leaf(&claims[1..2]);
    let with_extra = declaring(vec![batch_claims(&four, &claims[..1])[0], payment(&four), (claims[1], extra.1)]);
    let parent = || aggregate(Guest::Batched, std::slice::from_ref(&pruned), vec![extra.clone()], vec![], &[], Some(&with_extra), RATE);
    check(&parent().expect("a source survives a merge"));
    FORGE.with(|f| *f.borrow_mut() = Some(Box::new(|h: &mut Hints| *h.entry_mut("leaf_establishes", 0) = vec![count(0)])));
    refused_by_the_guest("an uncovered claim", parent());
}

/// EIP-8288's guest takes one-claim leaves and establishes no batch claim or payment, nor finalizes.
#[test]
fn the_base_guest_refuses_batching() {
    leanvm_core::init_prover();
    let (a, b) = ([0xa2; 32], [0xb2; 32]);
    let pair = leaf(&[a, b]);
    assert!(!verify_batch_leaf(Guest::Base, &pair.0, &pair.1, &pair.2));
    assert_eq!(
        aggregate(Guest::Base, &[], vec![pair.clone()], vec![], &[], None, RATE).err(),
        Some(AggregationError::InvalidGenericWitness)
    );
    let single = leaf(&[a]);
    let sponsored = declaring(vec![batch_claims(&single, &[a])[0], payment(&single)]);
    let run = || aggregate(Guest::Base, &[], vec![single.clone()], vec![], &[], Some(&sponsored), RATE);
    assert_eq!(run().err(), Some(AggregationError::NotCovered));
    let ordinary = declaring(vec![(a, single.1)]);
    SKIP_LEAF_CHECKS.with(|skip| skip.set(true));
    let results = [
        aggregate(Guest::Base, &[], vec![pair], vec![], &[], None, RATE),
        run(),
        aggregate_finalized(Guest::Base, &[], vec![single.clone()], vec![], &ordinary, &[], RATE),
    ];
    SKIP_LEAF_CHECKS.with(|skip| skip.set(false));
    for (name, result) in ["a two-claim leaf", "a batch claim and payment", "finalization"].into_iter().zip(results) {
        refused_by_the_guest(name, result);
    }
}

/// ethereum/EIPs#12664 Test Case: a finalized proof, a payment-only one included, is imported as neither an ordinary nor an
/// intermediate input; the guest rebuilds every child statement in the plain domain.
#[test]
fn finalized_proofs_are_no_inputs() {
    leanvm_core::init_prover();
    let single = leaf(&[[0xa7; 32]]);
    let paid = aggregate_finalized(Guest::Batched, &[], vec![single.clone()], vec![], &declaring(vec![payment(&single)]), &[], RATE)
        .expect("a payment-only finalized proof");
    check_final(&paid, &[payment(&single)]);
    let import = || aggregate(Guest::Batched, std::slice::from_ref(&paid), vec![], vec![], &[], None, RATE);
    assert_eq!(import().err(), Some(AggregationError::InvalidChild(AggregateVerifyError::MalformedClaim)));
    SKIP_LEAF_CHECKS.with(|skip| skip.set(true));
    let result = import();
    SKIP_LEAF_CHECKS.with(|skip| skip.set(false));
    refused_by_the_guest("a finalized child", result);
}
