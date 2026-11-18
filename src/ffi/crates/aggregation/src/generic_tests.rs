//! leanSTARK (`0x11`) dependencies: proving, recursion, the digest, and the guest's rejections.

use super::cells::count;
use super::hints::{ALLOW_MANY_GENERIC, FORGE, Hints};
use super::*;
use crate::signers_cache::{LeanSphincsSigner, get_lean_sphincs_signers};
use fiat_shamir_prover::merkle::hash_to_scalars;
use isa::{Program, Prover};
use lean_sphincs::LeanSphincsPublicKey;
use lean_vm_core::StableProver;
use lean_vm_core::cpu::to_scalar;
use primitives::field::F128;
use std::sync::OnceLock;
use verifier::E;
use zkdsl_compiler::{compile, parse};

const RATE: usize = lean_vm_core::pcs::TEST_LOG_INV_RATE;

/// An aggregate's claims and proof.
type Node = (AggregateClaims, AggregateProof);

/// [`aggregate`](super::aggregate) on the stable prover at the test rate, publishing `declare` or every claim.
fn aggregate(
    children: &[Node],
    raw_generic: Vec<RawGeneric>,
    raw_lean_sphincs: Vec<LeanSphincsSigner>,
    declare: Option<&AggregateClaims>,
) -> Result<Node, AggregateError> {
    StableProver::init();
    let output = declare.map_or(OutputClaims::All, OutputClaims::Only);
    super::aggregate::<StableProver>(children, raw_generic, raw_lean_sphincs, None, output, RATE)
        .map(|(claims, proof, _)| (claims, proof))
}

/// Proves `program` on the public input `data_hash`, with the hint streams `witness`.
fn prove(program: &Program, witness: Vec<(String, Vec<Vec<E>>)>, data_hash: &[u8; 32]) -> verifier::Proof {
    StableProver::init();
    let (proof, _) =
        StableProver::prove(program, &witness, hash_to_scalars(data_hash), RATE).expect("the program proves");
    proof
}

/// Publishes `keccak256` of a hinted 64-byte preimage: it accepts exactly the hashes of preimages.
const PREIMAGE: &str = "\
def main():
    pre = StackBuf(4)
    hint_witness(pre, \"pre\")
    c = StackBuf(2)
    keccak(pre[0:2], pre[2:4], c)
    p = 1
    p[1] = c[0]
    p[GEN] = c[1]
    return
";

/// Accepts any canonical public input, after a run of arithmetic that brings it near the cap.
fn wide_source() -> String {
    let mut src = String::from("def main():\n    h = StackBuf(2)\n    hint_witness(h, \"pi\")\n    acc = h[0]\n");
    for _ in 0..WIDE_STEPS {
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
    let program = Program::from(compile(&parse(src).expect("parse")));
    let table = program.stacked_bytecode().to_vec();
    let vk = generic_verification_key(&table).expect("within the cap");
    Generic { program, table, vk }
}

fn preimage_program() -> &'static Generic {
    static P: OnceLock<Generic> = OnceLock::new();
    P.get_or_init(|| generic(PREIMAGE))
}

fn wide_program() -> &'static Generic {
    static P: OnceLock<Generic> = OnceLock::new();
    P.get_or_init(|| generic(&wide_source()))
}

/// A preimage-check dependency: `data_hash = keccak256(seed repeated 64 times)`.
fn preimage_dep(seed: u8) -> RawGeneric {
    let g = preimage_program();
    let pre = [seed; 64];
    let data_hash = keccak256::hash(&pre);
    let pre_cells: Vec<E> = pre
        .chunks(16)
        .map(|c| to_scalar(&super::cells::pack_16_bytes(c)))
        .collect();
    let proof = prove(&g.program, vec![("pre".to_string(), vec![pre_cells])], &data_hash);
    (data_hash, g.vk, generic_witness(&g.table, &proof).expect("a witness"))
}

/// A dependency on the near-cap program, for any `data_hash`.
fn wide_dep(data_hash: [u8; 32]) -> RawGeneric {
    let g = wide_program();
    let pi: [E; 2] = hash_to_scalars(&data_hash);
    let proof = prove(&g.program, vec![("pi".to_string(), vec![pi.to_vec()])], &data_hash);
    (data_hash, g.vk, generic_witness(&g.table, &proof).expect("a witness"))
}

fn sphincs(n: usize) -> Vec<LeanSphincsSigner> {
    get_lean_sphincs_signers::<StableProver>(n)
}

fn claim(raw: &RawGeneric) -> GenericClaim {
    (raw.0, raw.1)
}

/// The D6 digest, from raw bytes: each list's 64-byte entries hashed, then combined.
fn independent_deps_hash(sphincs: &[LeanSphincsClaim], generic: &[GenericClaim]) -> [u8; 32] {
    let s_bytes: Vec<u8> = sphincs
        .iter()
        .flat_map(|(m, pk)| m.iter().chain(&pk.to_bytes()).copied().collect::<Vec<_>>())
        .collect();
    let s = keccak256::hash(&s_bytes);
    if generic.is_empty() {
        return s;
    }
    let g_bytes: Vec<u8> = generic.iter().flat_map(|(d, vk)| d.iter().chain(vk).copied()).collect();
    let g = keccak256::hash(&g_bytes);
    keccak256::hash(&[s.as_slice(), &g, b"eip8288/leanstark-deps\0\0\0\0\0\0\0\0\0\0"].concat())
}

/// A proof verifies as an aggregate and under its digest alone.
fn check((claims, proof): &Node) {
    assert!(proof.verify(claims), "verifies");
    let hash = deps_hash(&claims.lean_sphincs, &claims.generic);
    assert_eq!(hash, independent_deps_hash(&claims.lean_sphincs, &claims.generic));
    if claims.da_commitment.is_none() {
        assert!(verify_deps_hash(&hash, &proof.to_bytes()), "verifies under its digest");
    }
}

#[test]
fn programs_have_the_intended_sizes() {
    assert!(preimage_program().program.prog.len() <= 1 << 6);
    let wide = wide_program().program.prog.len();
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
    let dep = preimage_dep(2);
    let proof = aggregate(&[], vec![dep.clone()], vec![], None).expect("proves");
    assert_eq!(proof.0.generic, vec![claim(&dep)]);
    check(&proof);
}

#[test]
fn mixed_leaf_with_a_near_cap_program() {
    let deps = vec![preimage_dep(3), wide_dep([9; 32])];
    let proof = aggregate(&[], deps, sphincs(2), None).expect("proves");
    assert_eq!((proof.0.generic.len(), proof.0.lean_sphincs.len()), (2, 2));
    check(&proof);
}

#[test]
fn pure_lean_sphincs_digest_is_unchanged() {
    let claims: Vec<LeanSphincsClaim> = sphincs(3).iter().map(|(pk, m, _)| (*m, *pk)).collect();
    assert_eq!(deps_hash(&claims, &[]), independent_deps_hash(&claims, &[]));
    let entries: Vec<u8> = claims
        .iter()
        .flat_map(|(m, pk)| [&m[..], &pk.to_bytes()].concat())
        .collect();
    assert_eq!(deps_hash(&claims, &[]), keccak256::hash(&entries));
}

/// The same 64 bytes as a leanSPHINCS and as a leanSTARK claim are two dependencies: the digests differ,
/// and each list's claims are covered only by its own scheme.
#[test]
fn the_same_bytes_under_both_schemes_are_distinct() {
    let (message, pk) = sphincs(1).iter().map(|(pk, m, _)| (*m, *pk)).next().unwrap();
    let key = pk.to_bytes();
    let as_sphincs = deps_hash(&[(message, pk)], &[]);
    let as_generic = deps_hash(&[], &[(message, key)]);
    let both = deps_hash(&[(message, pk)], &[(message, key)]);
    assert!(as_sphincs != as_generic && as_sphincs != both && as_generic != both);
}

#[test]
fn recursion_mixes_schemes_dedups_and_discards() {
    let (a, b) = (preimage_dep(4), preimage_dep(5));
    let signers = sphincs(2);
    // A child with both lists, and a generic-only child sharing one of its generic claims.
    let mixed = aggregate(&[], vec![a.clone(), b.clone()], signers.clone(), None).expect("mixed leaf");
    let generic_leaf = aggregate(&[], vec![a.clone()], vec![], None).expect("generic leaf");
    let sphincs_leaf = aggregate(&[], vec![], signers[..1].to_vec(), None).expect("sphincs leaf");
    let merged = aggregate(
        &[mixed.clone(), generic_leaf.clone(), sphincs_leaf],
        vec![],
        vec![],
        None,
    )
    .expect("merges");
    let mut want = vec![claim(&a), claim(&b)];
    want.sort();
    assert_eq!(merged.0.generic, want, "the shared claim is published once");
    assert_eq!(merged.0.lean_sphincs.len(), 2);
    check(&merged);
    // Discard b: a node may publish less than its children cover.
    let declare = AggregateClaims {
        generic: vec![claim(&a)],
        lean_sphincs: mixed.0.lean_sphincs.clone(),
        da_commitment: None,
    };
    let discarded = aggregate(&[mixed, generic_leaf], vec![], vec![], Some(&declare)).expect("discards");
    assert_eq!(discarded.0, declare);
    check(&discarded);
    // A generic leaf merged with a raw generic dependency at the same node.
    let c = preimage_dep(6);
    let raw_and_child = aggregate(&[discarded], vec![c.clone()], vec![], None).expect("raw and child");
    assert!(raw_and_child.0.generic.contains(&claim(&c)));
    check(&raw_and_child);
}

#[test]
fn raw_proofs_over_the_cap_are_refused() {
    let deps: Vec<RawGeneric> = (0..=MAX_GENERIC_DEPENDENCIES as u8)
        .map(|i| preimage_dep(100 + i))
        .collect();
    assert_eq!(
        aggregate(&[], deps.clone(), vec![], None).err(),
        Some(AggregateError::InvalidInput(
            "more than MAX_GENERIC_DEPENDENCIES raw leanSTARK proofs"
        ))
    );
    // The guest refuses them too.
    ALLOW_MANY_GENERIC.with(|allow| allow.set(true));
    let result = aggregate(&[], deps, vec![], None);
    ALLOW_MANY_GENERIC.with(|allow| allow.set(false));
    assert_eq!(result.err(), Some(AggregateError::ProvingFailed));
}

/// The raw cap bounds one node's proofs, not the lists it carries: children whose union exceeds it merge, and the
/// merge is carried further.
#[test]
fn merges_carry_more_generic_claims_than_one_node_verifies() {
    let full: Vec<RawGeneric> = (0..MAX_GENERIC_DEPENDENCIES as u8)
        .map(|i| preimage_dep(140 + i))
        .collect();
    let (extra, more) = (preimage_dep(170), preimage_dep(171));
    let full_leaf = aggregate(&[], full.clone(), vec![], None).expect("the most raw proofs a node takes");
    let extra_leaf = aggregate(&[], vec![extra.clone()], vec![], None).expect("proves");
    let merged = aggregate(&[full_leaf, extra_leaf], vec![], vec![], None).expect("merges");
    let mut want: Vec<GenericClaim> = full.iter().chain([&extra]).map(claim).collect();
    want.sort();
    assert_eq!(merged.0.generic, want);
    check(&merged);
    let parent = aggregate(&[merged], vec![more.clone()], sphincs(1), None).expect("carries the merge");
    want.push(claim(&more));
    want.sort();
    assert_eq!(parent.0.generic, want);
    check(&parent);
}

#[test]
fn an_invalid_witness_is_refused_natively() {
    let (data_hash, vk, witness) = preimage_dep(8);
    let mut other = data_hash;
    other[5] ^= 1;
    for dep in [
        (other, vk, witness.clone()),
        (data_hash, [7; 32], witness.clone()),
        (data_hash, vk, witness[..40].to_vec()),
    ] {
        assert_eq!(
            aggregate(&[], vec![dep], vec![], None).err(),
            Some(AggregateError::InvalidSignature)
        );
    }
}

fn refused_by_the_guest(name: &str, result: Result<Node, AggregateError>) {
    assert_eq!(result.err(), Some(AggregateError::ProvingFailed), "{name}");
}

/// False claims and witnesses the host's native check refuses, handed to the guest with an honest
/// proof's sub-proof hints: every run must fail.
#[test]
fn the_guest_refuses_false_generic_claims() {
    let (data_hash, vk, witness) = preimage_dep(9);
    let signer = sphincs(1);
    let (message, pk) = (signer[0].1, signer[0].0);
    let sphincs_bytes = pk.to_bytes();
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
    let other = generic(&PREIMAGE.replace("keccak(pre[0:2], pre[2:4], c)", "keccak(pre[2:4], pre[0:2], c)"));
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
    super::hints::HONEST_GENERIC.with(|h| *h.borrow_mut() = Some((data_hash, witness.clone())));
    // The honest dependency itself proves under the switch: only the false ones below must fail.
    aggregate(&[], vec![(data_hash, vk, witness.clone())], vec![], None).expect("the honest claim proves");
    for (name, dep) in cases {
        refused_by_the_guest(name, aggregate(&[], vec![dep], vec![], None));
    }
    super::hints::HONEST_GENERIC.with(|h| *h.borrow_mut() = None);
}

/// A leanSTARK claim's bytes presented as a leanSPHINCS claim have no signature: the host refuses it.
#[test]
fn a_generic_claim_is_no_lean_sphincs_claim() {
    let (data_hash, vk, _) = preimage_dep(10);
    let mut signer = sphincs(1).remove(0);
    signer.0 = LeanSphincsPublicKey::from_bytes(&vk);
    signer.1 = data_hash;
    assert_eq!(
        aggregate(&[], vec![], vec![signer], None).err(),
        Some(AggregateError::InvalidSignature)
    );
}

/// Hints edited after the host built them: every run must fail.
#[test]
fn forged_generic_hints_are_rejected() {
    let dep = preimage_dep(11);
    // Where the proof's stream carries the bytecode value.
    let parsed = super::generic::parse_witness(&dep.2).unwrap();
    let summary = super::generic::check(&dep.0, &dep.1, &parsed).unwrap();
    let value = verifier::Bytecode::new(&parsed.table)
        .unwrap()
        .evaluate(&summary.bytecode_point)
        .unwrap();
    let value_at = parsed
        .proof
        .stream
        .iter()
        .position(|x| *x == value)
        .expect("the value rides the stream");
    let flip = |hints: &mut Hints, name: &str, at: usize| {
        let entry = hints.entry_mut(name, 0);
        entry[at] += F128::ONE;
    };
    let forgeries: Vec<(&str, Box<dyn Fn(&mut Hints)>)> = vec![
        ("tampered proof scalar", Box::new(move |h| flip(h, "stream", 40))),
        (
            "kgen above the cap",
            Box::new(|h| *h.entry_mut("gen_kbc", 0) = vec![count(MAX_GENERIC_BYTECODE_LOG + 1)]),
        ),
        // The generic program's bytecode claim is settled in the guest: a false value is not deferred.
        (
            "smuggled bytecode value",
            Box::new(move |h| flip(h, "stream", value_at)),
        ),
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
        refused_by_the_guest(name, aggregate(&[], vec![dep.clone()], vec![], None));
    }
}
