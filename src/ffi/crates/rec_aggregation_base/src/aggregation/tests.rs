use super::cells::count;
use super::deferred::{DeferredBytecodeClaim, bytecode_sums, bytecode_value, bytecode_vars, stacked_bytecode};
use super::error::{AggregateVerifyError, AggregationError};
use super::guest::{compile_guest, unified_guest};
use super::hints::{FORGE, Forgery, Hints};
use super::node::aggregate;
use super::placeholders::placeholder_map;
use super::proof::{EthereumClaims, EthereumProof, decode, encode};
use super::statement::{CLAIM_GROUP, claim_list_digest, list_split};
use lean_compiler::{compile, parse_with_replacements};
use lean_da::BLOB_SYMBOLS;
use leanvm_core::cpu::verify;
use primitives::field::{F64, F128, g_pow};
use primitives::multilinear::mle_eval_par;
use rand::SeedableRng;
use rand::rngs::StdRng;
use lean_sphincs::{LeanSphincsPublicKey, LeanSphincsSignature};
use lean_sphincs;

use crate::signers_cache::get_lean_sphincs_signers;

const SMALL_LEAF_SIZE: usize = 6;
const LOG_INV_RATE: usize = leanvm_core::pcs::TEST_LOG_INV_RATE;

#[test]
fn the_wire_layout_is_pinned() {
    let le = u64::to_le_bytes;
    let (point, proof) = (vec![F128::new(1, 2), F128::new(4, 5)], vec![9, 8, 7]);
    let bytes = encode(&point, &proof);
    assert_eq!(bytes, [&le(2)[..], &le(1), &le(2), &le(4), &le(5), &proof].concat());
    assert_eq!(decode(&bytes), Some((point, &proof[..])));
    // A count beyond the input, or beyond any input, fails whatever it claims.
    assert_eq!(decode(&[&le(3)[..], &bytes[8..]].concat()), None);
    assert_eq!(decode(&le(u64::MAX)), None);
}

/// The guest's `AGGREGATED_VK`: any change to the guest, its placeholders or the proof system changes it, and a chain
/// pins it, so a change here is a deliberate one.
#[test]
fn aggregated_vk_is_pinned() {
    let hex = super::proof::aggregated_vk().iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(hex, "b3a5a9b6773f76829132e11fa436d24bdac562014d2821396657fdf5dd081084");
}

/// The guest compiles to one program, always.
///
/// `unified_guest` finds a fixed point by compiling repeatedly and comparing
/// the result's log size, so a compiler that read a hash seed would not just
/// produce two incompatible transcripts, it could fail to converge at all.
/// The small programs in `lean_compiler`'s `determinism` suite pin the
/// digests; this pins the one program large enough to hit every path that
/// walks a map. A fixed `kbc` is enough: reproducibility does not depend on
/// the size being the fixed point.
#[test]
fn guest_compiles_reproducibly() {
    let (one, two) = (compile_guest(20), compile_guest(20));
    assert_eq!(
        format!("{:?}", one.prog()),
        format!("{:?}", two.prog()),
        "two compilations of the guest produced different bytecode, \
             so the compiler is reading a hash seed"
    );
}

fn prove_leaf(signers: &[RawSphincs]) -> EthereumProof {
    aggregate(&[], vec![], signers.to_vec(), &[], None, LOG_INV_RATE).expect("leaf aggregates")
}

type RawSphincs = (LeanSphincsPublicKey, lean_sphincs::Message, LeanSphincsSignature);

fn prove_lean_sphincs_leaf(signers: &[RawSphincs]) -> EthereumProof {
    aggregate(&[], vec![], signers.to_vec(), &[], None, LOG_INV_RATE).expect("leaf aggregates")
}

#[test]
fn aggregate_one_lean_sphincs_signer() {
    let aggregate = prove_lean_sphincs_leaf(&get_lean_sphincs_signers(1));
    aggregate.verify().expect("verifies");
    assert!(aggregate.claims.generic.is_empty());
    assert_eq!(aggregate.claims.lean_sphincs.len(), 1);
}

/// A leanSPHINCS signature's digest and openings are bound in-circuit: a node whose
/// hints put the digest's unused bytes off by one, order a FORS node and its sibling
/// the other way, or give a layer another counter fails the guest's run.
#[test]
fn forged_lean_sphincs_hints_are_rejected() {
    let signers = get_lean_sphincs_signers(1);
    let bump = |name: &'static str, i: usize| -> (&'static str, Forgery) {
        (name, Box::new(move |hints: &mut Hints| hints.entry_mut(name, i)[0] += F128::ONE))
    };
    let digit = |i: usize| -> Forgery { Box::new(move |hints: &mut Hints| hints.entry_mut("sp_digits", i)[0] *= count(1)) };
    let forgeries: Vec<(&str, Forgery)> = vec![
        bump("sp_rand", 0),
        bump("sp_fors_secrets", 0),
        bump("sp_fors_paths", 0),
        bump("sp_chain_starts", 0),
        bump("sp_siblings", 0),
        ("message digit", digit(0)),
        ("checksum digit", digit(lean_sphincs::LEN1)),
    ];
    for (name, forgery) in forgeries {
        FORGE.with(|forge| *forge.borrow_mut() = Some(forgery));
        let result = aggregate(&[], vec![], signers.clone(), &[], None, LOG_INV_RATE);
        assert!(matches!(result, Err(AggregationError::ProofError(_))), "{name}: {:?}", result.map(|_| ()));
    }
}

/// The repeat the statement allows: one pubkey signing two messages is two
/// claims, ordered bytewise by the 64-byte entry (message first), each needing its own signature. Generated
/// here rather than cached, the cache holding one message per pubkey.
#[test]
fn aggregate_one_key_two_messages() {
    let (secret_key, public_key) = lean_sphincs::key_gen_from_seed([77; lean_sphincs::SEED_LEN]);
    let raw: Vec<RawSphincs> = [3u8, 9]
        .into_iter()
        .map(|tag| {
            let signed: lean_sphincs::Message = std::array::from_fn(|i| tag.wrapping_mul(i as u8 + 1));
            let signature = lean_sphincs::sign(&secret_key, &signed).expect("signs");
            (public_key, signed, signature)
        })
        .collect();
    let aggregate = prove_lean_sphincs_leaf(&raw);
    aggregate.verify().expect("verifies");
    assert_eq!(aggregate.claims.lean_sphincs.len(), 2);
    let (first, second) = (aggregate.claims.lean_sphincs[0], aggregate.claims.lean_sphincs[1]);
    assert_eq!(first.1, second.1, "the same pubkey, twice");
    assert!(first.0 < second.0, "ordered by the message, the entry's first 32 bytes");
    let declare = EthereumClaims { lean_sphincs: aggregate.claims.lean_sphincs.clone(), ..Default::default() };
    assert_eq!(
        super::node::aggregate(&[], vec![], raw[..1].to_vec(), &[], Some(&declare), LOG_INV_RATE).err(),
        Some(AggregationError::NotCovered),
        "one signature covers one claim"
    );
}

#[test]
fn guest_column_selectors_match_native_eq() {
    let (helpers, _) = include_str!("../../guests/lean_ethereum.py")
        .split_once("\ndef main():")
        .unwrap();
    let source = format!(
        r#"{helpers}
def main():
    # The selector tables read whole nibbles of coordinates, zero past the stack.
    point = HeapBuf(4 * SEL_NIBBLES)
    hint_witness(point[0:MAX_STACK_LOG], "point")
    for k in unroll(MAX_STACK_LOG, 4 * SEL_NIBBLES):
        point[GEN ** k] = 0
    point1 = HeapBuf(4 * SEL_NIBBLES)
    for k in unroll(0, 4 * SEL_NIBBLES):
        point1[GEN ** k] = 1 + point[GEN ** k]
    sel_eq = selector_tables(point, point1)
    g_squares = exponent_tables()
    sel_g = g_squares * GEN ** SIZE_BITS
    offset = hint_witness("offset")
    kappa_g = hint_witness("kappa")
    weight = match(log(kappa_g), range(0, N_COLUMN_LOGS), lambda kappa: column_selector(offset, sel_eq, sel_g, kappa))
    public = GEN ** 0
    assert public[1] == weight
    return
"#
    );
    let kbc = 18;
    let guest = compile(&parse_with_replacements(&source, &placeholder_map(kbc)).unwrap());
    let run = |point: &[F128], offset: usize, kappa: usize, expected: F128| {
        let mut hints = Hints::default();
        hints.push("point", point.to_vec());
        hints.push("offset", vec![count(offset)]);
        hints.push("kappa", vec![count(kappa)]);
        let mut program = guest.clone();
        hints.install(&mut program);
        program.execute([expected, F128::ZERO])
    };
    let mut rng = StdRng::seed_from_u64(813);
    for mu in verifier::min_execution_stacked_log(kbc)..=verifier::MAX_STACKED_LOG {
        let mut point: Vec<F128> = (0..mu)
            .map(|_| {
                let (c0, c1) = rand::Rng::random(&mut rng);
                F128::new(c0, c1)
            })
            .collect();
        point.resize(verifier::MAX_STACKED_LOG, F128::ZERO);
        for kappa in 0..=mu {
            let mask = ((1usize << mu) - 1) & !((1usize << kappa) - 1);
            for offset in [0, mask, 0x0555_5555 & mask] {
                let selector: Vec<_> = (kappa..mu)
                    .map(|k| F128::from(F64(((offset >> k) & 1) as u64)))
                    .collect();
                let expected = primitives::multilinear::eq_eval(&selector, &point[kappa..mu]);
                assert!(
                    run(&point, offset, kappa, expected)
                        .unwrap()
                        .unconstrained_reads
                        .is_empty()
                );
            }
        }
    }
}

/// The right leaf holds more claims than one loop frame of its list hashes
/// ([`CLAIM_GROUP`]), so both that leaf and the parent rebuilding it run the
/// list's group loop and then a partial last group, while the left leaf's list is
/// a partial group alone.
#[test]
fn aggregate_two_to_one() {
    let big = 2 * CLAIM_GROUP + 3;
    let signers = get_lean_sphincs_signers(SMALL_LEAF_SIZE + big);
    let left = prove_leaf(&signers[..SMALL_LEAF_SIZE]);
    let right = prove_leaf(&signers[SMALL_LEAF_SIZE..]);
    let children = [left, right];
    let node = aggregate(&children, vec![], vec![], &[], None, LOG_INV_RATE).expect("node aggregates");
    node.verify().expect("node verifies");
    // `cpu::verify` accepts the same proof of the same statement.
    verify(unified_guest(), &node.vm_public_input(), &node.proof).expect("node verifies natively");
    assert_eq!(node.claims.lean_sphincs.len(), SMALL_LEAF_SIZE + big);
}

/// The root [`lean_da::BlobMatrix`] commits `rows` to.
fn da_root(rows: &[lean_da::Symbol]) -> [u8; 32] {
    lean_da::BlobMatrix::build(rows.as_chunks::<BLOB_SYMBOLS>().0).unwrap().top_root()
}

fn da_rows(n_rows: usize, seed: u64) -> Vec<lean_da::Symbol> {
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(seed);
    (0..n_rows * BLOB_SYMBOLS)
        .map(|_| rand::Rng::random(&mut rng))
        .collect()
}

/// A LeanDA payload, proven without signatures and published in the
/// statement. The node has to reach the native committer's root, and the
/// aggregate has to verify against a statement that carries it.
#[test]
fn aggregate_with_a_da_payload() {
    let rows = da_rows(3, 97);

    let node = aggregate(&[], vec![], vec![], &rows, None, LOG_INV_RATE).expect("node aggregates");
    node.verify().expect("node verifies");
    assert_eq!(node.claims.num_signature_claims(), 0);

    let commitment = da_root(&rows);
    assert_eq!(
        node.claims.da_commitment,
        Some(commitment),
        "the guest committed to something else"
    );
    // The receiver supplies the claims it expects: those verify, any others fail.
    let bytes = node.proof_bytes();
    let expected = EthereumClaims {
        da_commitment: Some(commitment),
        ..EthereumClaims::default()
    };
    EthereumProof::from_proof_bytes(&bytes, expected.clone())
        .unwrap()
        .verify()
        .unwrap();
    let other = EthereumClaims {
        da_commitment: Some([0; 32]),
        ..EthereumClaims::default()
    };
    let wrong = EthereumProof::from_proof_bytes(&bytes, other).unwrap();
    assert!(matches!(wrong.verify(), Err(AggregateVerifyError::Snark(_))));
    let claim = ([0; 32], [0; 32]);
    let unsorted = EthereumClaims {
        generic: vec![claim, claim],
        ..expected.clone()
    };
    let malformed = EthereumProof::from_proof_bytes(&bytes, unsorted);
    assert!(matches!(malformed, Err(AggregateVerifyError::MalformedSignerSet)));
    let trailing = EthereumProof::from_proof_bytes(&[&bytes[..], &[0]].concat(), expected);
    assert!(matches!(trailing, Err(AggregateVerifyError::MalformedEncoding)));
}

/// A node publishes a root it holds, and with blobs only their matrix's.
#[test]
fn invalid_da_selections_are_rejected_before_building_the_proof() {
    let select = EthereumClaims {
        da_commitment: Some([0xa5; 32]),
        ..EthereumClaims::default()
    };
    assert_eq!(
        aggregate(&[], vec![], vec![], &[], Some(&select), LOG_INV_RATE).unwrap_err(),
        AggregationError::BlobNotCovered
    );
    assert_eq!(
        aggregate(&[], vec![], vec![], &da_rows(1, 3), Some(&select), LOG_INV_RATE).unwrap_err(),
        AggregationError::BlobsUnpublished
    );
    let unpublished = EthereumClaims::default();
    assert_eq!(
        aggregate(&[], vec![], vec![], &da_rows(1, 3), Some(&unpublished), LOG_INV_RATE).unwrap_err(),
        AggregationError::BlobsUnpublished
    );
}

/// A proof carries one blob matrix. A node without blobs passes on one child's
/// root, the first's by default or the one it selects, or none; a node with blobs
/// publishes their matrix's, whatever its children hold.
#[test]
fn a_node_passes_on_one_childs_da_root() {
    let signers = get_lean_sphincs_signers(SMALL_LEAF_SIZE);
    let mut children = vec![prove_leaf(&signers)];
    for (n_rows, seed) in [(1, 509), (2, 510)] {
        let rows = da_rows(n_rows, seed);
        children.push(aggregate(&[], vec![], signers.clone(), &rows, None, LOG_INV_RATE).unwrap());
    }
    let (first, second) = (
        children[1].claims.da_commitment.unwrap(),
        children[2].claims.da_commitment.unwrap(),
    );
    assert_ne!(first, second);
    let pass_on = |selected: Option<Option<[u8; 32]>>, blobs: &[lean_da::Symbol]| {
        let declare = selected.map(|da_commitment| EthereumClaims {
            generic: vec![],
            lean_sphincs: children[0].claims.lean_sphincs.clone(),
            da_commitment,
        });
        let node = aggregate(&children, vec![], vec![], blobs, declare.as_ref(), LOG_INV_RATE).unwrap();
        node.verify().unwrap();
        node.claims.da_commitment
    };
    assert_eq!(pass_on(None, &[]), Some(first));
    assert_eq!(pass_on(Some(Some(second)), &[]), Some(second));
    assert_eq!(pass_on(Some(None), &[]), None);
    let rows = da_rows(1, 511);
    assert_eq!(pass_on(None, &rows), Some(da_root(&rows)));

    // Passed on again, one level up.
    let middle = aggregate(&children[1..], vec![], vec![], &[], None, LOG_INV_RATE).unwrap();
    let top = aggregate(&[children[0].clone(), middle], vec![], vec![], &[], None, LOG_INV_RATE).unwrap();
    top.verify().unwrap();
    assert_eq!(top.claims.da_commitment, Some(first));
}

/// The guest reads each child's root off its statement and publishes the one the
/// node picks, which must be its own with blobs: a child's root other than the one
/// its proof carries, a pick past the children, a child's root picked over the
/// node's blobs, or a membership challenge other than the root's fails the guest's run.
#[test]
fn forged_da_hints_are_rejected() {
    let signers = get_lean_sphincs_signers(SMALL_LEAF_SIZE);
    let child = aggregate(&[], vec![], signers.clone(), &da_rows(1, 7), None, LOG_INV_RATE).unwrap();
    let forgeries: [(Forgery, bool); 4] = [
        (
            Box::new(|hints: &mut Hints| hints.entry_mut("child_da", 0)[0] += F128::ONE),
            false,
        ),
        (
            Box::new(|hints: &mut Hints| hints.entry_mut("da_pick", 0)[0] *= count(2)),
            false,
        ),
        (
            Box::new(|hints: &mut Hints| hints.entry_mut("da_pick", 0)[0] = count(0)),
            true,
        ),
        (
            Box::new(|hints: &mut Hints| hints.entry_mut("da_challenge", 0)[0] += F128::ONE),
            true,
        ),
    ];
    for (forgery, with_blobs) in forgeries {
        FORGE.with(|forge| *forge.borrow_mut() = Some(forgery));
        let blobs = if with_blobs { da_rows(1, 8) } else { vec![] };
        let result = aggregate(std::slice::from_ref(&child), vec![], vec![], &blobs, None, LOG_INV_RATE);
        assert!(
            matches!(result, Err(AggregationError::ProofError(_))),
            "a forged DA hint is rejected"
        );
    }
}

/// A list hash's split is advice the guest then dispatches on, so the claim count
/// after the last group has to be bounded before the `match`: a negative
/// exponent that satisfies the product identity must fail the range check in
/// `list_split` itself, not reach the dispatch as a wild jump.
#[test]
fn list_split_rejects_a_negative_rest() {
    let (helpers, _) = include_str!("../../guests/lean_ethereum.py")
        .split_once("\ndef main():")
        .unwrap();
    let source = format!(
        r#"{helpers}
def main():
    n_g = hint_witness("n")
    bigs, body, rest = list_split(n_g)
    public = GEN ** 0
    assert public[1] == body
    assert public[GEN] == rest
    return
"#
    );
    let guest = compile(&parse_with_replacements(&source, &placeholder_map(20)).unwrap());
    let run = |body: F128, rest: F128| {
        let mut hints = Hints::default();
        hints.push("n", vec![count(6)]);
        hints.push("signers_split", vec![count(0), body, rest]);
        let mut program = guest.clone();
        hints.install(&mut program);
        program.execute([body, rest])
    };
    // Six claims: no whole group, then six.
    assert!(run(count(0), count(6)).is_ok());
    // One group and -11 claims after it: the product identity holds, the range
    // check must not.
    let negative = F128::from(g_pow(11).inv());
    let Err(err) = run(count(1), negative) else {
        panic!("a negative last-block count was accepted");
    };
    assert!(err.to_string().contains("list_split"), "rejected elsewhere: {err}");
}

/// The row count is a run-time parameter, so payloads of different heights
/// must prove against the *same* bytecode and each reach its own committer's
/// root. Powers of two and the counts between them alike: 3 pads to 4 and 5 to
/// 8, exercising two different arms of the tree dispatch and a non-empty gap.
#[test]
fn da_row_count_is_a_run_time_parameter() {
    let signers = get_lean_sphincs_signers(SMALL_LEAF_SIZE);
    for n_rows in [1usize, 3, 4, 5] {
        let rows = da_rows(n_rows, 200 + n_rows as u64);
        let node = aggregate(&[], vec![], signers.clone(), &rows, None, LOG_INV_RATE).expect("node aggregates");
        node.verify().expect("node verifies");
        let commitment = da_root(&rows);
        assert_eq!(node.claims.da_commitment, Some(commitment), "{n_rows} rows");
    }
}

/// A leaf carrying no payload publishes zeros for its root.
#[test]
fn no_payload_publishes_no_root() {
    let signers = get_lean_sphincs_signers(SMALL_LEAF_SIZE);
    let node = prove_leaf(&signers);
    assert_eq!(node.claims.da_commitment, None);
}

#[test]
fn aggregate_overlapping_signers() {
    let signers = get_lean_sphincs_signers(40);
    let left = prove_leaf(&signers[..25]);
    let right = prove_leaf(&signers[15..]);
    let node = aggregate(&[left, right], vec![], vec![], &[], None, LOG_INV_RATE).expect("node aggregates");
    node.verify().expect("node verifies");
    assert_eq!(node.claims.lean_sphincs.len(), 40);
    assert!(node.claims.lean_sphincs.windows(2).all(|w| w[0] < w[1]));
}

/// A child list walked by gaps (`child_claim_list_mono`) moves strictly forward. A
/// child may declare a claim twice, and a gap of `g^-1` would walk the copy back onto
/// the slot it just covered, with the same coverage mark, so write-once memory alone
/// would not see it: only the gap's `assert_gpow` does.
#[test]
fn a_child_walk_cannot_step_back() {
    let (helpers, _) = include_str!("../../guests/lean_ethereum.py")
        .split_once("\ndef main():")
        .unwrap();
    let source = format!(
        r#"{helpers}
def main():
    n_c = hint_witness("n")
    table = HeapBuf(GEN ** 8)
    hint_witness(table[0:8], "claims")
    cover = HeapBuf(GEN ** 2)
    d0, d1 = child_claim_list_digest(table, cover, GEN ** 3, GEN ** 2, n_c)
    public = GEN ** 0
    assert public[1] == d0
    assert public[GEN] == d1
    return
"#
    );
    let guest = compile(&parse_with_replacements(&source, &placeholder_map(20)).unwrap());
    let claim = |i: u64| [1, 2, 3, 4].map(|k| F128::new(i * 7919 + k, k));
    let table: Vec<F128> = [claim(0), claim(1)].concat();
    let run = |child: &[[F128; 4]], gaps: &[F128]| {
        let mut hints = Hints::default();
        hints.push("n", vec![count(child.len())]);
        hints.push("claims", table.clone());
        hints.push("signers_split", list_split(child.len()));
        hints.push("child_mono", vec![count(1)]);
        for &gap in gaps {
            hints.push("child_claim_gap", vec![gap]);
        }
        let mut program = guest.clone();
        hints.install(&mut program);
        program.execute(claim_list_digest(child.iter().copied()))
    };
    assert!(run(&[claim(0), claim(1)], &[count(0), count(0)]).is_ok());
    let back = F128::from(g_pow(1).inv());
    assert!(
        run(&[claim(0), claim(0)], &[count(0), back]).is_err(),
        "a walk revisited a slot"
    );
}

#[test]
#[ignore]
fn aggregate_round_trips_through_the_wire() {
    let signers = get_lean_sphincs_signers(2 * SMALL_LEAF_SIZE);
    let left = prove_leaf(&signers[..SMALL_LEAF_SIZE]);
    let right = prove_leaf(&signers[SMALL_LEAF_SIZE..]);
    // Mixed, so both published lists are non-empty.
    let node = aggregate(&[left, right],
        vec![],
        get_lean_sphincs_signers(3),
        &[],
        None,
        LOG_INV_RATE,
    )
    .expect("node");
    node.verify().expect("the honest node verifies");

    let received = EthereumProof::from_proof_bytes(&node.proof_bytes(), node.claims.clone()).expect("round trip");
    assert_eq!(
        received.proof_bytes(),
        node.proof_bytes(),
        "the wire format round-trips, recomputed claim value included"
    );
    received.verify().expect("the receiver's claims verify");
}

/// The all-zeros fast path in `DeferredBytecodeClaim::recompute` must agree with the
/// full pass it replaces, or every leaf would verify against the wrong
/// statement.
#[test]
fn leaf_claim_matches_the_general_path() {
    let leaf = DeferredBytecodeClaim::leaf();
    assert_eq!(
        leaf.bytecode_value,
        mle_eval_par(stacked_bytecode(), &leaf.bytecode_point)
    );
}

/// The scalar verifier's deferred values are the prover's, away from the leaf shortcut.
#[test]
fn scalar_deferred_claim_matches_the_prover() {
    let mut rng = StdRng::seed_from_u64(7);
    let mut point = |len: usize| -> Vec<F128> {
        let limbs = (0..len).map(|_| rand::Rng::random::<(u64, u64)>(&mut rng));
        limbs.map(|(c0, c1)| F128::new(c0, c1)).collect()
    };
    let bytecode_point = point(bytecode_vars());
    assert_eq!(
        DeferredBytecodeClaim::recompute_scalar(bytecode_point.clone()),
        DeferredBytecodeClaim::recompute(bytecode_point)
    );
}

/// Each claim's value read off its sums is the bytecode's evaluation, at a random point and a leaf's.
#[test]
fn bytecode_sums_give_the_bytecode_value() {
    let mut rng = StdRng::seed_from_u64(11);
    let limbs = (0..bytecode_vars()).map(|_| rand::Rng::random::<(u64, u64)>(&mut rng));
    let points = [
        limbs.map(|(c0, c1)| F128::new(c0, c1)).collect(),
        vec![F128::ZERO; bytecode_vars()],
    ];
    for (sums, point) in bytecode_sums(&points).iter().zip(&points) {
        assert_eq!(bytecode_value(sums, point), mle_eval_par(stacked_bytecode(), point));
    }
}

/// The same for a leanSPHINCS claim, whose witness walk is equally fallible: a
/// counter that does not encode has no witness, and that is an error rather
/// than a panic inside the prover.
#[test]
fn malformed_raw_lean_sphincs_signature_is_an_error() {
    let (public_key, signed, signature) = get_lean_sphincs_signers(1).pop().expect("one signer");
    // The bottom layer's counter follows the randomizer and the FORS openings.
    let mut bytes = signature.to_bytes();
    bytes[lean_sphincs::RANDOMIZER_LEN + lean_sphincs::K * (1 + lean_sphincs::A) * lean_sphincs::N] ^= 1;
    let signature = LeanSphincsSignature::from_bytes(&bytes);
    assert!(lean_sphincs::verify(&public_key, &signed, &signature).is_err());
    let raw = vec![(public_key, signed, signature)];
    assert_eq!(
        aggregate(&[], vec![], raw, &[], None, LOG_INV_RATE).err(),
        Some(AggregationError::MalformedRawSignature)
    );
}

/// `verify_sub` takes the inner program's bytecode log at run time: the guest's verification
/// constants are the same for every inner bytecode size, bar the final pc's baked stand-in and the
/// guest's OWN deferred-claim layout.
#[test]
fn verification_constants_do_not_depend_on_the_inner_bytecode_size() {
    let own = ["BYTECODE_LOG", "BYTECODE_VARS", "DEFER_SIZE", "STMT_PAIRS", "AGG_CHILD_PAD", "COORD_CONST"]
        .map(|k| format!("{k}_PLACEHOLDER"));
    let (a, b) = (placeholder_map(11), placeholder_map(19));
    for (key, value) in &a {
        if !own.contains(key) {
            assert_eq!(Some(value), b.get(key), "{key}");
        }
    }
    let coords = |m: &std::collections::BTreeMap<String, String>| m["COORD_CONST_PLACEHOLDER"].split(", ").map(str::to_string).collect::<Vec<_>>();
    let final_pc: usize = a["FINAL_PC_COORD_PLACEHOLDER"].parse().unwrap();
    let (ca, cb) = (coords(&a), coords(&b));
    assert!((0..ca.len()).all(|i| i == final_pc || ca[i] == cb[i]));
}
