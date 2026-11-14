// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

//! Proves a batch leaf of N claims (`batch_leaves [n]`, 1 to 16, default 4) with the `batch.py` template, then
//! aggregates it through the native aggregation input into a `stark_proof` over its N ethereum/EIPs#12664 leanSTARK
//! dependencies. The template's unrolled digest keeps it to 16 claims within the instruction
//! bound; a looping digest reaches the guest's 256.
//! Signature leaves (ML-DSA, Falcon, SLH-DSA, ...) replace the template's hinted claims with verified ones.

use fiat_shamir::merkle::hash_to_scalars;
use leanvm_core::cpu::{bytecode_table, prove};
use nethermind_lean::{batch_hash, final_statement, prove_aggregate};
use rec_aggregation::{
    BATCH_DOMAIN, Guest, LEAN_STARK_SCHEME, generic_verification_key, generic_witness,
    verify_batch_leaf, verify_deps_hash,
};

/// The most claims the template takes.
const MAX_CLAIMS: usize = 16;
use std::collections::BTreeMap;

fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .map_or(4, |n| n.parse().expect("claim count"));
    assert!((1..=MAX_CLAIMS).contains(&n), "1 to {MAX_CLAIMS} claims");
    let replacements = BTreeMap::from([
        ("MAX_CLAIMS_PLACEHOLDER".to_string(), MAX_CLAIMS.to_string()),
        (
            "BATCH_DOMAIN_PLACEHOLDER".to_string(),
            u128::from_le_bytes(BATCH_DOMAIN).to_string(),
        ),
    ]);
    let source = lean_compiler::parse_with_replacements(include_str!("batch.py"), &replacements)
        .expect("parses");
    let mut program = lean_compiler::compile(&source).committed();

    // A leaf's claims strictly increase: the aggregation guest rejects any other order.
    let mut claims: Vec<[u8; 32]> = (0..n as u64)
        .map(|i| nethermind_lean::keccak(&i.to_le_bytes()))
        .collect();
    claims.sort();
    let mut cells: Vec<_> = claims.iter().flat_map(hash_to_scalars).collect();
    cells.resize(2 * MAX_CLAIMS, Default::default());
    program.set_witness(
        "last_claim",
        vec![vec![primitives::field::g_pow(n - 1).into()]],
    );
    program.set_witness("claims", vec![cells]);
    let statement = batch_hash(&claims);
    let (proof, _) = prove(&program, hash_to_scalars(&statement), 1).expect("the leaf proves");
    let table: Vec<u64> = bytecode_table(program.prog())
        .iter()
        .map(|word| word.0)
        .collect();
    let key = generic_verification_key(&table).expect("within the instruction bound");
    let witness = generic_witness(&table, &proof).expect("a witness");
    assert!(verify_batch_leaf(Guest::Batched, &claims, &key, &witness));
    println!(
        "leaf of {n} claims: key {}, witness {} B",
        hex(&key),
        witness.len()
    );

    let dependencies: Vec<[u8; 96]> = claims
        .iter()
        .map(|claim| {
            let mut dependency = [0; 96];
            dependency[31] = LEAN_STARK_SCHEME;
            dependency[32..64].copy_from_slice(claim);
            dependency[64..].copy_from_slice(&key);
            dependency
        })
        .collect();
    // The native aggregation input: no direct witnesses, children or discards, then one leaf with the dependencies
    // it establishes.
    let number = |n: usize| (n as u32).to_le_bytes();
    let mut input = [number(0), number(0), number(0), number(1)].concat();
    input.extend(key);
    input.extend(number(n));
    input.extend(claims.iter().flatten());
    input.extend(number(dependencies.len()));
    input.extend(dependencies.iter().flatten());
    input.extend(number(witness.len()));
    input.extend(&witness);
    // A list holding batch claims is proved finalized, over its canonical (sorted) order.
    dependencies.sort();
    let deps_hash = final_statement(&dependencies);
    let stark_proof =
        prove_aggregate(Guest::Batched, &deps_hash, &input).expect("the leaf aggregates");
    verify_deps_hash(Guest::Batched, &deps_hash, &stark_proof).expect("the aggregate verifies");
    println!(
        "stark_proof over {n} claims: {} B, deps_hash {}",
        stark_proof.len(),
        hex(&deps_hash)
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
