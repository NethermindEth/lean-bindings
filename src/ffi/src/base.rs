// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

//! Guest 0: EIP-8288's recursive guest and its host exactly as the ABI 12 package 0.12.1 ships them, so a chain without batch pricing
//! keeps that package's `AGGREGATED_VK`, limits and input encoding.

use crate::{Dep, LEAN_SPHINCS, LEAN_STARK, LOG_INV_RATE, MAX_BYTES, MAX_DEPS, MAX_INPUT_BYTES};
use rec_aggregation_base::{EthereumClaims, EthereumProof, MAX_GENERIC_DEPENDENCIES};
use std::collections::{BTreeSet, HashSet};

pub fn aggregated_vk() -> [u8; 32] {
    rec_aggregation_base::aggregated_vk()
}

/// The ABI 12 limits, in `nlean_limits` order.
pub fn limits() -> [u32; 7] {
    [
        MAX_BYTES as u32,
        MAX_DEPS as u32,
        rec_aggregation_base::MAX_RECURSIONS as u32,
        (signatures::lean_sphincs::PUB_KEY_SIZE + signatures::lean_sphincs::SIG_SIZE) as u32,
        MAX_INPUT_BYTES as u32,
        MAX_GENERIC_DEPENDENCIES as u32,
        1 << rec_aggregation_base::MAX_GENERIC_BYTECODE_LOG,
    ]
}

struct Reader<'a> {
    bytes: &'a [u8],
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ()> {
        if n > self.bytes.len() {
            return Err(());
        }
        let (a, b) = self.bytes.split_at(n);
        self.bytes = b;
        Ok(a)
    }
    fn number(&mut self) -> Result<usize, ()> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().map_err(|_| ())?) as usize)
    }
    fn count(&mut self) -> Result<usize, ()> {
        let n = self.number()?;
        if n > MAX_DEPS { Err(()) } else { Ok(n) }
    }
    fn blob(&mut self) -> Result<&'a [u8], ()> {
        let n = self.number()?;
        if n > MAX_BYTES {
            return Err(());
        }
        self.take(n)
    }
    fn dep(&mut self) -> Result<Dep, ()> {
        let d: Dep = self.take(96)?.try_into().map_err(|_| ())?;
        if d[..31].iter().any(|b| *b != 0) || !matches!(d[31], LEAN_SPHINCS | LEAN_STARK) {
            return Err(());
        }
        Ok(d)
    }
    fn deps(&mut self) -> Result<Vec<Dep>, ()> {
        (0..self.count()?).map(|_| self.dep()).collect()
    }
    fn end(self) -> Result<(), ()> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(())
        }
    }
}

fn claims(deps: &[Dep]) -> EthereumClaims {
    let of = |scheme| deps.iter().filter(move |dep| dep[31] == scheme);
    EthereumClaims {
        lean_sphincs: of(LEAN_SPHINCS)
            .map(|dep| (crate::data(dep), crate::public_key(&crate::key(dep))))
            .collect(),
        generic: of(LEAN_STARK)
            .map(|dep| (crate::data(dep), crate::key(dep)))
            .collect(),
        ..Default::default()
    }
}
/// EIP-8288 `get_deps_hash` as the ABI 12 guest commits to it.
pub fn commitment(ds: &[Dep]) -> [u8; 32] {
    let claims = claims(ds);
    rec_aggregation_base::deps_hash(&claims.lean_sphincs, &claims.generic)
}
fn generic_count(ds: &[Dep]) -> usize {
    ds.iter().filter(|dep| dep[31] == LEAN_STARK).count()
}
fn canonical(ds: Vec<Dep>) -> Vec<Dep> {
    ds.into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
fn verify_witness(dep: &Dep, witness: &[u8]) -> bool {
    if dep[31] == LEAN_STARK {
        rec_aggregation_base::verify_generic(&crate::data(dep), &crate::key(dep), witness)
    } else {
        crate::verify_sphincs(&crate::data(dep), &crate::key(dep), witness)
    }
}

pub fn verify_aggregate(hash: &[u8; 32], proof: &[u8]) -> Result<(), ()> {
    if proof.is_empty() || proof.len() > MAX_BYTES {
        return Err(());
    }
    rec_aggregation_base::verify_deps_hash(hash, proof).map_err(|_| ())
}

fn decode_child(deps: &[Dep], proof: &[u8]) -> Result<EthereumProof, ()> {
    if proof.is_empty() || proof.len() > MAX_BYTES {
        return Err(());
    }
    let proof = EthereumProof::from_proof_bytes(proof, claims(deps)).map_err(|_| ())?;
    proof.verify().map_err(|_| ())?;
    Ok(proof)
}

/// Proves `hash` from an ABI 12 aggregation input.
pub fn prove_aggregate(hash: &[u8; 32], input: &[u8]) -> Result<Vec<u8>, ()> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(());
    }
    if input == [0; 12] {
        return if *hash == commitment(&[]) {
            Ok(vec![])
        } else {
            Err(())
        };
    }
    let _guard = crate::begin_proof();
    let mut r = Reader { bytes: input };
    let mut all = Vec::new();
    let mut raw = Vec::new();
    for _ in 0..r.count()? {
        let dep = r.dep()?;
        raw.push((dep, r.blob()?));
        all.push(dep);
    }
    let child_count = r.count()?;
    if child_count > rec_aggregation_base::MAX_RECURSIONS {
        return Err(());
    }
    let mut children = Vec::new();
    for _ in 0..child_count {
        let declared = canonical(r.deps()?);
        let proof = r.blob()?;
        if declared.is_empty() {
            if !proof.is_empty() {
                return Err(());
            }
            continue;
        }
        if generic_count(&declared) > MAX_GENERIC_DEPENDENCIES {
            return Err(());
        }
        children.push((decode_child(&declared, proof)?, proof, declared.clone()));
        all.extend(declared);
    }
    let discards: HashSet<_> = r.deps()?.into_iter().collect();
    r.end()?;
    let union: HashSet<_> = all.iter().copied().collect();
    if !discards.is_subset(&union) {
        return Err(());
    }
    let deps: Vec<_> = all
        .into_iter()
        .filter(|dep| !discards.contains(dep))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if deps.len() > MAX_DEPS
        || generic_count(&deps) > MAX_GENERIC_DEPENDENCIES
        || commitment(&deps) != *hash
    {
        return Err(());
    }
    if deps.is_empty() {
        return Ok(vec![]);
    }
    let kept: HashSet<_> = deps.iter().copied().collect();
    children.retain(|(_, _, declared)| declared.iter().any(|dep| kept.contains(dep)));
    let covered: HashSet<_> = children
        .iter()
        .flat_map(|(_, _, declared)| declared.iter().copied())
        .collect();
    // The guest checks only the witnesses it is given; one that a child covers or a discard drops is checked here,
    // so an invalid witness fails the call whether or not the proof needs it.
    let (raw, unused): (Vec<_>, Vec<_>) = raw
        .into_iter()
        .partition(|(dep, _)| kept.contains(dep) && !covered.contains(dep));
    if unused
        .iter()
        .any(|(dep, witness)| !verify_witness(dep, witness))
    {
        return Err(());
    }
    if let Some((_, bytes, _)) = children.iter().find(|(_, _, declared)| *declared == deps) {
        return Ok(bytes.to_vec());
    }
    let mut signatures = Vec::new();
    let mut generic = Vec::new();
    for (dep, witness) in raw {
        if dep[31] == LEAN_STARK {
            generic.push((crate::data(&dep), crate::key(&dep), witness.to_vec()));
        } else {
            let (pk, signature) = crate::parse_sphincs(&crate::key(&dep), witness)?;
            signatures.push((pk, crate::data(&dep), signature));
        }
    }
    let children: Vec<_> = children.into_iter().map(|(child, ..)| child).collect();
    let proof = rec_aggregation_base::aggregate(
        &children,
        generic,
        signatures,
        &[],
        Some(&claims(&deps)),
        LOG_INV_RATE,
    )
    .map_err(|_| ())?
    .proof_bytes();
    if proof.len() > MAX_BYTES {
        return Err(());
    }
    Ok(proof)
}
