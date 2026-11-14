// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

//! SLH-DSA-SHAKE-128s (FIPS 205 pure, empty context) over 32-byte messages: `slhdsa.py`. The host recomputes every
//! intermediate the program checks, as a verifier would, and pushes the hints in its execution order.

use std::collections::BTreeMap;

use fips205::slh_dsa_shake_128s;
use fips205::traits::{KeyGen, SerDes, Signer, Verifier};
use primitives::field::F192;
use sha3::digest::{ExtendableOutput, Update, XofReader};

use crate::common::{Claim, Hints, Scheme, cell, cells, count};

const GUEST: &str = include_str!("slhdsa.py");
/// The claim's domain: one cell.
pub const CLAIM_TAG: &[u8; 16] = b"EIP8288:slh128s1";
const N: usize = 16;
const K: usize = 14;
const A: usize = 12;
const D: usize = 7;
const HP: usize = 9;
const LEN: usize = 35;

pub struct SlhDsa128s;

#[derive(Clone)]
pub struct Item {
    pub pk: [u8; 32],
    pub msg: [u8; 32],
    pub sig: Vec<u8>,
    /// The key's index, for signing another message under it.
    key: usize,
}

fn signed(key: usize, msg: [u8; 32]) -> Item {
    let seed = |tag: u8| {
        let mut s = [tag; N];
        s[..8].copy_from_slice(&(key as u64).to_le_bytes());
        s
    };
    let (pk, sk) = slh_dsa_shake_128s::KG::keygen_with_seeds(&seed(1), &seed(2), &seed(3));
    let sig = sk.try_sign(&msg, &[], false).expect("signs");
    Item {
        pk: pk.into_bytes(),
        msg,
        sig: sig.to_vec(),
        key,
    }
}

fn message(i: usize) -> [u8; 32] {
    nethermind_lean::keccak(&(i as u64).to_le_bytes())
}

fn shake(parts: &[&[u8]], out: &mut [u8]) {
    let mut h = sha3::Shake256::default();
    for p in parts {
        h.update(p);
    }
    h.finalize_xof().read(out);
}

fn adrs(layer: u32, tree: u64, typ: u32, w1: u32, w2: u32, w3: u32) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[0..4].copy_from_slice(&layer.to_be_bytes());
    a[8..16].copy_from_slice(&tree.to_be_bytes());
    a[16..20].copy_from_slice(&typ.to_be_bytes());
    a[20..24].copy_from_slice(&w1.to_be_bytes());
    a[24..28].copy_from_slice(&w2.to_be_bytes());
    a[28..32].copy_from_slice(&w3.to_be_bytes());
    a
}

fn th(seed: &[u8], ad: &[u8; 32], msg: &[&[u8]]) -> [u8; N] {
    let mut parts: Vec<&[u8]> = vec![seed, ad];
    parts.extend_from_slice(msg);
    let mut out = [0u8; N];
    shake(&parts, &mut out);
    out
}

/// The bits of `bytes`, most significant first in each byte, as the program's `sl_bits` entries take them.
fn stream_bits(bytes: &[u8]) -> Vec<F192> {
    bytes
        .iter()
        .flat_map(|&b| (0..8).rev().map(move |k| F192::new(u64::from((b >> k) & 1), 0, 0)))
        .collect()
}

fn ordered<'a>(node: &'a [u8], sib: &'a [u8], right: bool) -> [&'a [u8]; 2] {
    if right { [sib, node] } else { [node, sib] }
}

/// Verifies `item` as the program does, pushing its hints; returns the recomputed hypertree root.
fn recompute(item: &Item, hints: &mut Hints) -> [u8; N] {
    let (seed, root) = (&item.pk[..N], &item.pk[N..]);
    let sig = &item.sig;
    let r = &sig[..N];
    hints.push("sl_r", vec![cell(r)]);
    hints.push("sl_pk", vec![cell(seed), cell(root)]);
    hints.push("sl_m0", vec![cell(&item.msg[..16])]);
    hints.push("sl_m1", vec![cell(&item.msg[16..])]);
    hints.push("sl_bits", stream_bits(&item.msg[..16]));
    hints.push("sl_bits", stream_bits(&item.msg[16..]));
    let mut digest = [0u8; 32];
    shake(&[r, seed, root, &[0, 0], &item.msg], &mut digest);
    hints.push("sl_bits", stream_bits(&digest[..16]));
    hints.push("sl_bits", stream_bits(&digest[16..]));
    let be = |b: &[u8]| b.iter().fold(0u64, |acc, &x| acc << 8 | x as u64);
    let idx_tree = be(&digest[21..28]) & ((1 << 54) - 1);
    let idx_leaf = (be(&digest[28..30]) & ((1 << HP) - 1)) as u32;
    let md_bit = |s: usize| (digest[s / 8] >> (7 - s % 8)) & 1;

    let fors = &sig[N..N + K * (A + 1) * N];
    let mut roots = Vec::new();
    for i in 0..K {
        let idx = (0..A).fold(0u32, |acc, b| acc << 1 | md_bit(A * i + b) as u32);
        let t = &fors[i * (A + 1) * N..(i + 1) * (A + 1) * N];
        hints.push("sl_fors", cells(t));
        hints.push("sl_ibits", (0..4).map(|b| F192::new(((i >> b) & 1) as u64, 0, 0)).collect());
        let base = (i as u32) << A;
        let mut node = th(seed, &adrs(0, idx_tree, 3, idx_leaf, 0, base + idx), &[&t[..N]]);
        for z in 1..=A {
            let ad = adrs(0, idx_tree, 3, idx_leaf, z as u32, (base + idx) >> z);
            node = th(seed, &ad, &ordered(&node, &t[z * N..(z + 1) * N], (idx >> (z - 1)) & 1 == 1));
        }
        roots.extend_from_slice(&node);
    }
    let mut signed = th(seed, &adrs(0, idx_tree, 4, idx_leaf, 0, 0), &[&roots]);

    let ht = &sig[N + K * (A + 1) * N..];
    let (mut tree, mut leaf) = (idx_tree, idx_leaf);
    for j in 0..D {
        let layer = &ht[j * (LEN + HP) * N..(j + 1) * (LEN + HP) * N];
        hints.push("sl_bits", stream_bits(&signed));
        let mut digits: Vec<u32> = signed.iter().flat_map(|&b| [(b >> 4) as u32, (b & 15) as u32]).collect();
        let csum: u32 = digits.iter().map(|d| 15 - d).sum();
        digits.extend([(csum >> 8) & 15, (csum >> 4) & 15, csum & 15]);
        hints.push("sl_csum", digits[32..].iter().map(|&d| count(d as usize)).collect());
        hints.push("sl_wots", cells(&layer[..LEN * N]));
        let mut tips = Vec::new();
        for (c, &d) in digits.iter().enumerate() {
            let mut v: [u8; N] = layer[c * N..(c + 1) * N].try_into().unwrap();
            for s in d..15 {
                v = th(seed, &adrs(j as u32, tree, 0, leaf, c as u32, s), &[&v]);
            }
            tips.extend_from_slice(&v);
        }
        let mut node = th(seed, &adrs(j as u32, tree, 1, leaf, 0, 0), &[&tips]);
        let auth = &layer[LEN * N..];
        hints.push("sl_auth", cells(auth));
        for z in 1..=HP {
            let ad = adrs(j as u32, tree, 2, 0, z as u32, leaf >> z);
            node = th(seed, &ad, &ordered(&node, &auth[(z - 1) * N..z * N], (leaf >> (z - 1)) & 1 == 1));
        }
        signed = node;
        leaf = (tree & ((1 << HP) - 1)) as u32;
        tree >>= HP;
    }
    signed
}

impl Scheme for SlhDsa128s {
    type Item = Item;
    const NAME: &'static str = "slhdsa128s";

    fn source() -> String {
        GUEST.into()
    }

    fn placeholders(ps: &mut BTreeMap<String, String>) {
        ps.insert("CLAIM_TAG".into(), u128::from_le_bytes(*CLAIM_TAG).to_string());
    }

    fn items(n: usize) -> Vec<Item> {
        (0..n).map(|i| signed(i, message(i))).collect()
    }

    fn claim(item: &Item) -> Claim {
        nethermind_lean::keccak(&[&CLAIM_TAG[..], &item.pk, &item.msg].concat())
    }

    fn push_hints(item: &Item, hints: &mut Hints) {
        recompute(item, hints);
    }

    fn forge(item: &Item) -> Item {
        let mut other = item.msg;
        other[0] ^= 1;
        Item {
            sig: signed(item.key, other).sig,
            ..item.clone()
        }
    }

    fn reference_check() {
        for item in Self::items(3) {
            let pk = slh_dsa_shake_128s::PublicKey::try_from_bytes(&item.pk).expect("a key");
            let sig: [u8; slh_dsa_shake_128s::SIG_LEN] = item.sig.clone().try_into().unwrap();
            assert!(pk.verify(&item.msg, &sig, &[]));
            assert_eq!(recompute(&item, &mut Hints::default()), item.pk[N..]);
            let forged = Self::forge(&item);
            let sig: [u8; slh_dsa_shake_128s::SIG_LEN] = forged.sig.clone().try_into().unwrap();
            assert!(!pk.verify(&forged.msg, &sig, &[]));
            assert_ne!(recompute(&forged, &mut Hints::default()), forged.pk[N..]);
            let mut flipped = item.clone();
            flipped.sig[N + 5 * N] ^= 1;
            assert_ne!(recompute(&flipped, &mut Hints::default()), flipped.pk[N..]);
        }
    }
}
