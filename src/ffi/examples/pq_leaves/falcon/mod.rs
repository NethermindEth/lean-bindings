// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

//! Falcon-512 (round 3, PQClean raw-message mode) leaf: `falcon.py`. The claim is
//! `keccak256("EIP8288:fn512:v1" || M || pk)` for a 32-byte message `M` and the 897-byte encoded key.

use std::collections::BTreeMap;

use primitives::field::F192;
use primitives::hash::keccak_f;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use tide_fn_dsa::{
    CryptoRng, FN_DSA_LOGN_512, FalconProfile, KeyPairGenerator512, RngCore, RngError, SIGN_KEY_SIZE_512,
    SIGNATURE_SIZE_512, SigningKey, SigningKeyStandard, VRFY_KEY_SIZE_512, VerifyingKey, VerifyingKeyStandard,
};

use crate::common::{Claim, Hints, Scheme, cell, count, f192_literal};

const GUEST: &str = include_str!("falcon.py");
const CLAIM_TAG: &[u8; 16] = b"EIP8288:fn512:v1";
const Q: u32 = 12289;
const N: usize = 512;
const NINV: u32 = 12265;
const NORM_BOUND: u64 = 34034726;
const RATE: usize = 136;

pub struct Falcon512;

#[derive(Clone)]
pub struct FalconItem {
    pk: [u8; VRFY_KEY_SIZE_512],
    msg: [u8; 32],
    sig: Vec<u8>,
    /// The same key's signature over another message.
    other: Vec<u8>,
}

/// A SHAKE256 stream of a label and an index, as the signer's randomness.
struct Stream(sha3::Shake256Reader);

impl Stream {
    fn new(label: &[u8], i: usize) -> Self {
        let mut h = sha3::Shake256::default();
        h.update(label);
        h.update(&(i as u64).to_le_bytes());
        Self(h.finalize_xof())
    }
}

impl RngCore for Stream {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0; 4];
        self.0.read(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0; 8];
        self.0.read(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.read(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        self.0.read(dest);
        Ok(())
    }
}

impl CryptoRng for Stream {}

fn sign(sk: &[u8], msg: &[u8], i: usize, label: &[u8]) -> Vec<u8> {
    let mut sig = [0; SIGNATURE_SIZE_512];
    let len = SigningKeyStandard::decode(sk)
        .expect("key")
        .sign_falcon(&mut Stream::new(label, i), FalconProfile::PqClean, msg, &mut sig)
        .expect("signs");
    sig[..len].to_vec()
}

fn verifies(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    VerifyingKeyStandard::decode(pk).is_some_and(|k| k.verify_falcon(FalconProfile::PqClean, sig, msg))
}

fn pow(b: u32, mut e: u32) -> u32 {
    let (mut acc, mut b) = (1u64, b as u64);
    while e > 0 {
        if e & 1 == 1 {
            acc = acc * b % Q as u64;
        }
        b = b * b % Q as u64;
        e >>= 1;
    }
    acc as u32
}

/// psi^brv9(m), psi = 11^12 a primitive 1024th root of unity mod q.
fn zetas() -> Vec<u32> {
    let psi = pow(11, 12);
    (0..N).map(|m| pow(psi, (m as u32).reverse_bits() >> 23)).collect()
}

/// The guest's constant table: zetas as g-powers, the 64 stream-bit lane weights `W[s] = x^(8 (s / 8) + 7 - s % 8)`,
/// and `E[t] = g^(2^(15 - t)) + 1`.
fn table() -> Vec<F192> {
    let mut t: Vec<F192> = zetas().iter().map(|&z| count(z as usize)).collect();
    t.extend((0..64).map(|s| count(8 * (s / 8) + 7 - s % 8)));
    t.extend((0..16).map(|k| count(1 << (15 - k)) + F192::ONE));
    t
}

fn cell_bytes(f: F192) -> [u8; 16] {
    assert_eq!(f.c2, 0);
    let mut b = [0; 16];
    b[..8].copy_from_slice(&f.c0.to_le_bytes());
    b[8..].copy_from_slice(&f.c1.to_le_bytes());
    b
}

/// The keccak chain the guest binds the table with: from two zero cells, `h = keccak256(h || pair)`.
fn chain(cells: &[F192]) -> [F192; 2] {
    let mut h = [F192::ZERO; 2];
    for pair in cells.chunks(2) {
        let bytes = [h[0], h[1], pair[0], pair[1]].map(cell_bytes).concat();
        let d = nethermind_lean::keccak(&bytes);
        h = [cell(&d[..16]), cell(&d[16..])];
    }
    h
}

fn lane(l: u64) -> F192 {
    F192::new(l, 0, 0)
}

fn lanes(bytes: &[u8]) -> Vec<F192> {
    bytes
        .chunks(8)
        .map(|c| lane(u64::from_le_bytes(c.try_into().unwrap())))
        .collect()
}

fn bit(b: bool) -> F192 {
    if b { F192::ONE } else { F192::ZERO }
}

/// Bytes as a stream of bits, most significant first in each byte.
fn stream_bits(bytes: &[u8]) -> Vec<F192> {
    bytes
        .iter()
        .flat_map(|&b| (0..8).map(move |t| bit(b >> (7 - t) & 1 == 1)))
        .collect()
}

/// SHAKE256 of a one-block `msg` over Keccak-f lanes: the state after the absorbed block, then after each further
/// permutation, `blocks` in all, so state `k`'s rate is output block `k`.
fn shake256_states(msg: &[u8], blocks: usize) -> Vec<[u64; 25]> {
    assert!(msg.len() < RATE);
    let mut block = [0u8; RATE];
    block[..msg.len()].copy_from_slice(msg);
    block[msg.len()] ^= 0x1f;
    block[RATE - 1] ^= 0x80;
    let mut st = [0u64; 25];
    for (l, c) in block.chunks(8).enumerate() {
        st[l] ^= u64::from_le_bytes(c.try_into().unwrap());
    }
    (0..blocks)
        .map(|_| {
            keccak_f(&mut st);
            st
        })
        .collect()
}

fn rate_bytes(st: &[u64; 25]) -> Vec<u8> {
    st[..17].iter().flat_map(|l| l.to_le_bytes()).collect()
}

/// Host side of the guest's mod-12289 arithmetic, pushing its hints.
struct Fq<'a>(&'a mut Hints);

impl Fq<'_> {
    fn mul(&mut self, a: u32, b: u32) -> u32 {
        let x = a * b;
        self.0
            .push("fq", vec![count((x % Q) as usize), count((x / Q) as usize)]);
        x % Q
    }
    fn can(&mut self, x: u32) -> u32 {
        self.0.push("fa", vec![count((x % Q) as usize)]);
        x % Q
    }
    fn ntt(&mut self, w: &[u32]) -> Vec<u32> {
        let z = zetas();
        let mut cur = w.to_vec();
        for layer in 0..9 {
            let len = 256 >> layer;
            let mut nxt = vec![0; N];
            for b in 0..(1 << layer) {
                let start = 2 * len * b;
                for j in start..start + len {
                    let t = self.mul(z[(1 << layer) + b], cur[j + len]);
                    nxt[j] = self.can(cur[j] + t);
                    nxt[j + len] = self.can(cur[j] + Q - t);
                }
            }
            cur = nxt;
        }
        cur
    }
    /// The inverse NTT without the scaling by 512^-1.
    fn intt(&mut self, w: &[u32]) -> Vec<u32> {
        let z = zetas();
        let mut cur = w.to_vec();
        for s in 0..9 {
            let len = 1 << s;
            let mut nxt = vec![0; N];
            for b in 0..(256 >> s) {
                let start = 2 * len * b;
                for j in start..start + len {
                    nxt[j] = self.can(cur[j] + cur[j + len]);
                    let d = self.can(cur[j + len] + Q - cur[j]);
                    nxt[j + len] = self.mul(z[(512 >> s) - 1 - b], d);
                }
            }
            cur = nxt;
        }
        cur
    }
}

/// Falcon's compressed s2 (comp_decode), on a well-formed encoding.
fn decode_s2(buf: &[u8]) -> Vec<i32> {
    let (mut acc, mut acc_len, mut v) = (0u32, 0u32, 0usize);
    (0..N)
        .map(|_| {
            acc = (acc << 8) | buf[v] as u32;
            v += 1;
            let b = acc >> acc_len;
            let (s, mut m) = (b & 128, (b & 127) as i32);
            loop {
                if acc_len == 0 {
                    acc = (acc << 8) | buf[v] as u32;
                    v += 1;
                    acc_len = 8;
                }
                acc_len -= 1;
                if (acc >> acc_len) & 1 != 0 {
                    break;
                }
                m += 128;
            }
            if s != 0 { -m } else { m }
        })
        .collect()
}

fn public_h(pk: &[u8]) -> Vec<u32> {
    let mut h = Vec::with_capacity(N);
    let (mut acc, mut acc_len) = (0u32, 0);
    for &b in &pk[1..] {
        acc = (acc << 8) | b as u32;
        acc_len += 8;
        if acc_len >= 14 {
            acc_len -= 14;
            h.push((acc >> acc_len) & 0x3fff);
        }
    }
    h
}

/// The squared norm of `(s1, s2)` that verification bounds, pushing the streams the guest takes. It does not check
/// the bound: a forged signature's streams are pushed as an honest one's.
fn norm(pk: &[u8], msg: &[u8], sig: &[u8], hints: &mut Hints) -> u64 {
    let nonce = &sig[1..41];
    let mut nm = nonce.to_vec();
    nm.extend_from_slice(msg);
    hints.push("fa_nonce_msg", lanes(&nm));

    let mut pkb = pk.to_vec();
    pkb.resize(113 * 8, 0);
    for lane_bits in stream_bits(&pkb).chunks(64) {
        hints.push("pk_bits", lane_bits.to_vec());
    }

    // HashToPoint: 16-bit big-endian samples of SHAKE256(nonce || M) below 5q, reduced.
    let states = shake256_states(&nm, 15);
    let stream: Vec<u8> = states.iter().flat_map(rate_bytes).collect();
    let (mut c, mut ns) = (Vec::with_capacity(N), 0);
    while c.len() < N {
        let w = (stream[2 * ns] as u32) << 8 | stream[2 * ns + 1] as u32;
        if w < 5 * Q {
            c.push(w % Q);
        }
        ns += 1;
    }
    let nb = ns / 68 + 1;
    hints.push("htp_nb", vec![count(nb)]);
    for st in &states[..nb] {
        hints.push("htp_bits", stream_bits(&rate_bytes(st)));
    }
    hints.push("htp_n", vec![count(ns)]);
    for s in 0..ns {
        let w = (stream[2 * s] as u32) << 8 | stream[2 * s + 1] as u32;
        hints.push("htp_acc", vec![bit(w < 5 * Q)]);
        if w < 5 * Q {
            hints.push("htp_kc", vec![count((w / Q) as usize), count((w % Q) as usize)]);
        }
    }

    // s2, s1 = c - s2 h, norms.
    let mut norm = 0u64;
    let s2q: Vec<u32> = decode_s2(&sig[41..])
        .iter()
        .map(|&v| {
            norm += (v * v) as u64;
            let r = v.rem_euclid(Q as i32) as u32;
            hints.push(
                "fa_s2",
                vec![count(v.unsigned_abs() as usize), bit(v < 0), count(r as usize)],
            );
            r
        })
        .collect();
    let mut fq = Fq(hints);
    let s2h = fq.ntt(&s2q);
    let hh = fq.ntt(&public_h(pk));
    let pr: Vec<u32> = (0..N).map(|k| fq.mul(s2h[k], hh[k])).collect();
    let p = fq.intt(&pr);
    for k in 0..N {
        let p = fq.mul(NINV, p[k]);
        let r = fq.can(c[k] + Q - p);
        let big = r >= 6145;
        let v = if big { Q - r } else { r } as u64;
        norm += v * v;
        fq.0.push("fa_big", vec![bit(big)]);
    }
    let slack = NORM_BOUND.saturating_sub(norm);
    hints.push(
        "fa_slack",
        vec![count((slack & 0xffff) as usize), count((slack >> 16) as usize)],
    );
    norm
}

impl Scheme for Falcon512 {
    type Item = FalconItem;
    const NAME: &'static str = "falcon512";

    fn source() -> String {
        GUEST.into()
    }

    fn placeholders(ps: &mut BTreeMap<String, String>) {
        let tag = cell(CLAIM_TAG);
        ps.insert("CLAIM_TAG_0".into(), tag.c0.to_string());
        ps.insert("CLAIM_TAG_1".into(), tag.c1.to_string());
        let d = chain(&table());
        ps.insert("CT_D0".into(), f192_literal(d[0]));
        ps.insert("CT_D1".into(), f192_literal(d[1]));
        ps.insert("FNINV".into(), f192_literal(count(NINV as usize)));
    }

    fn items(n: usize) -> Vec<FalconItem> {
        (0..n)
            .map(|i| {
                let mut seed = [0u8; 48];
                Stream::new(b"key", i).fill_bytes(&mut seed);
                let (mut sk, mut pk) = ([0; SIGN_KEY_SIZE_512], [0; VRFY_KEY_SIZE_512]);
                KeyPairGenerator512::default()
                    .keygen_from_seed_pqclean(FN_DSA_LOGN_512, &seed, &mut sk, &mut pk)
                    .expect("keygen");
                let mut msg = [0x42u8; 32];
                msg[..8].copy_from_slice(&(i as u64).to_le_bytes());
                let mut other_msg = msg;
                other_msg[31] ^= 1;
                FalconItem {
                    pk,
                    msg,
                    sig: sign(&sk, &msg, i, b"sign"),
                    other: sign(&sk, &other_msg, i, b"sign-other"),
                }
            })
            .collect()
    }

    fn claim(item: &FalconItem) -> Claim {
        let mut bytes = CLAIM_TAG.to_vec();
        bytes.extend_from_slice(&item.msg);
        bytes.extend_from_slice(&item.pk);
        nethermind_lean::keccak(&bytes)
    }

    fn setup_hints(hints: &mut Hints) {
        for pair in table().chunks(2) {
            hints.push("table_cells", pair.to_vec());
        }
    }

    fn push_hints(item: &FalconItem, hints: &mut Hints) {
        norm(&item.pk, &item.msg, &item.sig, hints);
    }

    fn forge(item: &FalconItem) -> FalconItem {
        FalconItem {
            sig: item.other.clone(),
            ..item.clone()
        }
    }

    fn reference_check() {
        // The host's SHAKE256 over Keccak-f agrees with the sha3 crate.
        let msg: Vec<u8> = (0..72u8).collect();
        let mut want = vec![0u8; RATE * 3];
        let mut h = sha3::Shake256::default();
        h.update(&msg);
        h.finalize_xof().read(&mut want);
        let got: Vec<u8> = shake256_states(&msg, 3).iter().flat_map(rate_bytes).collect();
        assert_eq!(got, want, "SHAKE256");

        // The NTT multiplies negacyclically.
        let a: Vec<u32> = (0..N as u32).map(|i| (i * 7919 + 3) % Q).collect();
        let b: Vec<u32> = (0..N as u32).map(|i| (i * 104729 + 5) % Q).collect();
        let mut hints = Hints::default();
        let mut fq = Fq(&mut hints);
        let (fa, fb) = (fq.ntt(&a), fq.ntt(&b));
        let pr: Vec<u32> = (0..N).map(|k| fq.mul(fa[k], fb[k])).collect();
        let got: Vec<u32> = fq.intt(&pr).iter().map(|&v| fq.mul(NINV, v)).collect();
        let mut want = vec![0i64; N];
        for i in 0..N {
            for j in 0..N {
                let p = a[i] as i64 * b[j] as i64;
                if i + j < N {
                    want[i + j] += p
                } else {
                    want[i + j - N] -= p
                }
            }
        }
        let want: Vec<u32> = want.iter().map(|v| v.rem_euclid(Q as i64) as u32).collect();
        assert_eq!(got, want, "negacyclic NTT");

        // The host's verification agrees with the reference implementation on honest and forged signatures.
        for item in Self::items(4) {
            assert!(verifies(&item.pk, &item.msg, &item.sig));
            assert!(!verifies(&item.pk, &item.msg, &item.other));
            assert!(norm(&item.pk, &item.msg, &item.sig, &mut Hints::default()) <= NORM_BOUND);
            assert!(norm(&item.pk, &item.msg, &item.other, &mut Hints::default()) > NORM_BOUND);
        }
    }
}
