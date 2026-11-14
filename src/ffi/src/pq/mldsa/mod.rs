// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

//! ML-DSA-44 (FIPS 204 pure, empty context) over 32-byte messages: `mldsa.py`. The host decodes the key and
//! signature, recomputes every intermediate the program checks and pushes the hints in its execution order.

use std::collections::BTreeMap;

use fips204::ml_dsa_44;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use primitives::field::F192;
use sha3::digest::{ExtendableOutput, Update, XofReader};

use super::common::{Claim, Hints, Scheme, cells, count, f192_literal};

const GUEST: &str = include_str!("mldsa.py");
/// The claim's domain: one cell.
pub const CLAIM_TAG: &[u8; 16] = b"EIP8288:mldsa44:";
const Q: u32 = 8380417;
const LIMB: u32 = 4096;
const GAMMA1: i32 = 1 << 17;
const GAMMA2: u32 = 95232;
const OMEGA: usize = 80;
const TAU: usize = 39;
/// 256^-1 mod q.
const FINV: u32 = 8347681;
/// Cells an NTT slot takes: the thirteen polynomials z, c, t1 and w', of 256 three-cell records each.
const SLOT: usize = 9984;

pub struct MlDsa44;

#[derive(Clone)]
pub struct Item {
    pub pk: [u8; ml_dsa_44::PK_LEN],
    pub msg: [u8; 32],
    pub sig: [u8; ml_dsa_44::SIG_LEN],
    /// The key's index, for signing another message under it.
    key: usize,
}

fn signed(key: usize, msg: [u8; 32]) -> Item {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&(key as u64).to_le_bytes());
    let (pk, sk) = ml_dsa_44::KG::keygen_from_seed(&seed);
    let sig = sk.try_sign_with_seed(&seed, &msg, &[]).expect("signs");
    Item {
        pk: pk.into_bytes(),
        msg,
        sig,
        key,
    }
}

/// The item of a signature that FIPS 204's verification (ML-DSA-44, pure, empty context) and this leaf's host computation
/// both accept, as a relay checks it before admission and a prover before proving.
pub fn verified(pk: &[u8], msg: &[u8; 32], sig: &[u8]) -> Option<Item> {
    let item = Item {
        pk: pk.try_into().ok()?,
        msg: *msg,
        sig: sig.try_into().ok()?,
        key: 0,
    };
    let key = ml_dsa_44::PublicKey::try_from_bytes(item.pk).ok()?;
    (key.verify(msg, &item.sig, &[]) && recompute_ctilde(&item, &mut Hints::default()) == item.sig[..32]).then_some(item)
}

/// Key `key`'s signature over `msg`, with its public key.
pub(super) fn sign_message(key: usize, msg: [u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let item = signed(key, msg);
    (item.pk.to_vec(), item.sig.to_vec())
}

/// Equivalence vectors: honest signatures and the encodings and substitutions the native check must reject.
pub(super) fn vector_inputs() -> Vec<super::RawCase> {
    let (a, b) = (signed(0, message(0)), signed(1, message(1)));
    let case = |label, pk: &[u8], msg, sig: &[u8], valid| (label, pk.to_vec(), msg, sig.to_vec(), valid);
    let mut cases = vec![
        case("honest", &a.pk, a.msg, &a.sig, true),
        case("honest, second key", &b.pk, b.msg, &b.sig, true),
        case("signature over another message", &a.pk, a.msg, &MlDsa44::forge(&a).sig, false),
        case("another key", &b.pk, a.msg, &a.sig, false),
        case("truncated signature", &a.pk, a.msg, &a.sig[..ml_dsa_44::SIG_LEN - 1], false),
        case("extended signature", &a.pk, a.msg, &[&a.sig[..], &[0]].concat(), false),
        case("truncated key", &a.pk[..ml_dsa_44::PK_LEN - 1], a.msg, &a.sig, false),
    ];
    let mut msg = a.msg;
    msg[31] ^= 1;
    cases.push(case("altered message", &a.pk, msg, &a.sig, false));
    for (label, at) in [("altered c~", 0), ("altered z", 100)] {
        let mut sig = a.sig;
        sig[at] ^= 1;
        cases.push(case(label, &a.pk, a.msg, &sig, false));
    }
    let mut pk = a.pk;
    pk[40] ^= 1;
    cases.push(case("altered key", &pk, a.msg, &a.sig, false));
    // The hint: OMEGA index bytes, then the four rows' cumulative counts.
    let hint = ml_dsa_44::SIG_LEN - OMEGA - 4;
    let total = a.sig[ml_dsa_44::SIG_LEN - 1] as usize;
    if total < OMEGA {
        let mut sig = a.sig;
        sig[hint + total] = 1;
        cases.push(case("nonzero hint padding", &a.pk, a.msg, &sig, false));
    }
    let mut sig = a.sig;
    sig[hint + OMEGA] = OMEGA as u8 + 1;
    cases.push(case("hint count above omega", &a.pk, a.msg, &sig, false));
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&0u64.to_le_bytes());
    let (_, sk) = ml_dsa_44::KG::keygen_from_seed(&seed);
    let with_context = sk.try_sign_with_seed(&seed, &a.msg, b"ctx").expect("signs");
    cases.push(case("nonempty context", &a.pk, a.msg, &with_context, false));
    cases
}

fn message(i: usize) -> [u8; 32] {
    crate::keccak(&(i as u64).to_le_bytes())
}

/// FIPS 204's M' (empty context), zero-filled to three cells.
fn m_cells(msg: &[u8; 32]) -> [u8; 48] {
    let mut m = [0u8; 48];
    m[2..34].copy_from_slice(msg);
    m
}

fn shake256(data: &[&[u8]], out: &mut [u8]) {
    let mut h = sha3::Shake256::default();
    for d in data {
        h.update(d);
    }
    h.finalize_xof().read(out);
}

fn bit(b: bool) -> F192 {
    if b { F192::ONE } else { F192::ZERO }
}

/// FIPS 204 `zetas[m] = 1753^brv8(m) mod q`.
fn zetas() -> [u32; 256] {
    std::array::from_fn(|m| pow(1753, (m as u8).reverse_bits() as u64))
}

fn pow(base: u32, mut e: u64) -> u32 {
    let (mut acc, mut b) = (1u64, base as u64);
    while e > 0 {
        if e & 1 == 1 {
            acc = acc * b % Q as u64;
        }
        b = b * b % Q as u64;
        e >>= 1;
    }
    acc as u32
}

fn record(r: u32) -> [F192; 3] {
    [
        count((r % LIMB) as usize),
        count((r / LIMB) as usize),
        count(r as usize),
    ]
}

/// FIPS 204 Decompose then UseHint.
fn use_hint(h: bool, r: u32) -> u32 {
    let alpha = 2 * GAMMA2;
    let mut r0 = (r % alpha) as i64;
    if r0 > (alpha / 2) as i64 {
        r0 -= alpha as i64;
    }
    let (r1, r0) = if r as i64 - r0 == (Q - 1) as i64 {
        (0i64, r0 - 1)
    } else {
        ((r as i64 - r0) / alpha as i64, r0)
    };
    match (h, r0 > 0) {
        (false, _) => r1 as u32,
        (true, true) => ((r1 + 1).rem_euclid(44)) as u32,
        (true, false) => ((r1 - 1).rem_euclid(44)) as u32,
    }
}

/// One NTT butterfly: its layer, its pair `(j, j + len)` and the zetas the NTT and its inverse take for it.
struct Row {
    layer: usize,
    j: usize,
    len: usize,
    zeta: usize,
    inverse_zeta: usize,
}

/// The 1024 butterflies in FIPS 204 NTT order (Algorithm 41). NTT^-1 (Algorithm 42) pairs the same indices in each
/// layer, with zeta index 2^(layer+1) - 1 - block.
fn rows() -> Vec<Row> {
    let mut out = Vec::with_capacity(1024);
    for layer in 0..8 {
        let len = 128 >> layer;
        for b in 0..1usize << layer {
            for j in 2 * len * b..2 * len * b + len {
                out.push(Row {
                    layer,
                    j,
                    len,
                    zeta: (1 << layer) + b,
                    inverse_zeta: (2 << layer) - 1 - b,
                });
            }
        }
    }
    out
}

/// UseHint's value at index 4 t + 2 [s = 0] + h.
fn use_hint_table() -> Vec<u32> {
    let mut out = vec![0u32; 356];
    for t in 0..89u32 {
        for z in 0..2u32 {
            for h in 0..2u32 {
                let r = t * GAMMA2 + (1 - z);
                out[(4 * t + 2 * z + h) as usize] = if r < Q { use_hint(h == 1, r) } else { 0 };
            }
        }
    }
    out
}

/// The hinted constant table and the offsets of its parts, in the order `mldsa.py` names them.
fn constants() -> (Vec<F192>, Vec<(&'static str, usize)>) {
    let mut cells = Vec::new();
    let mut offsets = Vec::new();
    let mut part = |name: &'static str, values: Vec<F192>, zero_at: usize| {
        offsets.push((name, cells.len() + zero_at));
        cells.extend(values);
    };
    let mut rows_cells = Vec::new();
    for r in rows() {
        let lo = SLOT * r.layer + 3 * r.j;
        rows_cells.extend([lo, lo + 3 * r.len, 3 * r.zeta, 3 * r.inverse_zeta].map(count));
    }
    part("ROWS", rows_cells, 0);
    part("ZT", zetas().iter().flat_map(|&z| record(z)).collect(), 0);
    part(
        "UH",
        use_hint_table()
            .iter()
            .map(|&v| count(v as usize))
            .collect(),
        0,
    );
    part("BT", (0..256u64).map(|v| F192::new(v, 0, 0)).collect(), 0);
    let basis = |i: usize| {
        if i < 64 {
            F192::new(1 << i, 0, 0)
        } else {
            F192::new(0, 1 << (i - 64), 0)
        }
    };
    part("BB", (0..16).map(|k| basis(8 * k)).collect(), 0);
    part("BASIS", (0..128).map(basis).collect(), 0);
    part("PW", (0..24).map(|i| count(1 << i)).collect(), 0);
    part(
        "TG",
        (0..89).map(|t| count(t * GAMMA2 as usize)).collect(),
        0,
    );
    // codes g^0, g^1, g^2 = coefficients 0, 1, -1: their records' three cells
    let q1 = (Q - 1) as usize;
    part("CS", [0, 1, 0, 0, 0, 2046, 0, 1, q1].map(count).to_vec(), 0);
    part("KOFF", (0..1024).map(|n| count(3 * (n % 256))).collect(), 0);
    // a state cell's bytes in its block (cell 8 holds lane 16 alone) and its high lane's
    let off = |c: usize| if c <= 8 { 16 * c } else { 16 * c - 8 };
    part("OFF", (0..11).map(|c| count(off(c))).collect(), 0);
    part("OFFHI", (0..11).map(|c| count(off(c) + 8)).collect(), 0);
    part("BLK", (0..8).map(|b| count(168 * b)).collect(), 0);
    part("ONES", vec![count(0); 256], 0);
    part("S256", (0..256).map(|v| count(256 * v)).collect(), 0);
    part("S65536", (0..256).map(|v| count(65536 * v)).collect(), 0);
    for (name, s) in [("F0", 1usize), ("F12", 1 << 12), ("F24", 1 << 24)] {
        let f = (-4096i64..=8192)
            .map(|y| count(s * ((y * y) / 4) as usize))
            .collect();
        part(name, f, 4096);
    }
    part("P1", (0..2048).map(|k| count(4096 * k)).collect(), 0);
    part("QT0", (0..4096).map(|k| count(Q as usize * k)).collect(), 0);
    part(
        "QT1",
        (0..16384).map(|k| count(4096 * Q as usize * k)).collect(),
        0,
    );
    if cells.len() % 2 == 1 {
        cells.push(F192::ZERO);
    }
    offsets.push(("SIZE", cells.len()));
    (cells, offsets)
}

fn cell_bytes(c: F192) -> [u8; 16] {
    assert_eq!(c.c2, 0);
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&c.c0.to_le_bytes());
    b[8..].copy_from_slice(&c.c1.to_le_bytes());
    b
}

/// The Keccak chain `load_checked` recomputes over the table's pairs.
fn table_digest(table: &[F192]) -> [F192; 2] {
    let mut h = [0u8; 32];
    for pair in table.chunks(2) {
        let mut pre = h.to_vec();
        pre.extend(cell_bytes(pair[0]));
        pre.extend(cell_bytes(pair[1]));
        h = crate::keccak(&pre);
    }
    let c = cells(&h);
    [c[0], c[1]]
}

/// Arithmetic mod q, pushing the hints the program pops in its execution order.
struct Mq<'a>(&'a mut Hints);

impl Mq<'_> {
    fn limbs(r: u64) -> Vec<F192> {
        vec![
            count((r % LIMB as u64) as usize),
            count((r / LIMB as u64) as usize),
        ]
    }

    /// `red`: x < 2^49 reduced, its quotient in limbs.
    fn red(&mut self, x: u64) -> u32 {
        let (qq, r) = (x / Q as u64, x % Q as u64);
        self.0.push("mq", Self::limbs(r));
        self.0.push("mqq", Self::limbs(qq));
        r as u32
    }

    /// `can`: x < 4q reduced.
    fn can(&mut self, x: u64) -> u32 {
        let r = x % Q as u64;
        self.0.push("ma", Self::limbs(r));
        r as u32
    }

    fn ntt(&mut self, w: &[u32; 256]) -> [u32; 256] {
        let z = zetas();
        let mut slots = vec![[0u32; 256]; 9];
        slots[0] = *w;
        for r in rows() {
            let (a, b) = (slots[r.layer][r.j], slots[r.layer][r.j + r.len]);
            let t = self.red(z[r.zeta] as u64 * b as u64);
            slots[r.layer + 1][r.j] = self.can(a as u64 + t as u64);
            slots[r.layer + 1][r.j + r.len] = self.can(a as u64 + 2 * Q as u64 - t as u64);
        }
        slots[8]
    }
}

/// FIPS 204 NTT^-1 (Algorithm 42).
fn intt(w: &[u32; 256]) -> [u32; 256] {
    let z = zetas();
    let mut cur = *w;
    for r in rows().iter().rev() {
        let (a, b) = (cur[r.j] as u64, cur[r.j + r.len] as u64);
        cur[r.j] = ((a + b) % Q as u64) as u32;
        cur[r.j + r.len] =
            (z[r.inverse_zeta] as u64 * ((b + Q as u64 - a) % Q as u64) % Q as u64) as u32;
    }
    cur.map(|v| (FINV as u64 * v as u64 % Q as u64) as u32)
}

/// RejNTTPoly(rho || s || r): the polynomial, blocks squeezed, candidates read, stream.
fn rej_ntt_poly(rho: &[u8], s: u8, r: u8) -> ([u32; 256], usize, usize, Vec<u8>) {
    let mut h = sha3::Shake128::default();
    h.update(rho);
    h.update(&[s, r]);
    let mut stream = vec![0u8; 168 * 8];
    h.finalize_xof().read(&mut stream);
    let mut out = [0u32; 256];
    let (mut n, mut c) = (0, 0);
    while n < 256 {
        let v = stream[3 * c] as u32
            | (stream[3 * c + 1] as u32) << 8
            | ((stream[3 * c + 2] & 0x7f) as u32) << 16;
        if v < Q {
            out[n] = v;
            n += 1;
        }
        c += 1;
    }
    (out, c.div_ceil(56), c, stream)
}

impl Scheme for MlDsa44 {
    type Item = Item;
    const NAME: &'static str = "mldsa44";

    fn source() -> String {
        GUEST.into()
    }

    fn placeholders(ps: &mut BTreeMap<String, String>) {
        ps.insert(
            "CLAIM_TAG".into(),
            u128::from_le_bytes(*CLAIM_TAG).to_string(),
        );
        let (t, offsets) = constants();
        let d = table_digest(&t);
        ps.insert("TABLE_PAIRS".into(), (t.len() / 2).to_string());
        ps.insert("TABLE_D0".into(), f192_literal(d[0]));
        ps.insert("TABLE_D1".into(), f192_literal(d[1]));
        for (name, at) in offsets {
            ps.insert(format!("CT_{name}"), at.to_string());
        }
    }

    fn item(i: usize) -> Item {
        signed(i, message(i))
    }

    fn claim(item: &Item) -> Claim {
        let mut tr = [0u8; 64];
        shake256(&[&item.pk], &mut tr);
        let mut bytes = CLAIM_TAG.to_vec();
        bytes.extend_from_slice(&tr);
        bytes.extend_from_slice(&m_cells(&item.msg));
        crate::keccak(&bytes)
    }

    fn setup_hints(hints: &mut Hints) {
        for pair in constants().0.chunks(2) {
            hints.push("table", pair.to_vec());
        }
    }

    fn push_hints(item: &Item, hints: &mut Hints) {
        hints.push("ml_pk", cells(&item.pk));
        hints.push("ml_msg", cells(&m_cells(&item.msg)));
        recompute_ctilde(item, hints);
    }

    /// The key's signature on another message, claimed for this one.
    fn forge(item: &Item) -> Item {
        let mut other = item.msg;
        other[0] ^= 1;
        Item {
            sig: signed(item.key, other).sig,
            ..item.clone()
        }
    }

    fn reference_check() {
        for item in super::common::items::<Self>(4) {
            let pk = ml_dsa_44::PublicKey::try_from_bytes(item.pk).expect("a key");
            assert!(pk.verify(&item.msg, &item.sig, &[]));
            assert_eq!(
                recompute_ctilde(&item, &mut Hints::default()),
                item.sig[..32]
            );
            let forged = Self::forge(&item);
            assert!(!pk.verify(&forged.msg, &forged.sig, &[]));
            assert_ne!(
                recompute_ctilde(&forged, &mut Hints::default()),
                forged.sig[..32]
            );
        }
        // The NTT and its inverse, row by row as the program runs them, multiply negacyclically.
        let mut h = Hints::default();
        let mut mq = Mq(&mut h);
        let a: [u32; 256] = std::array::from_fn(|i| (i as u32 * 7919 + 13) % Q);
        let b: [u32; 256] = std::array::from_fn(|i| (i as u32 * 104729 + 5) % Q);
        let (fa, fb) = (mq.ntt(&a), mq.ntt(&b));
        let prod: [u32; 256] =
            std::array::from_fn(|i| (fa[i] as u64 * fb[i] as u64 % Q as u64) as u32);
        let mut want = [0i128; 256];
        for i in 0..256 {
            for j in 0..256 {
                let p = a[i] as i128 * b[j] as i128;
                if i + j < 256 {
                    want[i + j] += p
                } else {
                    want[i + j - 256] -= p
                }
            }
        }
        assert_eq!(intt(&prod), want.map(|v| v.rem_euclid(Q as i128) as u32));
    }
}

/// Runs ML-DSA-44 verification as the program does, pushing its hints, and returns the c~ it recomputes. Checks
/// nothing: a forged signature yields its hints and a c~ that differs from the signature's.
fn recompute_ctilde(item: &Item, hints: &mut Hints) -> [u8; 32] {
    let (pk, sig) = (&item.pk, &item.sig);
    let mut tr = [0u8; 64];
    shake256(&[pk], &mut tr);
    let mut mu = [0u8; 64];
    shake256(&[&tr, &[0, 0], &item.msg], &mut mu);

    // SampleInBall.
    let ctilde = &sig[..32];
    hints.push("ml_ctilde", cells(ctilde));
    let mut sb = [0u8; 136];
    shake256(&[ctilde], &mut sb);
    let signs = u64::from_le_bytes(sb[..8].try_into().unwrap());
    let (mut entries, mut cursor) = (Vec::<(usize, usize, bool)>::new(), 8);
    for t in 0..TAU {
        let i = 256 - TAU + t;
        let mut skip = 0;
        while cursor + skip < 136 && sb[cursor + skip] as usize > i {
            skip += 1;
        }
        assert!(cursor + skip < 136, "SampleInBall needs a second block");
        let j = sb[cursor + skip] as usize;
        cursor += skip + 1;
        hints.push("sib_skip", vec![count(skip)]);
        entries.push((i, j, (signs >> t) & 1 == 1));
    }
    let mut c = [0u32; 256];
    for &(i, j, neg) in &entries {
        c[i] = c[j];
        c[j] = if neg { Q - 1 } else { 1 };
    }

    // z.
    let zbytes = &sig[32..32 + 2304];
    let mut z = vec![0u32; 1024];
    for (k, zk) in z.iter_mut().enumerate() {
        let mut v = 0u32;
        for b in 0..18 {
            let p = 18 * k + b;
            v |= ((zbytes[p / 8] >> (p % 8)) & 1) as u32 * (1 << b);
        }
        let zi = GAMMA1 - v as i32;
        let m = zi.unsigned_abs();
        *zk = zi.rem_euclid(Q as i32) as u32;
        hints.push(
            "ml_z",
            vec![
                count((m & 0xffff) as usize),
                bit(m >> 16 == 1),
                bit(zi < 0),
                count((*zk % LIMB) as usize),
                count((*zk / LIMB) as usize),
            ],
        );
    }

    // t1 2^13.
    let t1: Vec<u32> = (0..1024)
        .map(|k| {
            let mut v = 0u32;
            for b in 0..10 {
                let p = 256 + 10 * k + b;
                v |= ((pk[p / 8] >> (p % 8)) & 1) as u32 * (1 << b);
            }
            v << 13
        })
        .collect();
    // A_hat.
    let mut a_hat = vec![[0u32; 256]; 16];
    for r in 0..4u8 {
        for s in 0..4u8 {
            let (poly, nb, ncand, stream) = rej_ntt_poly(&pk[..32], s, r);
            hints.push("rej_nb", vec![count(nb)]);
            hints.push("rej_n", vec![count(ncand)]);
            for cidx in 0..ncand {
                let b = &stream[3 * cidx..3 * cidx + 3];
                let v24 = b[0] as u32 | (b[1] as u32) << 8 | (b[2] as u32) << 16;
                let v = v24 & 0x7f_ffff;
                hints.push(
                    "rej_split",
                    vec![
                        count((v % LIMB) as usize),
                        count((v / LIMB) as usize),
                        bit(v24 >> 23 == 1),
                    ],
                );
                hints.push("rej_acc", vec![bit(v < Q)]);
                if v < Q {
                    let r1 = (v >> 12) as usize;
                    let wy = if r1 == 2046 {
                        F192::ZERO
                    } else {
                        (count(r1) + count(2046)).inv()
                    };
                    hints.push("rej_wy", vec![wy]);
                }
            }
            a_hat[(4 * r + s) as usize] = poly;
        }
    }

    // w' = NTT^-1(A_hat z_hat - c_hat t1_hat), natively; then, as the program runs them, the NTTs of z, c, t1 and w'
    // and the check of every coefficient of A_hat z_hat - c_hat t1_hat (plus q 2^24) against NTT(w').
    let poly = |v: &[u32]| -> [u32; 256] { v.try_into().unwrap() };
    let mut scratch = Hints::default();
    let mut native = Mq(&mut scratch);
    let zh: Vec<[u32; 256]> = (0..4)
        .map(|i| native.ntt(&poly(&z[256 * i..256 * (i + 1)])))
        .collect();
    let ch = native.ntt(&c);
    let th: Vec<[u32; 256]> = (0..4)
        .map(|i| native.ntt(&poly(&t1[256 * i..256 * (i + 1)])))
        .collect();
    let mut acc = vec![[0u64; 256]; 4];
    for (j, row) in acc.iter_mut().enumerate() {
        for (k, out) in row.iter_mut().enumerate() {
            *out = Q as u64 * (1 << 24) - ch[k] as u64 * th[j][k] as u64;
            for i in 0..4 {
                *out += a_hat[4 * j + i][k] as u64 * zh[i][k] as u64;
            }
        }
    }
    let w: Vec<u32> = acc
        .iter()
        .flat_map(|row| intt(&row.map(|x| (x % Q as u64) as u32)))
        .collect();
    for &wk in &w {
        hints.push("ml_w", Mq::limbs(wk as u64));
    }
    let mut mq = Mq(hints);
    for p in z
        .chunks(256)
        .chain([&c[..]])
        .chain(t1.chunks(256))
        .chain(w.chunks(256))
    {
        mq.ntt(&poly(p));
    }
    for row in &acc {
        for &x in row {
            mq.red(x);
        }
    }

    // h, UseHint, w1Encode, and c~'.
    let hb = &sig[32 + 2304..];
    let mut h = vec![false; 1024];
    let mut index = 0usize;
    for i in 0..4 {
        let end = (hb[OMEGA + i] as usize).min(OMEGA);
        while index < end {
            h[256 * i + hb[index] as usize] = true;
            index += 1;
        }
    }
    hints.push("ml_h", h.iter().map(|&b| bit(b)).collect());
    let mut w1enc = vec![0u8; 768];
    for k in 0..1024 {
        let r = w[k];
        let (t, s) = (r / GAMMA2, r % GAMMA2);
        let wz = if s == 0 {
            F192::ZERO
        } else {
            (count(s as usize) + F192::ONE).inv()
        };
        let wy = if t == 88 {
            F192::ZERO
        } else {
            (count(t as usize) + count(88)).inv()
        };
        hints.push(
            "uh",
            vec![
                count(t as usize),
                count((s & 0xffff) as usize),
                bit(s >> 16 == 1),
                bit(s == 0),
                wz,
                wy,
            ],
        );
        let v = use_hint(h[k], r);
        for b in 0..6 {
            let p = 6 * k + b;
            w1enc[p / 8] |= (((v >> b) & 1) as u8) << (p % 8);
        }
    }
    let mut ct2 = [0u8; 32];
    shake256(&[&mu, &w1enc], &mut ct2);
    ct2
}
