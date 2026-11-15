# ML-DSA-44 (FIPS 204 pure ML-DSA, empty context) over a 32-byte message M.
#
# claim = keccak256(CLAIM_TAG || tr || m), tr = SHAKE256(pk, 64) and m the 48 bytes
# 0x00 0x00 || M || 0^14: FIPS 204's M' = 0x00 0x00 || M, zero-filled to whole cells. The leaf
# proves a signature on the bytes it absorbs into mu, tr || m with the SHAKE256 padding XORed
# in at byte 98, so a claim whose m is in that form attests M; any other m names no message
# an application would compute and attests nothing it would accept.
#
# The signature is a witness and only its acceptance is proven: c~ is recomputed from mu and
# w1 and compared; z and the hint vector h are taken as coefficients, with
# ||z||_inf < gamma1 - beta and |h| <= omega checked.
#
# Arithmetic mod q = 8380417 runs in the exponent of g: a residue is a 3-cell record
# [g^r0, g^r1, g^r], r = r0 + 4096 r1 with r0 < 4096, r1 < 2047 (so r < q + 4095, congruent to
# the value). Products use quarter squares per 12-bit limb pair from tables
# F_s[y] = g^(s floor(y^2/4)), s = 1, 2^12, 2^24; a product is reduced by hinting
# x = Q q + r and checking g^x = g^(Q q) g^r with tabled powers.
#
# w' = NTT^-1(A_hat z_hat - c_hat t1_hat) is hinted rather than computed: the leaf takes the NTT
# of z, c, t1 and w' (one flat loop over the 8 x 128 butterflies each, reading operand offsets
# and zetas from a row table) and checks A_hat z_hat - c_hat t1_hat = NTT(w') coefficientwise.
# The row table and every other constant (arithmetic tables, zetas, UseHint values, bases,
# offsets) are hinted once per proof and bound by a Keccak chain to TABLE_D0, TABLE_D1.

CLAIM_TAG = CLAIM_TAG_PLACEHOLDER
TABLE_D0 = TABLE_D0_PLACEHOLDER
TABLE_D1 = TABLE_D1_PLACEHOLDER
TABLE_PAIRS = TABLE_PAIRS_PLACEHOLDER
SHAKE_PAD = 31
ML_TAU = 39
GAMMA2 = 95232
Q_MOD = 8380417
LIMB = 4096
R1_BOUND = 2047
Q1_WIDE = 16384
H2 = 16777216
# A polynomial's 256 records; the NTT's slots, each holding the 13 polynomials z (4), c, t1 (4)
# and w' (4).
POLY = 768
SLOT = 9984
# The constant table's layout (mod.rs `constants`).
CT_ZT = CT_ZT_PLACEHOLDER
CT_UH = CT_UH_PLACEHOLDER
CT_BT = CT_BT_PLACEHOLDER
CT_BB = CT_BB_PLACEHOLDER
CT_BASIS = CT_BASIS_PLACEHOLDER
CT_PW = CT_PW_PLACEHOLDER
CT_TG = CT_TG_PLACEHOLDER
CT_CS = CT_CS_PLACEHOLDER
CT_KOFF = CT_KOFF_PLACEHOLDER
CT_OFF = CT_OFF_PLACEHOLDER
CT_OFFHI = CT_OFFHI_PLACEHOLDER
CT_BLK = CT_BLK_PLACEHOLDER
CT_ONES = CT_ONES_PLACEHOLDER
CT_S256 = CT_S256_PLACEHOLDER
CT_S65536 = CT_S65536_PLACEHOLDER
CT_F0 = CT_F0_PLACEHOLDER
CT_F12 = CT_F12_PLACEHOLDER
CT_F24 = CT_F24_PLACEHOLDER
CT_P1 = CT_P1_PLACEHOLDER
CT_QT0 = CT_QT0_PLACEHOLDER
CT_QT1 = CT_QT1_PLACEHOLDER
CT_SIZE = CT_SIZE_PLACEHOLDER


def setup_scheme():
    # The constants, hinted in pairs and bound by a Keccak chain from zero to the digest.
    ct = HeapBuf(CT_SIZE)
    h = HeapBuf(2 * TABLE_PAIRS + 2)
    h[1] = 0
    h[GEN] = 0
    for i in mul_range(1, GEN ** TABLE_PAIRS):
        pair = ct * i * i
        hint_witness(pair[0:2], "table")
        cur = h * i * i
        nxt = cur * GEN ** 2
        keccak(cur[0:2], pair[0:2], nxt[0:2])
    fin = h * GEN ** (2 * TABLE_PAIRS)
    assert fin[1] == TABLE_D0
    assert fin[GEN] == TABLE_D1
    return ct


# ------------------------------------------------------------------ arithmetic mod q


def prod(a, b, ct):
    # g^(a b) of two records: a b = sum of floor((x+y)^2/4) - floor((x-y)^2/4) over limb pairs.
    a0 = a[1]
    a1 = a[GEN]
    b0 = b[1]
    b1 = b[GEN]
    f0 = ct * GEN ** CT_F0
    f12 = ct * GEN ** CT_F12
    f24 = ct * GEN ** CT_F24
    p = f0[a0 * b0] / f0[a0 / b0] * f12[a0 * b1] / f12[a0 / b1]
    return p * f12[a1 * b0] / f12[a1 / b0] * f24[a1 * b1] / f24[a1 / b1]


def red(p, ct, out):
    # out <- the record of x mod q for p = g^x, x < 2^49: x = Q q + r, Q < 2^26.
    hint_witness(out[0:2], "mq")
    qq = StackBuf(2)
    hint_witness(qq, "mqq")
    assert log(out[1]) < LIMB
    assert log(out[GEN]) < R1_BOUND
    assert log(qq[0]) < LIMB
    assert log(qq[1]) < Q1_WIDE
    r = out[1] * ct[GEN ** CT_P1 * out[GEN]]
    out[GEN ** 2] = r
    assert p == ct[GEN ** CT_QT0 * qq[0]] * ct[GEN ** CT_QT1 * qq[1]] * r
    return


def can(s, ct, out):
    # out <- the record of x mod q for s = g^x, x < 4q.
    hint_witness(out[0:2], "ma")
    assert log(out[1]) < LIMB
    assert log(out[GEN]) < R1_BOUND
    r = out[1] * ct[GEN ** CT_P1 * out[GEN]]
    out[GEN ** 2] = r
    d = s / r
    assert (d + 1) * (d + GEN ** Q_MOD) * (d + GEN ** (2 * Q_MOD)) * (d + GEN ** (3 * Q_MOD)) == 0
    return


def ntt(buf, ct):
    # FIPS 204 NTT (Algorithm 41) of slot 0 of buf into slot 8, layer l writing slot l + 1.
    for k in mul_range(1, GEN ** 1024):
        row = ct * k ** 4
        a = buf * row[1]
        b = buf * row[GEN]
        t = HeapBuf(3)
        red(prod(ct * GEN ** CT_ZT * row[GEN ** 2], b, ct), ct, t)
        ga = a[GEN ** 2]
        gt = t[GEN ** 2]
        can(ga * gt, ct, a * GEN ** SLOT)
        can(ga * GEN ** (2 * Q_MOD) / gt, ct, b * GEN ** SLOT)
    return


# ------------------------------------------------------------------ unpacking


def pack_cell(bits, ct):
    # The cell whose bit i (lanes low first) is bits[i], each checked boolean.
    acc = HeapBuf(129)
    acc[1] = 0
    for i in mul_range(1, GEN ** 128):
        b = bits[i]
        assert b * b == b
        acc[i * GEN] = acc[i] + b * ct[GEN ** CT_BASIS * i]
    return acc[GEN ** 128]


def cell_bits(cell, bits, ct):
    hint_decompose_bits(bits, cell, 128)
    assert pack_cell(bits, ct) == cell
    return


def cell_bytes(cell, lo, hi, ct):
    # lo[0..8), hi[0..8) = the cell's low and high lanes' bytes as g-powers, little-endian.
    hint_windows_exponent(lo, cell, 0, 8, 8)
    hint_windows_exponent(hi, cell, 64, 8, 8)
    acc = HeapBuf(9)
    acc[1] = 0
    for k in mul_range(1, GEN ** 8):
        u = lo[k]
        v = hi[k]
        assert log(u) < 256
        assert log(v) < 256
        acc[k * GEN] = acc[k] + ct[GEN ** CT_BT * u] * ct[GEN ** CT_BB * k] + ct[GEN ** CT_BT * v] * ct[GEN ** (CT_BB + 8) * k]
    assert acc[GEN ** 8] == cell
    return


def block_bytes(st, blk, scratch, n_g, ct):
    # The bytes of a state's first n cells (lanes 0..16 two to a cell but lane 16 alone, then
    # lanes 17.. two to a cell), contiguous at blk; cell 8's empty high lane goes to scratch.
    for c in mul_range(1, n_g):
        hi = StackBuf(1)
        if c == GEN ** 8:
            hi[0] = scratch
        else:
            hi[0] = blk * ct[GEN ** CT_OFFHI * c]
        cell_bytes(st[c], blk * ct[GEN ** CT_OFF * c], hi[0], ct)
    return


def bits_val(bits, n_g, ct):
    # g^v for v the integer the n checked bits spell, least significant first.
    acc = HeapBuf(25)
    acc[1] = 1
    for i in mul_range(1, n_g):
        b = bits[i]
        assert b * b == b
        acc[i * GEN] = acc[i] * (1 + b * (ct[GEN ** CT_PW * i] + 1))
    return acc[n_g]


# ------------------------------------------------------------------ ExpandA


@inline
def rej_cand(b3, ci, nc, out, ct):
    # One RejNTTPoly candidate b0 + 256 b1 + 65536 (b2 mod 128) = r0 + 4096 r1, kept as
    # coefficient ci iff below q.
    sp = StackBuf(3)
    hint_witness(sp, "rej_split")
    r0 = sp[0]
    r1 = sp[1]
    assert log(r0) < LIMB
    assert log(r1) < 2048
    sp[2] = sp[2] * sp[2]
    gr = r0 * ct[GEN ** CT_P1 * r1]
    assert b3[1] * ct[GEN ** CT_S256 * b3[GEN]] * ct[GEN ** CT_S65536 * b3[GEN ** 2]] == gr * (1 + sp[2] * (GEN ** 8388608 + 1))
    acc = hint_witness("rej_acc")
    if acc == 1:
        wy = hint_witness("rej_wy")
        assert log(r1) < R1_BOUND
        assert (r0 + 1) * (1 + (r1 + GEN ** 2046) * wy) == 0
        rec = out * ci ** 3
        rec[1] = r0
        rec[GEN] = r1
        rec[GEN ** 2] = gr
        nc[1] = ci * GEN
    else:
        assert log(r1 / GEN ** 2046) < 2
        assert gr != GEN ** (Q_MOD - 1)
        nc[1] = ci
    return


def expand_a(rho0, rho1, seed, out, ct):
    # A_hat[r][s] = RejNTTPoly(rho || s || r): SHAKE128, squeezed through Keccak-f. In the
    # even layout cells 0..8 hold lanes 0..16 (lane 16 alone) and cells 9..12 lanes 17..24, so
    # the 0x80 closing the 168-byte block (lane 20) is cell 10's high lane.
    st = HeapBuf(13 * 9)
    cap = [0, 0, LANE_HI_TOP, 0, 0]
    keccak([rho0, rho1], [seed, 0], st[0:13], tail=[0, 0, 0, 0], cap=cap)
    nb = hint_witness("rej_nb")
    assert log(nb) < 9
    by = HeapBuf(168 * 8)
    sc = HeapBuf(8 * 8)
    for b in mul_range(1, nb):
        cur = st * b ** 13
        nx = cur * GEN ** 13
        keccak(cur[0:2], cur[2:4], nx[0:13], tail=cur[4:8], cap=cur[8:13])
        block_bytes(cur, by * ct[GEN ** CT_BLK * b], sc * b ** 8, GEN ** 11, ct)
    ncand = hint_witness("rej_n")
    assert log(ncand) < log(nb ** 56)
    kept = HeapBuf(449)
    kept[1] = 1
    for c in mul_range(1, ncand):
        rej_cand(by * c ** 3, kept[c], kept * c * GEN, out, ct)
    assert kept[ncand] == GEN ** 256
    return


# ------------------------------------------------------------------ SampleInBall


def sib_step(prev, now, gi, j, code):
    # c_i <- c_j, then c_j <- the step's sign, every other coefficient carried.
    for p in mul_range(1, GEN ** 256):
        if p == j:
            now[p] = code
        elif p == gi:
            now[p] = prev[j]
        else:
            now[p] = prev[p]
    return


def sample_in_ball(sb, signs, crec, ct):
    # FIPS 204 SampleInBall over the bytes sb after the 8 sign bytes, on 256 coefficient codes
    # g^0, g^1, g^2 for 0, 1, -1, one array a step.
    arr = HeapBuf(256 * ML_TAU)
    at = HeapBuf(ML_TAU + 1)
    at[1] = ct * GEN ** CT_ONES
    cur = HeapBuf(ML_TAU + 1)
    cur[1] = 1
    for t in mul_range(1, GEN ** ML_TAU):
        skip = hint_witness("sib_skip")
        assert log(skip) < 128
        c0 = cur[t]
        top = GEN ** 218 * t
        room = GEN ** 256 / top
        for k in mul_range(1, skip):
            assert log(sb[c0 * k] / top) < log(room)
        j = sb[c0 * skip]
        assert log(j) < log(top)
        cur[t * GEN] = c0 * skip * GEN
        now = arr * t ** 256
        at[t * GEN] = now
        sib_step(at[t], now, top / GEN, j, GEN * (1 + signs[t] * (GEN + 1)))
    assert log(cur[GEN ** ML_TAU]) < 129
    final = at[GEN ** ML_TAU]
    cs = ct * GEN ** CT_CS
    for k in mul_range(1, GEN ** 256):
        code = final[k]
        rec = crec * k ** 3
        rec[1] = cs[code]
        rec[GEN] = cs[GEN ** 3 * code]
        rec[GEN ** 2] = cs[GEN ** 6 * code]
    return


# ------------------------------------------------------------------ signature vectors


@inline
def load_z(rec, ct):
    # |z| = m < gamma1 - beta with its sign; rec = z mod q.
    hz = StackBuf(5)
    hint_witness(hz, "ml_z")
    hz[1] = hz[1] * hz[1]
    hz[2] = hz[2] * hz[2]
    assert log(hz[0] * (1 + hz[1] * (GEN ** 78 + 1))) < 65536
    gm = hz[0] * (1 + hz[1] * (GEN ** 65536 + 1))
    assert log(hz[3]) < LIMB
    assert log(hz[4]) < R1_BOUND
    v = hz[3] * ct[GEN ** CT_P1 * hz[4]]
    assert v == gm + hz[2] * (GEN ** Q_MOD / gm + gm)
    rec[1] = hz[3]
    rec[GEN] = hz[4]
    rec[GEN ** 2] = v
    return


@inline
def use_hint_idx(w, hbit, ct):
    # Decompose(w) as w = t gamma2 + s, s < gamma2: UseHint depends only on t, [s = 0]
    # and h, so its value is looked up at index 4 t + 2 [s = 0] + h.
    hs = StackBuf(6)
    hint_witness(hs, "uh")
    tq = hs[0]
    slo = hs[1]
    hs[2] = hs[2] * hs[2]
    zb = hs[3]
    assert log(tq) < 89
    assert log(slo * (1 + hs[2] * (GEN ** 35840 + 1))) < 65536
    gs = slo * (1 + hs[2] * (GEN ** 65536 + 1))
    dd = w[GEN ** 2] / (ct[GEN ** CT_TG * tq] * gs)
    assert (dd + 1) * (dd + GEN ** Q_MOD) == 0
    x = gs + 1
    assert zb * x == 0
    assert zb + x * hs[4] == 1
    assert (1 + zb) * (1 + (tq + GEN ** 88) * hs[5]) == 0
    return tq ** 4 * (1 + zb * (GEN ** 2 + 1)) * (1 + hbit * (GEN + 1))


@inline
def load_rec(rec, ct):
    # A hinted residue as its record.
    h = StackBuf(2)
    hint_witness(h, "ml_w")
    assert log(h[0]) < LIMB
    assert log(h[1]) < R1_BOUND
    rec[1] = h[0]
    rec[GEN] = h[1]
    rec[GEN ** 2] = h[0] * ct[GEN ** CT_P1 * h[1]]
    return


# ------------------------------------------------------------------ verification


def verify_claim(ct):
    # tr = SHAKE256(pk, 64): 1312 bytes, padded to 10 blocks.
    pk = HeapBuf(85)
    hint_witness(pk[0:82], "ml_pk")
    pk[GEN ** 82] = SHAKE_PAD
    pk[GEN ** 83] = 0
    pk[GEN ** 84] = LANE_HI_TOP
    trc = HeapBuf(13 * 6)
    tr = absorb_pairs(trc, pk, GEN ** 5)
    t0 = tr[1]
    t1 = tr[GEN]
    t2 = tr[GEN ** 2]
    t3 = tr[GEN ** 3]
    m = StackBuf(3)
    hint_witness(m, "ml_msg")
    claim = StackBuf(2)
    keccak([CLAIM_TAG, t0], [t1, t2], claim, tail=[t3, m[0], m[1], m[2]])

    # mu = SHAKE256(tr || M', 64) and SHAKE256(c~): one block each; lane 16 (cell 8) closes it.
    top = [LANE_LO_TOP, 0, 0, 0, 0]
    mu = StackBuf(13)
    keccak([t0, t1], [t2, t3], mu, tail=[m[0], m[1], m[2] + const(SHAKE_PAD * 65536), 0], cap=top)
    ctl = StackBuf(2)
    hint_witness(ctl, "ml_ctilde")
    ss = HeapBuf(13)
    keccak([ctl[0], ctl[1]], [SHAKE_PAD, 0], ss[0:13], tail=[0, 0, 0, 0], cap=top)

    # c = SampleInBall(c~): 8 sign bytes, then 128 sample bytes.
    sbytes = HeapBuf(136)
    sc = HeapBuf(8)
    block_bytes(ss, sbytes, sc, GEN ** 9, ct)
    signs = HeapBuf(128)
    cell_bits(ss[1], signs, ct)
    pb = HeapBuf(9 * SLOT)
    sample_in_ball(sbytes * GEN ** 8, signs, pb * GEN ** (4 * POLY), ct)

    # z (4 x 256), t1 2^13 (from pk bytes 32..) and the hinted w' into slot 0; h, at most omega
    # ones. Then the 13 NTTs.
    tbits = HeapBuf(10240)
    for l in mul_range(1, GEN ** 80):
        cell_bits(pk[GEN ** 2 * l], tbits * l ** 128, ct)
    hh = HeapBuf(1024)
    hint_witness(hh[0:1024], "ml_h")
    hc = HeapBuf(1025)
    hc[1] = 1
    for k in mul_range(1, GEN ** 1024):
        o = k ** 3
        load_z(pb * o, ct)
        hi = bits_val(tbits * k ** 10, GEN ** 10, ct) ** 2
        rec = pb * GEN ** (5 * POLY) * o
        rec[1] = 1
        rec[GEN] = hi
        rec[GEN ** 2] = ct[GEN ** CT_P1 * hi]
        load_rec(pb * GEN ** (9 * POLY) * o, ct)
        x = hh[k]
        assert x * x == x
        hc[k * GEN] = hc[k] * (1 + x * (GEN + 1))
    assert log(hc[GEN ** 1024]) < 81
    for p in mul_range(1, GEN ** 13):
        ntt(pb * p ** POLY, ct)

    # A_hat = ExpandA(rho), A_hat[j][i] at (4 i + j) POLY; then A_hat z_hat - c_hat t1_hat =
    # NTT(w') at every (j, k), n = 256 j + k (plus q 2^24, keeping the exponent positive).
    am = HeapBuf(16 * POLY)
    for r in mul_range(1, GEN ** 4):
        for s in mul_range(1, GEN ** 4):
            seed = ct[GEN ** CT_BT * s] + ct[GEN ** CT_BT * r] * GEN ** 8 + const(SHAKE_PAD * 65536)
            expand_a(pk[1], pk[GEN], seed, am * (s ** 4 * r) ** POLY, ct)
    zh = pb * GEN ** (8 * SLOT)
    for n in mul_range(1, GEN ** 1024):
        o = n ** 3
        z = zh * ct[GEN ** CT_KOFF * n]
        x = GEN ** (Q_MOD * H2) / prod(z * GEN ** (4 * POLY), zh * GEN ** (5 * POLY) * o, ct)
        x = x * prod(am * o, z, ct) * prod(am * GEN ** (4 * POLY) * o, z * GEN ** POLY, ct)
        x = x * prod(am * GEN ** (8 * POLY) * o, z * GEN ** (2 * POLY), ct) * prod(am * GEN ** (12 * POLY) * o, z * GEN ** (3 * POLY), ct)
        red(x, ct, zh * GEN ** (9 * POLY) * o)

    # c~' = SHAKE256(mu || w1Encode(UseHint(h, w')), 32) must equal c~: 832 bytes, 7 blocks.
    wbits = HeapBuf(6144)
    for k in mul_range(1, GEN ** 1024):
        v = ct[GEN ** CT_UH * use_hint_idx(pb * GEN ** (9 * POLY) * k ** 3, hh[k], ct)]
        bb = wbits * k ** 6
        hint_decompose_bits_exponent(bb, v, 6)
        assert bits_val(bb, GEN ** 6, ct) == v
    fb = HeapBuf(52)
    for c in unroll(0, 4):
        fb[GEN ** c] = mu[c]
    for c in mul_range(1, GEN ** 48):
        fb[GEN ** 4 * c] = pack_cell(wbits * c ** 128, ct)
    fc = HeapBuf(13 * 4)
    fs = absorb_pairs(fc, fb, GEN ** 3)
    a = StackBuf(13)
    a[0] = fs[1] + fb[GEN ** 51]
    a[1] = fs[GEN] + SHAKE_PAD
    for c in unroll(2, 8):
        a[c] = fs[GEN ** c]
    a[8] = fs[GEN ** 8] + LANE_LO_TOP
    for c in unroll(9, 13):
        a[c] = fs[GEN ** c]
    fo = StackBuf(2)
    keccak(a[0:2], a[2:4], fo, tail=a[4:8], cap=a)
    assert fo[0] == ctl[0]
    assert fo[1] == ctl[1]
    return claim[0], claim[1]
