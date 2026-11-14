# Falcon-512 (round 3, PQClean raw-message mode) claim:
# claim = keccak256(CLAIM_TAG || M || pk), M 32 bytes, pk the 897-byte encoded key.
#
# Arithmetic mod q = 12289 in the exponent of g: a residue r < q is the cell g^r; products
# by quarter squares F[y] = g^floor(y^2/4) and a hinted exact reduction. The signature is a
# witness: s2 is taken as its coefficients (|s2_i| <= 2047, no "-0", the compressed
# format's range), not as the compressed string. Bytes enter as bit streams, most
# significant bit of each byte first, each bit pinned boolean once: a 64-bit lane is
# sum b_s W[s], a k-bit big-endian field is prod (1 + b_t E[t]), E[t] = g^(2^(15 - t)) + 1.

FQ = 12289
FN = 512
F_NEG = 12288
F_SIZE = 36873
QT_OFF = F_SIZE
TB_SIZE = QT_OFF + FQ + 1
# constant table: zetas, then W, then E
ZT_OFF = 0
W_OFF = 512
E_OFF = 576
CT_SIZE = 592
CT_PAIRS = 296
NORM_BOUND = 34034726
SHAKE_PAD = 31
LANE_TOP = 9223372036854775808
Y_CELL = f192(0, 1, 0)
CLAIM_TAG_0 = CLAIM_TAG_0_PLACEHOLDER
CLAIM_TAG_1 = CLAIM_TAG_1_PLACEHOLDER
CT_D0 = CT_D0_PLACEHOLDER
CT_D1 = CT_D1_PLACEHOLDER
FNINV = FNINV_PLACEHOLDER


def setup_scheme():
    # F[y] for y in [-12288, 24584] (F[-y] = F[y]), QT[k] = g^(q k) for k <= q.
    tb = HeapBuf(TB_SIZE)
    f = tb * GEN ** F_NEG
    f[1] = 1
    for k in mul_range(1, GEN ** 12292):
        odd = f[k * k] * k
        f[k * k * GEN] = odd
        f[k * k * GEN ** 2] = odd * k * GEN
    for k in mul_range(GEN, GEN ** 12289):
        f[1 / k] = f[k]
    qt = tb * GEN ** QT_OFF
    qt[1] = 1
    for k in mul_range(1, GEN ** FQ):
        qt[k * GEN] = qt[k] * GEN ** FQ
    # zetas, W, E: hinted pairs bound by a keccak chain from zero.
    ct = HeapBuf(CT_SIZE)
    h = HeapBuf(2 * CT_PAIRS + 2)
    h[1] = 0
    h[GEN] = 0
    for i in mul_range(1, GEN ** CT_PAIRS):
        pair = ct * i * i
        hint_witness(pair[0:2], "table_cells")
        cur = h * i * i
        keccak([cur[1], cur[GEN]], [pair[1], pair[GEN]], (h * i * i * GEN ** 2)[0:2])
    assert h[GEN ** (2 * CT_PAIRS)] == CT_D0
    assert h[GEN ** (2 * CT_PAIRS + 1)] == CT_D1
    # g^(2^k), k = 0 .. 9
    p2 = HeapBuf(10)
    p2[1] = GEN
    for k in mul_range(1, GEN ** 9):
        p2[k * GEN] = p2[k] * p2[k]
    ctx = HeapBuf(4)
    ctx[1] = f
    ctx[GEN] = ct
    ctx[GEN ** 2] = p2
    return ctx


@inline
def fq_mul(a, b, f):
    p = f[a * b] / f[a / b]
    h = StackBuf(2)
    hint_witness(h, "fq")
    assert log(h[0]) < FQ
    assert log(h[1]) < FQ
    assert p == h[0] * f[GEN ** (QT_OFF - F_NEG) * h[1]]
    return h[0]


@inline
def fq_can(s):
    # s = g^x with x < 2q: g^(x mod q).
    r = hint_witness("fa")
    assert log(r) < FQ
    d = s / r
    assert (d + 1) * (d + GEN ** FQ) == 0
    return r


def lane_of(bits, w):
    # sum b_s W[s] over 64 bits, each pinned boolean, eight a loop frame.
    acc = HeapBuf(9)
    acc[1] = 0
    for k in mul_range(1, GEN ** 8):
        b = bits * k ** 8
        wk = w * k ** 8
        x = acc[k]
        for t in unroll(0, 8):
            v = b[GEN ** t]
            assert v * v == v
            x = x + v * wk[GEN ** t]
        acc[k * GEN] = x
    return acc[GEN ** 8]


def gpow_of(bits, e, n):
    # g^v for v the 2n-bit big-endian integer the bits spell, two bits a loop frame.
    acc = HeapBuf(9)
    acc[1] = 1
    for t in mul_range(1, n):
        b = bits * t * t
        f = e * t * t
        acc[t * GEN] = acc[t] * (1 + b[1] * f[1]) * (1 + b[GEN] * f[GEN])
    return acc[n]


def absorb(st, inp, out):
    # Keccak-f of the state st with the 17 lanes inp XORed into its rate.
    a = HeapBuf(13)
    for c in mul_range(1, GEN ** 8):
        a[c] = st[c] + inp[c * c] + Y_CELL * inp[c * c * GEN]
    a[GEN ** 8] = st[GEN ** 8] + inp[GEN ** 16]
    for c in mul_range(GEN ** 9, GEN ** 13):
        a[c] = st[c]
    keccak(a[0:2], a[2:4], out[0:13], tail=a[4:8], cap=a[8:13])
    return


def sponge(lanes, nb, states):
    # The states after each of nb blocks of 17 lanes, absorbed from zero.
    for k in mul_range(1, GEN ** 13):
        states[k] = 0
    for b in mul_range(1, nb):
        absorb(states * b ** 13, lanes * b ** 17, states * (b * GEN) ** 13)
    return


def fntt(arr, f, ct, p2):
    # FIPS-style forward NTT, layer by layer from arr into arr + 512 (layer + 1).
    for lay in mul_range(1, GEN ** 9):
        cur = arr * lay ** FN
        half = p2[GEN ** 8 / lay]
        blocks = p2[lay]
        ptr = HeapBuf(257)
        ptr[1] = 1
        for b in mul_range(1, blocks):
            o = ptr[b]
            ptr[b * GEN] = o * half * half
            fntt_block(cur * o, cur * o * GEN ** FN, ct[blocks * b], half, f)
    return


def fntt_block(sa, da, z, half, f):
    for j in mul_range(1, half):
        a = sa[j]
        t = fq_mul(z, sa[j * half], f)
        da[j] = fq_can(a * t)
        da[j * half] = fq_can(a * GEN ** FQ / t)
    return


def fintt(arr, f, ct, p2):
    for s in mul_range(1, GEN ** 9):
        cur = arr * s ** FN
        half = p2[s]
        blocks = p2[GEN ** 8 / s]
        zb = ct * p2[GEN ** 9 / s] / GEN
        ptr = HeapBuf(257)
        ptr[1] = 1
        for b in mul_range(1, blocks):
            o = ptr[b]
            ptr[b * GEN] = o * half * half
            fintt_block(cur * o, cur * o * GEN ** FN, zb / b, half, f)
    return


def fintt_block(sa, da, z, half, f):
    for j in mul_range(1, half):
        a = sa[j]
        b = sa[j * half]
        da[j] = fq_can(a * b)
        da[j * half] = fq_mul(z[1], fq_can(b * GEN ** FQ / a), f)
    return


def htp_sample(w, ci, nc, cvec, f):
    # One HashToPoint sample: accepted iff w < 5 q, then c[ci] = w mod q.
    acc = hint_witness("htp_acc")
    if acc == 1:
        kc = StackBuf(2)
        hint_witness(kc, "htp_kc")
        assert log(kc[0]) < 5
        assert log(kc[1]) < FQ
        assert w == kc[1] * f[GEN ** (QT_OFF - F_NEG) * kc[0]]
        cvec[ci] = kc[1]
        nc[1] = ci * GEN
    else:
        assert log(w / GEN ** 61445) < 4091
        nc[1] = ci
    return


def squeeze_check(st, rb, w):
    # The rate of state st spells the 1088 stream bits at rb.
    for c in mul_range(1, GEN ** 8):
        cb = rb * c ** 128
        assert st[c] == lane_of(cb, w) + Y_CELL * lane_of(cb * GEN ** 64, w)
    # Cell 8 holds lane 16 alone: lanes 17 .. 24 are the four cells after it.
    assert st[GEN ** 8] == lane_of(rb * GEN ** 1024, w)
    return


def verify_claim(ctx):
    f = ctx[1]
    ct = ctx[GEN]
    p2 = ctx[GEN ** 2]
    w = ct * GEN ** W_OFF
    e = ct * GEN ** E_OFF

    # claim = keccak256(tag || M || pk): 945 bytes, 7 blocks of 17 lanes.
    cl = HeapBuf(119)
    cl[1] = CLAIM_TAG_0
    cl[GEN] = CLAIM_TAG_1
    hl = HeapBuf(17 * 16)
    hint_witness(hl[0:9], "fa_nonce_msg")
    assert_in_k(hl[1], hl[GEN])
    assert_in_k(hl[GEN ** 2], hl[GEN ** 3])
    assert_in_k(hl[GEN ** 4], hl[GEN ** 5])
    assert_in_k(hl[GEN ** 6], hl[GEN ** 7])
    assert_in_k(hl[GEN ** 8], 0)
    for k in mul_range(1, GEN ** 4):
        cl[GEN ** 2 * k] = hl[GEN ** 5 * k]
    # pk lanes from its bit stream; byte 896 is lane 112's only byte.
    pb = HeapBuf(113 * 64)
    pkl = cl * GEN ** 6
    for l in mul_range(1, GEN ** 112):
        lb = pb * l ** 64
        hint_witness(lb[0:64], "pk_bits")
        pkl[l] = lane_of(lb, w)
    lb = pb * GEN ** (112 * 64)
    hint_witness(lb[0:64], "pk_bits")
    for k in mul_range(GEN ** 8, GEN ** 64):
        lb[k] = 0
    cl[GEN ** 118] = lane_of(lb, w) + const(256 + LANE_TOP)
    cls = HeapBuf(13 * 8)
    sponge(cl, GEN ** 7, cls)
    claim = cls * GEN ** (13 * 7)

    # h: byte 0 is the header 0x09, then 512 14-bit coefficients below q.
    assert gpow_of(pb, e * GEN ** 8, GEN ** 4) == GEN ** 9
    hp = HeapBuf(FN * 10)
    hc = pb * GEN ** 8
    for i in mul_range(1, GEN ** FN):
        v = gpow_of(hc * i ** 14, e * GEN ** 2, GEN ** 7)
        assert log(v) < FQ
        hp[i] = v

    # c = HashToPoint(nonce || M): SHAKE256 output, 16-bit big-endian samples below 5q.
    hl[GEN ** 9] = SHAKE_PAD
    for k in mul_range(GEN ** 10, GEN ** 16):
        hl[k] = 0
    hl[GEN ** 16] = LANE_TOP
    nb = hint_witness("htp_nb")
    assert log(nb) < 16
    for k in mul_range(GEN ** 17, nb ** 17):
        hl[k] = 0
    st = HeapBuf(13 * 17)
    sponge(hl, nb, st)
    hb = HeapBuf(1088 * 15)
    for b in mul_range(1, nb):
        rb = hb * b ** 1088
        hint_witness(rb[0:1088], "htp_bits")
        squeeze_check(st * (b * GEN) ** 13, rb, w)
    ns = hint_witness("htp_n")
    assert log(ns) < log(nb ** 68)
    cvec = HeapBuf(FN)
    cur = HeapBuf(1021)
    cur[1] = 1
    for s in mul_range(1, ns):
        htp_sample(gpow_of(hb * s ** 16, e, GEN ** 8), cur[s], cur * s * GEN, cvec, f)
    assert cur[ns] == GEN ** FN

    # s2 = (-1)^sg m with m <= 2047, no "-0"; its squared norm.
    s2 = HeapBuf(FN * 10)
    n2 = HeapBuf(FN + 1)
    n2[1] = 1
    for k in mul_range(1, GEN ** FN):
        h = StackBuf(3)
        hint_witness(h, "fa_s2")
        assert log(h[0]) < 2048
        h[1] = h[1] * h[1]
        assert log(h[2]) < FQ
        assert h[2] == h[0] + h[1] * (GEN ** FQ / h[0] + h[0])
        s2[k] = h[2]
        n2[k * GEN] = n2[k] * f[h[0] * h[0]]

    # s1 = c - s2 h mod q, centered; ||s1||^2 + ||s2||^2 <= floor(beta^2).
    fntt(s2, f, ct, p2)
    fntt(hp, f, ct, p2)
    sh = s2 * GEN ** (FN * 9)
    hh = hp * GEN ** (FN * 9)
    pr = HeapBuf(FN * 10)
    for k in mul_range(1, GEN ** FN):
        pr[k] = fq_mul(sh[k], hh[k], f)
    fintt(pr, f, ct, p2)
    pi = pr * GEN ** (FN * 9)
    n1 = HeapBuf(FN + 1)
    n1[1] = 1
    for k in mul_range(1, GEN ** FN):
        r = fq_can(cvec[k] * GEN ** FQ / fq_mul(FNINV, pi[k], f))
        big = hint_witness("fa_big")
        if big == 1:
            assert log(r / GEN ** 6145) < 6144
            n1[k * GEN] = n1[k] * f[(GEN ** FQ / r) ** 2]
        else:
            assert log(r) < 6145
            n1[k * GEN] = n1[k] * f[r ** 2]
    d = StackBuf(2)
    hint_witness(d, "fa_slack")
    assert log(d[0]) < 65536
    assert log(d[1]) < 65536
    assert n1[GEN ** FN] * n2[GEN ** FN] * d[0] * d[1] ** 65536 == GEN ** NORM_BOUND
    return claim[1], claim[GEN]
