# SLH-DSA-SHAKE-128s (FIPS 205, pure, empty context) over 32-byte messages.
# claim = keccak256(CLAIM_TAG || PK.seed || PK.root || M).
#
# n = 16 bytes is one cell, so F and H are one Keccak-f each (SHAKE256 of 64 or 80 bytes,
# padded in the state); T_k and T_len run the block-pair sponge. ADRS is two cells, A =
# (layer, tree) and B = (type, word1, word2, word3), every field big-endian. Indices are
# bits of H_msg's output, hinted MSB first per byte (the stream order of FIPS 205's base_2b)
# and bound to the digest; a field is the dot product of its bits with a table of cell
# weights. Small loop counters become field bytes through BT[g^v] = v.

CLAIM_TAG = CLAIM_TAG_PLACEHOLDER
SHAKE_PAD = 31
Y_CELL = 18446744073709551616
# B's byte 11 (word2) and byte 15 (word3) as cell bits, and A's byte 3 (layer).
W2_BYTE = 309485009821345068724781056
W3_BYTE = 1329227995784915872903807060280344576
LAYER_BYTE = 16777216
TYPE_SHIFT = 16777216


def setup_scheme():
    # BT[g^v] = v for v < 256; SW[s] the weight of stream bit s (byte s/8, bit 7 - s%8) in a
    # cell; WE[q] (WE7[q]) the weight of bit q of a big-endian field ending at byte 15 (7).
    ctx = HeapBuf(4)
    bt = HeapBuf(256)
    bt[1] = 0
    for v in mul_range(1, GEN ** 128):
        x = bt[v] * GEN
        bt[v * v] = x
        bt[v * v * GEN] = x + 1
    sw = HeapBuf(128)
    we = HeapBuf(64)
    we7 = HeapBuf(64)
    for k in mul_range(1, GEN ** 8):
        lo = k ** 8
        hi = (GEN ** 7 / k) ** 8
        for r in unroll(0, 8):
            sw[lo * GEN ** r] = lo * GEN ** (7 - r)
            sw[GEN ** 64 * lo * GEN ** r] = Y_CELL * lo * GEN ** (7 - r)
            we[lo * GEN ** r] = Y_CELL * hi * GEN ** r
            we7[lo * GEN ** r] = hi * GEN ** r
    ctx[1] = bt
    ctx[GEN] = sw
    ctx[GEN ** 2] = we
    ctx[GEN ** 3] = we7
    return ctx


def dot(v, n_g, w):
    # sum over k < 8 n of v[k] w[k], eight terms a loop frame.
    acc = HeapBuf(17)
    acc[1] = 0
    for b in mul_range(1, n_g):
        vb = v * b ** 8
        wb = w * b ** 8
        t = acc[b]
        for r in unroll(0, 8):
            t = t + vb[GEN ** r] * wb[GEN ** r]
        acc[b * GEN] = t
    return acc[n_g]


def bits_of(dst, cell, w):
    # 128 hinted bits (stream sl_bits), pinned boolean, whose weighted sum is cell.
    hint_witness(dst[0:128], "sl_bits")
    acc = HeapBuf(17)
    acc[1] = 0
    for b in mul_range(1, GEN ** 16):
        vb = dst * b ** 8
        wb = w * b ** 8
        t = acc[b]
        for r in unroll(0, 8):
            x = vb[GEN ** r]
            assert x * x == x
            t = t + x * wb[GEN ** r]
        acc[b * GEN] = t
    assert acc[GEN ** 16] == cell
    return


def th(seed, ad_a, ad_b, m1, c4, c5):
    # SHAKE256(seed || ADRS || m1 [|| c4]) to 16 bytes: F with (c4, c5) = (pad, 0), H with
    # (m2, pad). One Keccak-f in overwrite mode over the padded state.
    t = StackBuf(4)
    t[0] = c4
    t[1] = c5
    t[2] = 0
    t[3] = 0
    c = StackBuf(5)
    c[0] = LANE_LO_TOP
    c[1] = 0
    c[2] = 0
    c[3] = 0
    c[4] = 0
    o = StackBuf(1)
    keccak([seed, ad_a], [ad_b, m1], o, tail=t, cap=c)
    return o[0]


def shake_tl(buf, pairs_g):
    # SHAKE256 to 16 bytes of the padded cells at buf: pairs block pairs, then one block.
    chain = HeapBuf(KECCAK_STATE * 3)
    last = absorb_pairs(chain, buf, pairs_g)
    tail = buf * pairs_g ** LEAF_CHUNK
    a = StackBuf(KECCAK_STATE)
    for c in unroll(0, 9):
        a[c] = last[GEN ** c] + tail[GEN ** c]
    for c in unroll(9, KECCAK_STATE):
        a[c] = last[GEN ** c]
    o = StackBuf(1)
    permute(a, o)
    return o[0]


def fors_tree(i, ctx, seed, a0, b_fors, sb, roots):
    # Tree i's root from its secret and auth path. Its leaf index t is md bits 12i .. 12i + 11
    # (MSB first) under i's four bits; the node at height z has tree index t >> z.
    bt = ctx[1]
    we = ctx[GEN ** 2]
    fs = HeapBuf(13)
    hint_witness(fs[0:13], "sl_fors")
    fb = HeapBuf(28)
    for k in unroll(16, 28):
        fb[GEN ** k] = 0
    top = sb * i ** 12 * GEN ** 11
    for p in mul_range(1, GEN ** 12):
        fb[p] = top[1 / p]
    ib = StackBuf(4)
    hint_witness(ib, "sl_ibits")
    acc = 1
    for r in unroll(0, 4):
        b = ib[r]
        assert b * b == b
        fb[GEN ** (12 + r)] = b
        acc = acc * (1 + b * (GEN ** (2 ** r) + 1))
    assert acc == i
    nodes = HeapBuf(13)
    nodes[1] = th(seed, a0, b_fors + dot(fb, GEN ** 2, we), fs[1], SHAKE_PAD, 0)
    for z in mul_range(GEN, GEN ** 13):
        below = z / GEN
        node = nodes[below]
        sib = fs[z]
        s = (node + sib) * fb[below]
        ad_b = b_fors + bt[z] * W2_BYTE + dot(fb * z, GEN ** 2, we)
        nodes[z] = th(seed, a0, ad_b, node + s, sib + s, SHAKE_PAD)
    roots[i] = nodes[GEN ** 12]
    return


def wots_chain(v, d, seed, ad_a, b_chain, bt):
    # Chain steps d .. 14 from v, two a loop frame: 15 - d = 2 h + o.
    split = StackBuf(2)
    hint_witness(split, "sl_chain_split")
    h = split[0]
    o = split[1]
    assert o * o == o
    assert log(h) < 8
    assert h * h * (1 + o * (GEN + 1)) * d == GEN ** 15
    cv = HeapBuf(9)
    cv[1] = v
    for t in mul_range(1, h):
        s = d * t * t
        pad = StackBuf(4)
        pad[0] = SHAKE_PAD
        pad[1] = 0
        pad[2] = 0
        pad[3] = 0
        cap = StackBuf(5)
        cap[0] = LANE_LO_TOP
        cap[1] = 0
        cap[2] = 0
        cap[3] = 0
        cap[4] = 0
        x = StackBuf(1)
        keccak([seed, ad_a], [b_chain + bt[s] * W3_BYTE, cv[t]], x, tail=pad, cap=cap)
        y = StackBuf(1)
        keccak([seed, ad_a], [b_chain + bt[s * GEN] * W3_BYTE, x[0]], y, tail=pad, cap=cap)
        cv[t * GEN] = y[0]
    out = StackBuf(1)
    if o == 1:
        out[0] = th(seed, ad_a, b_chain + bt[d * h * h] * W3_BYTE, cv[h], SHAKE_PAD, 0)
    else:
        out[0] = cv[h]
    return out[0]


def ht_layer(j, ctx, seed, gb, msg):
    # Layer j's tree root from its WOTS+ signature on msg and auth path. Leaf index: bits
    # 9j .. 9j + 8 of gb (= idx_tree << 9 | idx_leaf, LSB first); tree address: bits 9j + 9 up.
    bt = ctx[1]
    sw = ctx[GEN]
    we = ctx[GEN ** 2]
    lg = gb * j ** 9
    lb = HeapBuf(25)
    for k in unroll(0, 9):
        lb[GEN ** k] = lg[GEN ** k]
    for k in unroll(9, 25):
        lb[GEN ** k] = 0
    ad_a = bt[j] * LAYER_BYTE + dot(lg * GEN ** 9, GEN ** 7, we)
    kp = dot(lb, GEN ** 2, ctx[GEN ** 3])
    # Base-16 digits of msg, MSB first, and their checksum digits.
    nb = HeapBuf(128)
    bits_of(nb, msg, sw)
    ds = HeapBuf(35)
    tot = HeapBuf(33)
    tot[1] = 1
    for c in mul_range(1, GEN ** 32):
        q = nb * c ** 4
        e = (1 + q[1] * (GEN ** 8 + 1)) * (1 + q[GEN] * (GEN ** 4 + 1))
        e = e * (1 + q[GEN ** 2] * (GEN ** 2 + 1)) * (1 + q[GEN ** 3] * (GEN + 1))
        ds[c] = e
        tot[c * GEN] = tot[c] * e
    hint_witness(ds[32:35], "sl_csum")
    for k in unroll(32, 35):
        assert log(ds[GEN ** k]) < 16
    assert tot[GEN ** 32] * ds[GEN ** 32] ** 256 * ds[GEN ** 33] ** 16 * ds[GEN ** 34] == GEN ** 480
    sig = HeapBuf(35)
    hint_witness(sig[0:35], "sl_wots")
    tl = HeapBuf(43)
    tl[1] = seed
    tl[GEN] = ad_a
    tl[GEN ** 2] = kp + const(1 * TYPE_SHIFT)
    for c in mul_range(1, GEN ** 35):
        tl[GEN ** 3 * c] = wots_chain(sig[c], ds[c], seed, ad_a, kp + bt[c] * W2_BYTE, bt)
    tl[GEN ** 38] = SHAKE_PAD
    for k in unroll(39, 42):
        tl[GEN ** k] = 0
    tl[GEN ** 42] = LANE_LO_TOP
    nodes = HeapBuf(10)
    nodes[1] = shake_tl(tl, GEN ** 2)
    auth = HeapBuf(9)
    hint_witness(auth[0:9], "sl_auth")
    for z in mul_range(GEN, GEN ** 10):
        below = z / GEN
        node = nodes[below]
        sib = auth[below]
        s = (node + sib) * lb[below]
        ad_b = const(2 * TYPE_SHIFT) + bt[z] * W2_BYTE + dot(lb * z, GEN ** 2, we)
        nodes[z] = th(seed, ad_a, ad_b, node + s, sib + s, SHAKE_PAD)
    return nodes[GEN ** 9]


def verify_claim(ctx):
    sw = ctx[GEN]
    we7 = ctx[GEN ** 3]
    r = hint_witness("sl_r")
    pk = StackBuf(2)
    hint_witness(pk, "sl_pk")
    seed = pk[0]
    root = pk[1]
    # M as 256 bits, MSB first per byte: its two cells, and M' = 0x00 0x00 || M shifted two
    # bytes into H_msg's cells 3 .. 5.
    mb = HeapBuf(256)
    m0 = StackBuf(1)
    hint_witness(m0, "sl_m0")
    m1 = StackBuf(1)
    hint_witness(m1, "sl_m1")
    bits_of(mb, m0[0], sw)
    bits_of(mb * GEN ** 128, m1[0], sw)
    claim = StackBuf(2)
    keccak_cells([CLAIM_TAG, seed, root, m0[0], m1[0]], claim)

    # H_msg = SHAKE256(R || PK.seed || PK.root || M', 30 bytes): one block.
    h = StackBuf(KECCAK_STATE)
    h[0] = r
    h[1] = seed
    h[2] = root
    h[3] = dot(mb, GEN ** 14, sw * GEN ** 16)
    h[4] = dot(mb * GEN ** 112, GEN ** 16, sw)
    h[5] = dot(mb * GEN ** 240, GEN ** 2, sw) + const(SHAKE_PAD * 65536)
    h[6] = 0
    h[7] = 0
    h[8] = LANE_LO_TOP
    for k in unroll(9, KECCAK_STATE):
        h[k] = 0
    hd = StackBuf(2)
    permute(h, hd)
    sb = HeapBuf(256)
    bits_of(sb, hd[0], sw)
    bits_of(sb * GEN ** 128, hd[1], sw)
    # gb: idx_leaf (stream bits 239 down) then idx_tree (stream bits 223 down), LSB first.
    gb = HeapBuf(119)
    for p in mul_range(1, GEN ** 9):
        gb[p] = (sb * GEN ** 239)[1 / p]
    for p in mul_range(GEN ** 9, GEN ** 63):
        gb[p] = (sb * GEN ** 232)[1 / p]
    for p in mul_range(GEN ** 63, GEN ** 119):
        gb[p] = 0

    # FORS: 14 roots into T_k's buffer.
    a0 = dot(gb * GEN ** 9, GEN ** 7, ctx[GEN ** 2])
    kp0 = dot(gb, GEN, we7) + gb[GEN ** 8] * we7[GEN ** 8]
    tk = HeapBuf(26)
    tk[1] = seed
    tk[GEN] = a0
    tk[GEN ** 2] = kp0 + const(4 * TYPE_SHIFT)
    roots = tk * GEN ** 3
    for i in mul_range(1, GEN ** 14):
        fors_tree(i, ctx, seed, a0, kp0 + const(3 * TYPE_SHIFT), sb, roots)
    tk[GEN ** 17] = SHAKE_PAD
    for k in unroll(18, 25):
        tk[GEN ** k] = 0
    tk[GEN ** 25] = LANE_LO_TOP

    # Hypertree: layer j signs what layer j - 1 produced.
    signed = HeapBuf(8)
    signed[1] = shake_tl(tk, GEN)
    for j in mul_range(1, GEN ** 7):
        signed[j * GEN] = ht_layer(j, ctx, seed, gb, signed[j])
    assert signed[GEN ** 7] == root
    return claim[0], claim[1]
