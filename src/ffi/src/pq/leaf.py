# An EIP-8288 batch leaf over signatures: one claim per verified signature, published as
# get_batch_hash(claims) = keccak256(BATCH_DOMAIN | claims) for 1 to MAX_CLAIMS claims. The
# claim count is a hint, so one program (one key) serves every batch size. The scheme's
# source, prepended by the host, defines setup_scheme() and verify_claim(ctx), which returns
# the claim's two cells after verifying a signature over it. The claims' order is the
# aggregation guest's to check.
BATCH_DOMAIN = BATCH_DOMAIN_PLACEHOLDER
MAX_CLAIMS = MAX_CLAIMS_PLACEHOLDER
LEAF_CHUNK = 17
KECCAK_STATE = 13
# 0x80 as the last byte of a cell's low lane, and of its high lane.
LANE_LO_TOP = 9223372036854775808
LANE_HI_TOP = 170141183460469231731687303715884105728


@inline
def permute(a, out):
    # Keccak-f[1600] of the 13-cell state a, no padding: lanes 2c, 2c + 1 in cell c < 8, lane 16
    # alone in cell 8, lanes 17 .. 24 two a cell in cells 9 .. 12.
    keccak(a[0:2], a[2:4], out, tail=a[4:8], cap=a)
    return


def main():
    n = hint_witness("n_claims")
    assert log(n) < MAX_CLAIMS + 1
    assert n != 1
    ctx = setup_scheme()
    pre = HeapBuf(LEAF_CHUNK * 31)
    pre[1] = BATCH_DOMAIN
    for i in mul_range(1, n):
        c0, c1 = verify_claim(ctx)
        at = pre * GEN * i * i
        at[1] = c0
        at[GEN] = c1
    d0, d1 = leaf_digest(pre, n)
    p = GEN ** 0
    p[1] = d0
    p[GEN] = d1
    return


def leaf_digest(pre, n_g):
    # keccak256 of the L = 1 + 2N cells at pre.
    d = HeapBuf(4)
    padded_hash(pre, GEN * n_g ** 2, 1, 1, d)
    return d[1], d[GEN]


def padded_hash(buf, q, r, first, out):
    # Writes to out the first four cells of the Keccak state after absorbing, from zero, the
    # Q = log(q) cells at buf, then the cell first: a message's last r < 16 bytes with the
    # padding's first byte after them. The rest of pad10*1 is written after it, then the padded
    # message is absorbed a block pair (LEAF_CHUNK cells) a loop frame through a heap chain of
    # sponge states, and an odd last block alone. Q = 17 chunks + t, hinted: the last block is
    # lone (odd) exactly when the padding's first byte, 16 t + r into the last chunk, falls in
    # its first block.
    split = StackBuf(3)
    hint_witness(split, "hash_split")
    chunks = split[0]
    t = split[1]
    odd = split[2]
    assert log(chunks) < 32
    assert log(t) < LEAF_CHUNK
    base = chunks ** LEAF_CHUNK
    assert base * t == q
    tail = buf * base
    pos = t ** 16 * r
    pairs = StackBuf(1)
    if odd == 1:
        assert log(pos) < 136
        pad_tail(tail, t, first, GEN ** 8, LANE_LO_TOP)
        pairs[0] = chunks
    else:
        assert log(pos / GEN ** 136) < 136
        pad_tail(tail, t, first, GEN ** 16, LANE_HI_TOP)
        pairs[0] = chunks * GEN
    chain = HeapBuf(KECCAK_STATE * 33)
    last = absorb_pairs(chain, buf, pairs[0])
    if odd == 1:
        a = StackBuf(KECCAK_STATE)
        for c in unroll(0, 9):
            a[c] = last[GEN ** c] + tail[GEN ** c]
        for c in unroll(9, KECCAK_STATE):
            a[c] = last[GEN ** c]
        o = StackBuf(KECCAK_STATE)
        permute(a, o)
        for c in unroll(0, 4):
            out[GEN ** c] = o[c]
    else:
        for c in unroll(0, 4):
            out[GEN ** c] = last[GEN ** c]
    return


def absorb_pairs(chain, buf, pairs_g):
    # The Keccak state after absorbing, from zero, the block pairs (LEAF_CHUNK cells each) at
    # buf, padding included; chain holds the states, 13 cells each.
    for k in unroll(0, KECCAK_STATE):
        chain[GEN ** k] = 0
    for xq in mul_range(1, pairs_g):
        st = chain * xq ** KECCAK_STATE
        nxt = st * GEN ** KECCAK_STATE
        blk = buf * xq ** LEAF_CHUNK
        keccak_cells(blk[0:LEAF_CHUNK], nxt[0:KECCAK_STATE], state=st[0:KECCAK_STATE], final=0)
    return chain * pairs_g ** KECCAK_STATE


def pad_tail(tail, rest, first, end, top):
    # Keccak's pad10*1 from cell rest to cell end: first, which holds the padding's first byte,
    # in cell rest, top (0x80 in the block's last byte) in cell end, zeros between.
    if rest == end:
        tail[end] = top + first
    else:
        tail[rest] = first
        for k in mul_range(GEN, end / rest):
            tail[rest * k] = 0
        tail[end] = top
    return
