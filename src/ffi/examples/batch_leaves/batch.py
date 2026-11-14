# An EIP-8288 batch leaf template: it publishes get_batch_hash(claims) =
# keccak256(BATCH_DOMAIN | claims) over 1 to MAX_CLAIMS hinted 32-byte claims, each as two
# 16-byte cells. A real leaf derives each claim from a check it makes, a signature over the
# claim say; this one takes them as given, so it authenticates nothing and only shows the
# statement's shape. The claims' order is the aggregation guest's to check.
MAX_CLAIMS = MAX_CLAIMS_PLACEHOLDER
CLAIM_CELLS = 2 * MAX_CLAIMS
PRE_CELLS = 1 + CLAIM_CELLS
BATCH_DOMAIN = BATCH_DOMAIN_PLACEHOLDER


def digest(claims, last: Const):
    pre = StackBuf(PRE_CELLS)
    pre[0] = BATCH_DOMAIN
    for i in unroll(0, 2 * last + 2):
        pre[1 + i] = claims[GEN ** i]
    out = StackBuf(2)
    keccak_cells(pre[0:3 + 2 * last], out)
    return out[0], out[1]


def main():
    last = hint_witness("last_claim")  # g^(claims - 1)
    assert log(last) < MAX_CLAIMS
    claims = HeapBuf(CLAIM_CELLS)
    hint_witness(claims[0:CLAIM_CELLS], "claims")
    d0, d1 = match(log(last), range(0, MAX_CLAIMS), lambda k: digest(claims, k))
    p = GEN ** 0
    p[1] = d0
    p[GEN] = d1
    return
