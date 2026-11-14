# Batched generic proof dependencies in the leanVM guest

Batched Generic Proof Dependencies ([ethereum/EIPs#12664](https://github.com/ethereum/EIPs/pull/12664) at `34ef363a`)
enables EIP-8288's `LEANSTARK_SCHEME` and lets one leaf prove claims for many transactions. Both EIPs specify
statements and leave their encoding to the proof system. This note covers how `lean_ethereum.py` and its host
(`src/aggregation`) realise them, and what of #12664 they do not yet.

## Two guests

The C ABI (version 17) selects the guest with a leading `u32` argument on `nlean_limits`, `nlean_aggregated_vk`,
`nlean_verify_leanstark`, `nlean_verify_recursive` and `nlean_prove_recursive`. The key a caller passes must be that
guest's key. A consumer maps its fork's `AGGREGATED_VK` to a guest.

- Guest 0 is EIP-8288's guest and host exactly as the ABI 12 package 0.12.1 ships them (leanSPHINCS keys laid out
  `PK.seed ‖ PK.root`), vendored unchanged as `crates/rec_aggregation_base`. Its key (`f6f37690…`), its limits (16
  recursive inputs per step, 16 leanSTARK dependencies per list), its direct leanSTARK statement (the bare claim), its
  split dependency digest and its aggregation input encoding are that package's, so a chain without #12664 is
  unaffected by this crate.
- Guest 1 compiles this crate's `lean_ethereum.py` (`Guest::Batched`): leaves of up to 256 claims, the scheme-bearing
  dependency digest and `get_vk_hash` keys. The crate's `Guest::Base` placeholders (`MAX_CLAIMS_PER_BATCH_LEAF = 1`)
  remain for its own tests only; the ABI does not expose them.

## Dependency digest

`get_deps_hash` is `keccak256` of the canonical 96-byte triples `scheme word ‖ data_hash ‖ key`, every statement's and
every child's. The guest keeps one coverage region per scheme, its declared claims then its duplicate slots, so each
writer is range-checked into its own scheme. It copies each region's declared entries behind their scheme word into one
list, leanSPHINCS (`0x10`) first as the triples sort, and hashes that list 17 triples (102 cells, six block pairs) a
loop frame through a sponge-state chain (`deps_list_digest`). A child's claims are collected the same way, read at
hinted offsets into this node's tables, then hashed with the same function. The scheme word in the preimage is what
makes a published triple's scheme the scheme that verified it.

## Leaves and keys

A leaf's statement is `get_batch_hash(claims) = keccak256(b"EIP8288:batch:v1" ‖ claims)` over 1 to 256 strictly
increasing claims, `get_claim_hash` for one. It is hashed in 17-cell (272-byte) block-pair chunks carried through a
sponge-state chain, followed by a remainder of up to 16 cells (`leaf_digest`). Claim bytes are hinted in the exponent
and range-checked; order is decided at the first differing byte (`batch_increasing`). Each claim establishes
`(0x11, claim, key)`; a node publishes any subset.

The key is `get_vk_hash(program_commitment) = keccak256(b"EIP8288:vk:v1" ‖ program_commitment)`
(`check_vk_hash`). The guest rehashes the hinted `kgen`, root and `ood` into the commitment, re-cuts its range-checked
bytes three bytes on behind the 13-byte tag, checks the result is the claim's key, and seeds the leaf proof's transcript
with the commitment.

## Step arity

Measured with the committed bytecode key (`../EIP8288-PROFILE.md`) and near-cap programs (2^11 instructions) under
distinct keys, at rate 1/2 on a 12-core, 32 GB machine (`examples/agg_bench.rs batch 16`, `children 16`):

| Step | Cycles | Committed witness | Prove |
| --- | --- | --- | --- |
| 1 leaf of 256 claims | 0.47M | 2^23.8 | 0.30 s |
| 16 leaves of 256 claims | 7.0M | 2^27.6 | 6.1 s |
| 8 leaves and 8 children of 256 claims | 5.6M | 2^27.3 | 4.5 s |
| 16 children | 3.4M | 2^26.8 | 2.1 s |

`MAX_INNER_PROOFS_PER_STEP` is therefore 16, as #12664 sets it, leaving about 2^2.4 of the outer proof's 2^30 bound for
the leanSPHINCS signatures a step may add. Under the earlier flat key, which rehashed the whole
table in every leaf (2.96M cycles a leaf), 14 leaves exceeded 2^30 and the arity was 12.

## Against #12664 at `34ef363a`

Implemented: `LEANSTARK_SCHEME` with multi-claim leaves (`MAX_CLAIMS_PER_BATCH_LEAF = 256`) and their claim-order,
width and count checks before hashing; a direct leanSTARK witness as a one-claim leaf, so a proof of the bare claim
satisfies nothing; the scheme-bearing 96-byte-triple `get_deps_hash` for every statement; `get_vk_hash` keys over an
openable program commitment (below); and `MAX_INNER_PROOFS_PER_STEP = 16`, counting discarded and redundant inputs, with
each direct witness counted as one by the ABI. Recursive statements stay EIP-8288's `(get_deps_hash(deps),
AGGREGATED_VK)`.

Not yet:

- Output capacity of at least `MAX_DEPS_PER_BLOCK` (16,384) dependencies, with counters that never narrow (the
  65,535- and 65,536-entry test lengths). The ABI bounds a statement at 256 dependencies.
- The finalized resource bounds and the joint benchmarks the activation requirements name; the values here are this
  prototype's.

## Program commitments and adversarial keys

#12664 makes the leanSTARK verification key name a `program_commitment` that binds at most one complete program and
layout even when chosen adversarially, supports sound openings of the program-table evaluations verification needs,
and authenticates them inside recursion at cost sublinear in the padded program size. Guest 1 commits to a program by
the committed bytecode key of `../EIP8288-PROFILE.md`: a WHIR commitment to the stacked table and an out-of-domain value
drawn from it, opened by each proof at the bus's point and the out-of-domain point, at a cost independent of the
program's size. The core changes it needs are patched in from Marchhill/leanVM `feature/eip8288-bytecode-commitment`
until they are upstream. Guest 0 keeps the flat digest `keccak256("leanvm-v1" ‖ table)` unchanged.
