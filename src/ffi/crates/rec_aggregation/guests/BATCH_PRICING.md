# Batch pricing in the leanVM guest

Generic Proof Verification and Batching ([ethereum/EIPs#12664](https://github.com/ethereum/EIPs/pull/12664), which
absorbed the EIP-8288 amendments of the closed #12654) builds on EIP-8288. Both specify statements and leave their
encoding to the proof system. This note covers how `lean_ethereum.py` and its host (`src/aggregation`) realise them, and
what of #12664 at `0cbf1366` they do not yet.

## Two guests

The C ABI (version 15) selects the guest with a leading `u32` argument on `nlean_limits`, `nlean_aggregated_vk`,
`nlean_verify_recursive` and `nlean_prove_recursive`. The key a caller passes must be that guest's key. A consumer maps
its fork's `AGGREGATED_VK` to a guest.

- Guest 0 is EIP-8288's guest and host exactly as the ABI 12 package ships them, vendored unchanged as
  `crates/rec_aggregation_base`. Its key (`f7cf7458…`), its limits (16 inner proofs per step, 16 leanSTARK
  dependencies per list) and its aggregation input encoding are that package's, so a chain without batch pricing is
  unaffected by this crate.
- Guest 1 compiles this crate's `lean_ethereum.py` (`Guest::Batched`): leaves of up to 256 claims and both new schemes.
  The crate's `Guest::Base` placeholders (`MAX_CLAIMS_PER_BATCH_LEAF = 1`, `BATCHED_DEPENDENCIES = 0`) remain for its own
  tests only; the ABI no longer exposes them.

## Leanstark list entries

Each leanSTARK list entry is 64 bytes, `data ‖ key`. The key depends on the scheme:

| Scheme | Data | Key |
| --- | --- | --- |
| `0x11` | claim | `vk` |
| `0x12`, intermediate | claim | `keccak256(word(0x12) ‖ vk ‖ source)` |
| `0x12`, finalized | claim | `keccak256(word(0x12) ‖ vk)` |
| `0x13` | leaf digest | `keccak256(word(0x13) ‖ vk)` |

- `word(s)` is the 32-byte scheme word.
- `source` is the leaf's `get_batch_hash(claims)`.
- An intermediate `0x12` entry is the EIP's `(dependency, source)` record. Only a leaf derives its key (`establish`), so a
  union cannot create a source and pruning cannot change one. Changing a source needs another verified leaf.
- These keys replace the EIP's 192-byte `get_batch_state_hash` records. Intermediate statements therefore share the plain
  digest form, and the scheme-bound keys keep them apart from ordinary lists.
- The host keeps one record per dependency, preferring a source whose payment is retained. The guest does not reject two
  sources for one claim; finalization's bijection does.

## Finalization as a node mode

Any node may finalize; the `final` hint selects it. A finalizing node maps its declared list one-to-one onto a finalized
list:

- Each `0x12` entry is checked against its hinted `(vk, source)` and rekeyed to the finalized key, once its payment
  `(source, keccak256(word(0x13) ‖ vk))` is found in the node's own list.
- Every other entry is copied unchanged.

The node publishes `get_batch_final_hash(deps_hash) = keccak256("EIP8288:batch-final:v1" ‖ deps_hash)` over the
finalized lists' plain digest:

- The guest re-cuts the digest's bytes six bytes on, behind the 22-byte tag (`batch_final_hash`).
- Child statements are always rebuilt in the plain form, so a finalized proof is never a child, payment-only ones
  included.
- Payment presence is checked only here, so an intermediate proof may hold claims without their payments.

## Claim hashing

A leaf's statement is hashed in 17-cell (272-byte) block-pair chunks carried through a sponge-state chain, followed by
a remainder of up to 16 cells (`leaf_digest`). The cost is linear in the claim count, with no 256-arm unrolled match.

Claim bytes are hinted in the exponent and range-checked. Order is decided at the first differing byte
(`batch_increasing`).

## Step arity

Measured with the flat program key and near-cap programs (2^11 instructions), every claim sponsored and the step
finalized:

| Step | Cycles | Committed witness | Result |
| --- | --- | --- | --- |
| 1 leaf of 256 claims | 2.96M | 2^26.2 | fits |
| 12 leaves of 256 claims | 34.9M | 2^29.8 | fits (~22 GB peak) |
| 13 leaves of 256 claims | 37.8M | 2^29.8 | fits |
| 14 leaves, any claim count | — | over 2^30 | fails |
| 16 leaves, even 1 claim each | — | over 2^30 | fails |
| 16 children | 3.5M | — | fits |

`MAX_INNER_PROOFS_PER_STEP` is therefore provisionally 12, leaving room for the leanSPHINCS signatures a step may add.
A different program-commitment construction changes these numbers.

## Against #12664 at `0cbf1366`

Implemented: batch leaves with exact, strictly increasing claim lists, a direct leanSTARK witness as a one-claim leaf
(`get_claim_hash(claim) = get_batch_hash([claim])`), payment binding through intermediate records, and finalization.

Not yet, each needing a new `AGGREGATED_VK`:

- The replaced dependency digest: `get_deps_hash` over canonical 96-byte triples, scheme word included, in place of the
  split leanSPHINCS/leanSTARK lists and the scheme-bound keys above. It also makes scheme separation structural.
- The tagged statement domains: `DEPS_HASH(b"EIP8288:aggregate:v1" ‖ tag ‖ payload)` with tags 0x00 (ordinary, over
  `deps_hash`), 0x01 (intermediate, over the 192-byte records) and 0x02 (finalized). Today ordinary statements are the
  plain digest and finalization uses the `EIP8288:batch-final:v1` tag.
- `get_vk_hash(program_commitment) = keccak256(b"EIP8288:vk:v1" ‖ program_commitment)`.
- `MAX_INNER_PROOFS_PER_STEP = 16`, counting direct inputs across wrappers and discarded or redundant proofs. The arity
  table above fails 14 leaves under the flat key, so 16 depends on the commitment construction.
- Output capacity of at least `MAX_RLP_BLOCK_SIZE // 96` dependencies, with counters that never narrow (65,535 and
  65,536 test lengths). The guest's lists are bounded at 256 today.

## Program commitments and adversarial keys

#12664 makes the leanSTARK verification key a `program_commitment` that binds at most one complete program and layout even
when the key is chosen adversarially, supports sound openings of the program-table evaluations verification needs, and
authenticates them inside recursion at cost sublinear in the padded program size. The flat digest
`keccak256("leanvm-v1" ‖ table)` used here binds the table only by rehashing all of it, so it meets none of the opening
requirements. NethermindEth/lean-bindings#10 prototypes an openable bytecode commitment as the key; this crate takes it
when that lands.
