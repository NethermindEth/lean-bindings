# leanSTARK EIP-8288 profile v1

This is the proof-system specification that Generic Proof Verification and Batching
([EIPs#12664](https://github.com/ethereum/EIPs/pull/12664), which absorbed EIPs#12654) leaves to "the fork's pinned
proof-system specification" for the leanSTARK schemes (`0x11`, `0x12`, `0x13`). The EIP pins it by repository and
commit. It covers the leanVM CPU proof of a leaf as implemented by this crate's aggregation guest, guest 1 of the C ABI
(`Guest::Batched`; `guests/lean_ethereum.py`, `src/aggregation/generic.rs`), and by the leanVM core revision
`../../Cargo.toml` takes. Guest 0, EIP-8288's guest in `../rec_aggregation_base`, keeps the flat table key and is not
covered. Any change to a value in this document changes guest 1's `AGGREGATED_VK` and the profile version.

## 1. Fixed parameters

All of these are fixed. No key overrides any of them.

| parameter | value |
|---|---|
| base field `K` | `GF(2)[x]/(x^64 + x^4 + x^3 + x + 1)` |
| extension `E` | `K[y]/(y^3 + y + 1)`; an element is `c0 + c1·y + c2·y²`, limbs `c0, c1, c2` |
| hash | Keccak-256, for keys, Merkle trees and the duplex sponge (Keccak-f[1600], rate lanes 0..16) |
| program size | `2^kgen` instructions, `kgen ≤ 11` (`MAX_GENERIC_BYTECODE_LOG`); table `16·2^kgen` words |
| bytecode commitment | the table zero-padded to a stack of `2^16` words (`MIN_STACKED_LOG`), one size for every `kgen` |
| commitment rate | `1/16` (`COMMITTED_BYTECODE_LOG_INV_RATE = 4`) |
| opening | WHIR, folds 6, 4, 4; queries 56, 32, 22; 17 grinding bits before each level's queries |
| soundness target | 128-bit round-by-round, Johnson list decoding with η chosen per level (level 0: η ≈ 0.0032) |
| out-of-domain samples on the commitment | 1 (§5) |

The execution proof itself uses upstream leanVM's parameters at the PCS rate it announces. The guest admits rates
`2^-1 .. 2^-4`.

## 2. Key derivation and encodings

```
program_commitment = keccak256(COMMITTED_TAG || u8 kgen || root || ood)          # 80-byte preimage, 32 bytes out
verification_key_hash = get_vk_hash(program_commitment)                          # EIPs#12664
```

Guest 1 does not apply `get_vk_hash` yet: a dependency's `verification_key_hash` is `program_commitment` itself
(`guests/BATCH_PRICING.md` lists this with the other parts of #12664 still to come).

- `COMMITTED_TAG = "leanvm-commit-1"` (15 bytes). With `kgen`, it fills one 16-byte cell. Its first bytes differ from
  upstream's table-digest tag `"leanvm-v1"`, so the two kinds of key never share a transcript.
- `root` (32 bytes) is the Merkle root of the WHIR commitment to the stack: upstream `bytecode_table` words as `K`
  elements, zero past the table, encoded at rate 1/16. KeyGen is deterministic, so a table has exactly one honest
  `root`.
- `ood_point ∈ E^16` comes from the root alone. A duplex sponge is seeded with IV `root` and public input
  `OOD_TAG || u8 kgen || 0^16`, where `OOD_TAG = "leanvm-ood-pt-1"` (15 bytes). The sponge then draws 16 challenges,
  each permuting with an empty rate and reading lanes 0..2 as `c0, c1, c2`. The value is not involved, so the point
  is fixed before it.
- `ood_value = T̃(ood_point)`, where `T̃` is the stack's multilinear extension in LSB-first variable order (stack
  index bit `j` is coordinate `j`).
- `ood` is two 16-byte cells `a ‖ b` with `ood_value = a + y²·b`, where a cell's bytes are two little-endian `u64`
  limbs `c0, c1`. KeyGen writes `c0 ‖ c1 ‖ c2 ‖ 0^8`. Verifiers decode any pair as `a + y²·b`, so the native verifier
  and the guest accept the same keys.
- `program_commitment` is also the proof's Fiat-Shamir IV.

## 3. Witness and proof encoding

- Witness: `u8 kgen ‖ root (32) ‖ ood (32) ‖ proof`. The statement is the leaf's `get_batch_hash(claims)`, for a
  direct dependency on `data_hash` the singleton `get_claim_hash(data_hash) = get_batch_hash([data_hash])`, as the
  32-byte public input in two 16-byte cells.
- `proof` is upstream leanVM's `Proof::to_bytes`, with every count a little-endian `u32` and every word a
  little-endian `u64`:
  - the scalar stream: its length, then each element as three words;
  - the number of Merkle phases, then each phase pruned: query positions, height, leaf and row width, distinct
    leaves, and the siblings no other path supplies.
- A committed proof has the execution opening's phases (at most 6) and then the bytecode opening's 3. The decoder
  admits at most `MAX_PHASES = 9` phases, 256 queries per phase, 64 leaf words and height 32. Decoding rejects
  anything else and any trailing byte.
- The bytecode opening adds 46–60 KB to a proof. The witness no longer carries the table (`2^(kgen+7)` bytes). The OOD
  binding adds no phase and no proof byte: its claim is batched into the same opening.

## 4. Commitment, transcript binding and opening verification

1. The transcript is seeded with IV `program_commitment` and the public input, so `kgen`, `root` and `ood` are fixed
   before the first challenge.
2. The proof runs as upstream's table mode up to the bus GKR. A table-mode verifier would evaluate the table at the
   bus point `(ζ[..kgen+4], α)` itself. Instead, the prover sends `v`, which is absorbed alone and followed by one
   discarded challenge. Every later word therefore keeps its sponge position from table mode, and `v` is bound
   before any challenge that depends on it.
3. After the execution's own opening, the proof opens `root` in one WHIR run over two claims, batched with powers of
   one challenge `λ`:
   - `eq((ζ[..kgen+4], α, 0, …, 0), ·) ↦ v`, the bus point with its high stack coordinates zero;
   - `eq(ood_point, ·) ↦ ood_value`.

   The target is `v + λ·ood_value`, and the terminal weight is the same combination of the two `eq` weights.
4. The guest mirrors this. It rehashes the hinted `kgen`, `root` and `ood` into the claim's key and verifies the
   sub-proof in committed mode. It then derives `ood_point` with the same sponge and checks the opening with the same
   `open_stacked` arm as the execution opening, at the fixed 2^16 stack and rate 1/16. Its cost does not depend on
   `kgen`. KECCAK rejects a cell with a nonzero top limb, so `root` and `ood` cells are canonical.

## 5. Soundness against adversarial keys

EIP-8288 requires a key to bind at most one complete program and layout even when an adversary generates it.

- Level 0 of the opening is in the Johnson list-decoding regime. A `root` that no honest KeyGen produced can be
  within the decoding radius of a list of up to `L = 1/(2η√ρ)` codewords. Here `log₂ L ≈ 9.29` at rate 1/16, 2^16
  words, η ≈ 0.0032. Without more binding, such a root could open as either of two tables.
- The key fixes `ood_value` at a point drawn from `root` after it is fixed. Two distinct 16-variate multilinears agree
  at a uniformly random point of `E^16` with probability at most `μ/|E| = 16/2^192`. Over all pairs in the list, the
  key leaves more than one candidate with probability at most `L²·μ/(2|E|)`.
- For `s` samples this is the PCS's own `paper_ood_bits` bound, `s·(192 − log₂ μ) − (2·log₂ L − 1)`. One sample
  gives `188 − 17.6 ≈ 170` bits, above the 128-bit target with margin for grinding roots.
- Given one candidate, WHIR's 128-bit RBR soundness makes `v` the evaluation of that table at a point drawn after the
  key. The bus argument then binds the execution to that table.
- A different table gives a different codeword, so a different `root` (Merkle collision resistance) and a different
  `program_commitment` (Keccak collision resistance).
- The Lean formalization (`formal/` upstream) covers table mode only. It does not cover committed mode.

## 6. Resource bounds

- Program: at most 2048 instructions, including compiler-generated code and padding (`kgen ≤ 11`).
- Commitment stack: `2^16` words for every admitted `kgen`. The guest asserts this at compile time.
- Inner execution proof: the guest's fixed capacities bound it. These are 40 GKR layers per bus side (`MU_CAP`), a
  scalar stream of at most 8192 elements (`STREAM_CAP`), and the stacked sizes and rates the guest compiles arms for.
  The native check builds the guest's hints, so it rejects any proof outside them.
- Bytes: a witness is at most 8 MiB (`MAX_BYTES`), and aggregation input is at most 18 MiB.
- A leaf holds 1 to 256 strictly increasing claims (`MAX_CLAIMS_PER_BATCH_LEAF`); a step verifies at most 16 leaves
  and children together (`MAX_INNER_PROOFS_PER_STEP`, `guests/BATCH_PRICING.md`).

## 7. One construction for every size

A flat hash of the table is cheaper only for very small programs. On this guest, a 16-instruction program's leaf is
217,447 cycles with a flat key and 243,954 with the committed key. A 2^11-instruction leaf is 2,720,622 against
245,915. The crossover is about 38 instructions, and below it the flat key saves at most about 3% of a leaf. That
saving does not justify a second key format, verifier path and set of vectors, so every program is keyed by its
commitment.

## 8. Key-hash and key-opening consistency vectors

`examples/fixtures.rs` emits these into the fixture directory (packaged as `lean-vectors/`) for the accept-all
program `ANY_INPUT_PROGRAM` with the claim `data_hash = 0x09…09`, proved on `get_claim_hash(data_hash)`:

- `stark-key-hash-vectors.txt`: the table, `kgen`, `root`, every `ood_point` coordinate, `ood`, `program_commitment`
  and `vk_hash`. An implementation checks that it derives each value from the one before.
- `stark-batched-key.bin`, `stark-message.bin`, `stark-claim-proof.bin`: the honest `program_commitment`, claim and
  witness. These must verify. (`stark-key.bin` and `stark-proof.bin` are guest 0's flat-keyed pair.)
- `stark-key-opening-wrong-ood.bin` and `stark-key-opening-wrong-root.bin`: `program_commitment ‖ witness` with `ood`
  or `root` tampered and the commitment recomputed over it. These must be rejected.
- The case where a proof is made under a key with a wrong `ood` is in `src/aggregation/generic_tests.rs`
  (`a_key_must_carry_the_tables_out_of_domain_value`). There, only the opening's OOD claim can reject the proof. It
  needs a prover switch that the shipped library does not build with.
