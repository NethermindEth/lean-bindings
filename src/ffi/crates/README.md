# Vendored leanVM crates

`rec_aggregation` and `lean_sphincs` derive from [leanEthereum/leanVM](https://github.com/leanEthereum/leanVM) at
`f7ba4999ae523b94c8d0969b32762c3effea4cbd`, the revision `../Cargo.toml` pins for every other leanVM crate. Upstream
licenses them under MIT or Apache-2.0 (each crate's `LICENSE-MIT`, `LICENSE-APACHE`). The core (`leanvm_core`, `verifier`,
`lean_compiler`, `fiat_shamir`, `pcs`, `primitives`) stays a git dependency at that revision, patched in `../Cargo.toml`
to the committed bytecode key's core changes on top of it until they are upstream.

Changes against upstream, all EIP-8288 specific:

- `lean_sphincs`: NiceTry v2 (SPHINCS- v2) parameters and encoding, the wallet's signature scheme, in place of upstream's
  leanSPHINCS, with the public key `PK.seed ‖ PK.root`. Upstream's tests and known-answer vectors are for its own scheme
  and are not vendored; the crate checks NiceTry's reference vector instead. leanXMSS is upstream's `lean_xmss`, unvendored.
- `rec_aggregation`: the aggregation guest (`guests/lean_ethereum.py`) commits to the EIP-8288 dependency digest with
  Keccak-256, verifies NiceTry v2 signatures (scheme `0x10`) and leanVM execution proofs of programs up to 2^11
  instructions as EIP-8288 one-claim leaves (scheme `0x11`, `src/aggregation/generic.rs`), and merges or discards child
  aggregates. It is the batched guest's crate, compiled as its `Guest::Base`: the scheme-bearing 96-byte-triple
  dependency digest, leaves keyed by `get_vk_hash` of a committed bytecode key and proving `get_claim_hash(data_hash)`,
  and `MAX_INNER_PROOFS_PER_STEP` counting leaves and children together.
  [`rec_aggregation/EIP8288-PROFILE.md`](rec_aggregation/EIP8288-PROFILE.md) specifies that key, the witness and the
  proof encoding; [`rec_aggregation/guests/BATCHING.md`](rec_aggregation/guests/BATCHING.md) describes what the guest
  decides that the EIPs leave to the proof system.

`crates/upstream.sh diff` prints every change against upstream at the pinned revision; `crates/upstream.sh update <rev>`
moves the crates and the pin to a newer upstream revision by three-way merge and lists what needs review. After an
update, run the workspace tests and `fixtures`, and when `AGGREGATED_VK` changes, bump the package version and the
consumers' pinned key together.

Every change to a guest changes `AGGREGATED_VK`; `../examples/fixtures.rs` prints it and the native tests check it
against `Eip8288Constants.AggregatedVk`.
