# Vendored leanVM crates

`rec_aggregation` and `signatures` derive from [leanEthereum/leanVM](https://github.com/leanEthereum/leanVM) at
`e4dcb8d5436c9bf76398d890c57c59613af12956`, the revision `../Cargo.toml` pins for every other leanVM crate. Upstream
licenses them under MIT or Apache-2.0 (each crate's `LICENSE-MIT`, `LICENSE-APACHE`). The core (`leanvm_core`, `verifier`,
`lean_compiler`, `fiat_shamir`, `pcs`, `primitives`) stays an unmodified git dependency.

Changes against upstream, all EIP-8288 specific:

- `signatures::lean_sphincs`: NiceTry v2 (SPHINCS- v2) parameters and encoding, the wallet's signature scheme. The vendored
  copy drops leanXMSS; test-only mock signers come from the upstream crate.
- `rec_aggregation`: the aggregation guest (`guests/lean_ethereum.py`) commits to the EIP-8288 dependency digest with
  Keccak-256, verifies NiceTry v2 signatures (scheme `0x10`) and leanVM execution proofs of programs up to 2^11
  instructions as EIP-8288 batch leaves (scheme `0x11`, `src/aggregation/generic.rs`), and merges or discards child
  aggregates.

`crates/upstream.sh diff` prints every change against upstream at the pinned revision; `crates/upstream.sh update <rev>`
moves the crates and the pin to a newer upstream revision by three-way merge and lists what needs review. After an
update, run the workspace tests and `fixtures`, and when `AGGREGATED_VK` changes, bump the package version and the
consumers' pinned key together.

Every change to a guest changes `AGGREGATED_VK`; `../examples/fixtures.rs` prints it and the native tests check it
against `Eip8288Constants.AggregatedVk`.
