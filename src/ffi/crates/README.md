# Vendored leanVM crates

`rec_aggregation` derives from [leanEthereum/leanVM](https://github.com/leanEthereum/leanVM) at
`f7ba4999ae523b94c8d0969b32762c3effea4cbd`, the revision `../Cargo.toml` pins for every other leanVM crate. Upstream
licenses it under MIT or Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`). The core (`leanvm_core`, `verifier`,
`lean_compiler`, `fiat_shamir`, `pcs`, `primitives`) and `lean_sphincs` stay unmodified git dependencies.

Changes against upstream, all EIP-8288 specific:

- `rec_aggregation`: the aggregation guest (`guests/lean_ethereum.py`) commits to the EIP-8288 dependency digest with
  Keccak-256, verifies upstream leanSPHINCS signatures (scheme `0x10`) and leanVM execution proofs of programs up to 2^11
  instructions (scheme `0x11`, `src/aggregation/generic.rs`), and merges or discards child aggregates.

`crates/upstream.sh diff` prints every change against upstream at the pinned revision; `crates/upstream.sh update <rev>`
moves the crates and the pin to a newer upstream revision by three-way merge and lists what needs review. After an
update, run the workspace tests and `fixtures`, and when `AGGREGATED_VK` changes, bump the package version and the
consumers' pinned key together.

Every change to a guest changes `AGGREGATED_VK`; `../examples/fixtures.rs` prints it and the native tests check it
against `Eip8288Constants.AggregatedVk`.
