# Vendored leanVM crates

`aggregation` and `../guests/lean_ethereum.py` derive from [leanEthereum/leanVM](https://github.com/leanEthereum/leanVM)
at the revision `../Cargo.toml` pins for every other leanVM crate (`crates/aggregation`, `guests/lean_ethereum.py`).
Upstream licenses them under MIT or Apache-2.0 (`aggregation/LICENSE-MIT`, `aggregation/LICENSE-APACHE`). Everything
else, `lean_sphincs` included, stays an unmodified git dependency, proving on upstream's stable prover.

Changes against upstream, all EIP-8288 specific:

- The statement commits to the EIP-8288 dependency digest with Keccak-256 (`deps_hash`): leanSPHINCS (`0x10`) claims
  are `(data_hash, PK.seed ‖ PK.root)`, and the leanXMSS list is replaced by leanSTARK (`0x11`) claims, leanVM
  execution proofs of programs up to 2^11 instructions (`src/generic.rs`), under the `eip8288/leanstark-deps` domain.
- The guest drops the leanXMSS verifier and verifies proofs of any bytecode size (`KBC_SRC`, `FINAL_PC_COORD`).

`crates/upstream.sh diff` prints every change against upstream at the pinned revision; `crates/upstream.sh update <rev>`
moves the vendored files and the pin to a newer upstream revision by three-way merge and lists what needs review. After
an update, run the workspace tests and `fixtures`, and when `AGGREGATED_VK` changes, bump the package version and the
consumers' pinned key together.

Every change to the guest changes `AGGREGATED_VK`; `../examples/fixtures.rs` prints it, `aggregated_vk_is_pinned` pins
it, and the native tests check it against `Eip8288Constants.AggregatedVk`.
