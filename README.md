# lean-bindings

[![Test / Publish](https://github.com/NethermindEth/lean-bindings/actions/workflows/test-publish.yml/badge.svg)](https://github.com/NethermindEth/lean-bindings/actions/workflows/test-publish.yml)

Native EIP-8288 Lean backend for [Nethermind](https://github.com/NethermindEth/nethermind), packaged for NuGet as `Nethermind.Crypto.Lean`.

The library, `libnethermind_lean.so`, is built from [`tools/lean-ffi`](https://github.com/NethermindEth/nethermind/tree/master/tools/lean-ffi) in the Nethermind repository, which stays its canonical source. This repository only builds, tests and publishes it, the way [blst-bindings](https://github.com/NethermindEth/blst-bindings) does for blst.

## Package

| RID | CPU baseline | Built on |
| --- | --- | --- |
| `linux-x64` | x86-64-v3 + PCLMULQDQ | `ubuntu-latest`, inside `ubuntu:22.04` |
| `linux-arm64` | ARMv8 + AES (PMULL) | `ubuntu-24.04-arm`, inside `ubuntu:22.04` |

- Native-only: no managed assembly. Nethermind's `NativeLeanProofVerifier` loads the library and, on chains with EIP-8288 scheduled, checks the CPU features, ABI version, aggregated verification key and acceptance bounds at startup.
- Version `<ABI>.<minor>.<patch>.<run>`: the major version is the native ABI version, so an ABI change is a major bump.
- `LeanSourceRevision` in `src/Directory.Build.props` and the package release notes name the Nethermind commit the binaries come from.
- No other RIDs: an EIP-8288 node on osx, win or musl fails at startup with Nethermind's backend message; other chains never load the library.

## Layout

- `src/Nethermind.Crypto.Lean`: the package; `runtimes/*/native/libnethermind_lean.so` (Git LFS) are committed by **Build Lean**.
- `src/Nethermind.Crypto.Lean.Test`: loads the committed library and checks its ABI version and aggregated verification key.
- `notices/`: `cargo-about` configuration for `THIRD-PARTY-NOTICES`.
- `licenses/`: LGPL-3.0 and GPL-3.0 texts for the shipped library.

## Workflows

- **Build Lean** (manual): builds `tools/lean-ffi` at a given Nethermind commit for each RID, twice, and fails unless both builds are byte-identical; regenerates `THIRD-PARTY-NOTICES`; optionally opens a pull request with the binaries.
- **Test / Publish**: on pull requests and `main`, checks formatting, runs the smoke test and Nethermind's native suite (startup checks and real verifications, at `LeanSourceRevision`) against the committed library on x64 and arm64 hardware, and verifies a consumer gets the right library per RID. On a release or a manual run, publishes to NuGet (staging or production) through trusted publishing, only after all of these pass.

See [RELEASING.md](RELEASING.md).

## License

The packaging code is [MIT](LICENSE). The shipped library is Nethermind's `tools/lean-ffi`, licensed [LGPL-3.0-only](licenses/LICENSE-LGPL); its dependencies are listed in [THIRD-PARTY-NOTICES](THIRD-PARTY-NOTICES).
