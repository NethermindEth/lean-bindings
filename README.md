# Lean bindings

[![Test / Publish](https://github.com/nethermindeth/lean-bindings/actions/workflows/test-publish.yml/badge.svg)](https://github.com/nethermindeth/lean-bindings/actions/workflows/test-publish.yml)
[![Nethermind.Crypto.Lean](https://img.shields.io/nuget/v/Nethermind.Crypto.Lean)](https://www.nuget.org/packages/Nethermind.Crypto.Lean)

Native EIP-8288 Lean backend for [Nethermind](https://github.com/NethermindEth/nethermind), packaged for NuGet as `Nethermind.Crypto.Lean`.

The library, `libnethermind_lean.so`, is built from the Rust crate in [`src/ffi`](https://github.com/nethermindeth/lean-bindings/tree/main/src/ffi), a thin C ABI over an unmodified, pinned [leanVM](https://github.com/leanEthereum/leanVM) and the EIP-8288 aggregation guest in `src/ffi/crates` (vendored from the same revision; see its README). This repository is the source of that code: consumers take the packages, not the source.

## Package

| RID | CPU baseline | Built on |
| --- | --- | --- |
| `linux-x64` | x86-64-v3 + PCLMULQDQ | `ubuntu-latest`, inside `rust:1.99.0-bookworm` |
| `linux-arm64` | ARMv8 + AES (PMULL) | `ubuntu-24.04-arm`, inside `rust:1.99.0-bookworm` |

- Native-only: no managed assembly. Nethermind's `NativeLeanProofVerifier` loads the library and, on chains with EIP-8288 scheduled, checks the CPU features, ABI version, aggregated verification key and acceptance bounds at startup.
- Version `<native version>.<run>`: the native version is the `src/ffi` crate version.
- glibc 2.35 (Ubuntu 22.04) or newer: Build Lean fails if the library needs a newer glibc symbol.
- No other RIDs: an EIP-8288 node on osx, win or musl fails at startup with Nethermind's backend message; other chains never load the library.

## Layout

- `src/ffi`: the Rust source of the library, and the `cargo-about` configuration (`about.toml`, `about.hbs`) for `THIRD-PARTY-NOTICES`.
- `src/bindings/Nethermind.Crypto.Lean`: the package; `runtimes/*/native/libnethermind_lean.so` (Git LFS) are committed by **Build Lean**.
- `src/bindings/Nethermind.Crypto.Lean/testing`: test assets for consumers' native suites: the vectors, the `fixtures` signing/proving tool and an incompatible startup stub, all built with the library (Git LFS, committed by **Build Lean**). They ship in the package outside `runtimes/`; a test project gets them in `lean-vectors/` only with `<NethermindCryptoLeanTestAssets>true</NethermindCryptoLeanTestAssets>`, so production publishes never contain them.
- `src/bindings/Nethermind.Crypto.Lean.Tests`: loads the committed library and checks its ABI version, aggregated verification key and limits, and verifies the packaged vectors and a signature from the packaged tool.

## Workflows

- **Build Lean** (manual): builds `src/ffi` for each RID, twice, and fails unless both builds are byte-identical; generates `THIRD-PARTY-NOTICES`; runs the smoke test on the built libraries on x64 and arm64 hardware; optionally opens a pull request with them into the branch it runs on. That pull request is opened with `GITHUB_TOKEN`, which starts no workflows, so run **Test / Publish** on its branch manually.
- **Test / Publish**: on pull requests and `main`, checks formatting, runs the Rust tests of the whole `src/ffi` workspace and the .NET tests against the committed library on x64 and arm64 hardware, and verifies a consumer gets the right library per RID. On a release or a manual run, publishes to NuGet (staging or production) through trusted publishing, only after all of these pass.

## License

This project is licensed under the [MIT](https://github.com/nethermindeth/lean-bindings/blob/main/LICENSE) license.

The shipped library statically links leanVM and other Rust crates, used under permissive licenses. See [THIRD-PARTY-NOTICES](https://github.com/nethermindeth/lean-bindings/blob/main/THIRD-PARTY-NOTICES) for the full texts.
