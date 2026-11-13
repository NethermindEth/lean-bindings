# AGENTS instructions

Nethermind's native EIP-8288 Lean backend (`libnethermind_lean.so`) and its NuGet package. See [global.json](./global.json), [src/bindings](./src/bindings/) and [src/ffi](./src/ffi/) directories for the project requirements and configuration.

## Project structure

- [src/ffi](./src/ffi/): The Rust source of the library, a thin C ABI (`nlean_*`) over unmodified upstream leanVM pinned by git revision, and the EIP-8288 guest crates in [src/ffi/crates](./src/ffi/crates/) vendored from that revision. This repository is the only source of this code.
- [src/bindings](./src/bindings/): The .NET codebase. `Nethermind.Crypto.Lean` is a native-only package; `Nethermind.Crypto.Lean` also carries, under `testing/`, the consumers' test assets, which `buildTransitive` copies only with `NethermindCryptoLeanTestAssets=true`; `Nethermind.Crypto.Lean.Tests` tests the committed library through the `nlean_*` C API.
- [build-lean.yml](./.github/workflows/build-lean.yml): Builds [src/ffi](./src/ffi/), generates [THIRD-PARTY-NOTICES](./THIRD-PARTY-NOTICES) and opens a pull request with the resulting binaries.
- [test-publish.yml](./.github/workflows/test-publish.yml): Runs the Rust tests and the .NET tests against the committed binaries, and optionally publishes the package on NuGet.

## Coding guidelines

- Follow [.editorconfig](./.editorconfig) and, for Rust, `rustfmt`.
- Do not assume; measure, research, ask if unsure.
- Keep comments short and to the point.
- Add tests for new code and bug fixes.
- Use conventional commits; keep scoped and imperative.
- Keep the native binaries under `src/bindings/Nethermind.Crypto.Lean/runtimes/` and [THIRD-PARTY-NOTICES](./THIRD-PARTY-NOTICES) built from the current [src/ffi](./src/ffi/). They are updated only by [build-lean.yml](./.github/workflows/build-lean.yml) (the binaries are Git LFS objects), so do not edit or rebuild them locally.
- Version the package as `<native version>.<run number>`: the native version is the crate `version` in [Cargo.toml](./src/ffi/Cargo.toml); [build-lean.yml](./.github/workflows/build-lean.yml) copies it into `VersionPrefix` in [Directory.Build.props](./src/bindings/Directory.Build.props), and [test-publish.yml](./.github/workflows/test-publish.yml) appends the run number. The crate's minor version is the C ABI version (`0.14.x` for ABI 14); bump the patch for a guest or key change at the same ABI. Changing it also needs the `nethermind-lean` entry in [Cargo.lock](./src/ffi/Cargo.lock).
- Keep the smoke test's expected ABI version and aggregated verification key, and the ABI version in the package `Description`, in sync with [src/ffi](./src/ffi/). Consumers pin both and check them at startup; a change of either is a new package version they adopt deliberately.
- Prefer the latest versions of GitHub Actions and runners.
- Keep upstream leanVM unmodified and pinned to one revision in [src/ffi/Cargo.toml](./src/ffi/Cargo.toml). The vendored [src/ffi/crates](./src/ffi/crates/) are upstream at that revision plus EIP-8288 changes: `crates/upstream.sh diff` shows them, `crates/upstream.sh update <rev>` moves the crates and the pin together. Keep the changes as small as the guest allows.
- Keep [src/ffi/about.toml](./src/ffi/about.toml) accepting every dependency license; Build Lean generates [THIRD-PARTY-NOTICES](./THIRD-PARTY-NOTICES) from it and [src/ffi/about.hbs](./src/ffi/about.hbs).
- Keep [AGENTS.md](./AGENTS.md) in sync with the ongoing development.
