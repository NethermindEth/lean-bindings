# AGENTS instructions

Nethermind's native EIP-8288 Lean backend (`libnethermind_lean.so`) and its NuGet package. See [global.json](./global.json), [src/bindings](./src/bindings/) and [src/ffi](./src/ffi/) directories for the project requirements and configuration.

## Project structure

- [src/ffi](./src/ffi/): The Rust source of the library, a thin C ABI (`nlean_*`) over a pinned leanVM fork.
- [src/bindings](./src/bindings/): The .NET codebase. `Nethermind.Crypto.Lean` is a native-only package; `Nethermind.Crypto.Lean.Tests` smoke-tests the committed library through the `nlean_*` C API.
- [build-lean.yml](./.github/workflows/build-lean.yml): Builds [src/ffi](./src/ffi/), generates [THIRD-PARTY-NOTICES](./THIRD-PARTY-NOTICES) and opens a pull request with the resulting binaries.
- [test-publish.yml](./.github/workflows/test-publish.yml): Runs the Rust tests, and the .NET tests and Nethermind's native suite against the committed binaries, and optionally publishes on NuGet.

## Coding guidelines

- Follow [.editorconfig](./.editorconfig) and, for Rust, `rustfmt`.
- Do not assume; measure, research, ask if unsure.
- Keep comments short and to the point.
- Add tests for new code and bug fixes.
- Use conventional commits; keep scoped and imperative.
- Keep the native binaries under `src/bindings/Nethermind.Crypto.Lean/runtimes/` and [THIRD-PARTY-NOTICES](./THIRD-PARTY-NOTICES) built from the current [src/ffi](./src/ffi/). They are updated only by [build-lean.yml](./.github/workflows/build-lean.yml) (the binaries are Git LFS objects), so do not edit or rebuild them locally.
- Version the package as `<native version>.<run number>`: the native version is the crate `version` in [Cargo.toml](./src/ffi/Cargo.toml); [build-lean.yml](./.github/workflows/build-lean.yml) copies it into `VersionPrefix` in [Directory.Build.props](./src/bindings/Directory.Build.props), and [test-publish.yml](./.github/workflows/test-publish.yml) appends the run number. The crate version stays `0.1.0` until a versioning scheme is agreed; changing it also needs the `nethermind-lean` entry in [Cargo.lock](./src/ffi/Cargo.lock).
- Keep the smoke test's expected ABI version and aggregated verification key, and the ABI version in the package `Description`, in sync with [src/ffi](./src/ffi/). On a change of either, also bump `NETHERMIND_REVISION` in [test-publish.yml](./.github/workflows/test-publish.yml) to a Nethermind commit whose native suite expects the new library.
- Prefer the latest versions of GitHub Actions and runners.
- Keep [src/ffi/about.toml](./src/ffi/about.toml) accepting every dependency license; Build Lean generates [THIRD-PARTY-NOTICES](./THIRD-PARTY-NOTICES) from it and [src/ffi/about.hbs](./src/ffi/about.hbs).
- Keep [AGENTS.md](./AGENTS.md) in sync with the ongoing development.
