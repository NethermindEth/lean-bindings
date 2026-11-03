# Releasing

## When

A new package is needed whenever Nethermind's `tools/lean-ffi` changes in a way that changes the library: the leanVM revision, the FFI ABI, the acceptance bounds, the aggregated verification key or a CPU baseline.

- ABI change (`nlean_abi_version`): bump the major `VersionPrefix` in `src/Directory.Build.props`, and the smoke test's expected ABI.
- Verification key change: update the smoke test's expected key.
- Anything else: bump the minor or patch.

## Steps

1. Merge the `tools/lean-ffi` change in NethermindEth/nethermind and note the full commit SHA.
2. Run **Build Lean** with that SHA and `create-pr`. It fails unless each architecture's two builds are byte-identical.
3. The bot PR updates the binaries, `THIRD-PARTY-NOTICES` and `LeanSourceRevision`. Pull requests opened with `GITHUB_TOKEN` don't start workflows, so run **Test / Publish** on the PR branch (`workflow_dispatch`, publish `No`) before review.
4. Review: the PR lists both sha256 values; every required check, including the arm64 native suite, must pass. Merge.
5. Run **Test / Publish** on `main` with publish `Staging`; check the package on int.nugettest.org.
6. Publish `Production` (manual run or a GitHub release). The version is `<VersionPrefix>.<run number>`.
7. In Nethermind, pin the exact version in `Directory.Packages.props` and regenerate `Nethermind.Runner/packages.lock.json`. Its `Lean package tests` workflow runs the native suite against the package's library on both architectures.

## Repository settings

- Git LFS enabled.
- Actions: "Allow GitHub Actions to create and approve pull requests" on, for **Build Lean**'s PR.
- Branch protection on `main`: pull requests with a CODEOWNERS review; required checks: `Verify formatting`, `Test (ubuntu-latest)`, `Test (ubuntu-24.04-arm)`, `Nethermind native suite (linux-x64)`, `Nethermind native suite (linux-arm64)`, `Verify package assets`. The arm64 native suite is the release gate for arm64: it runs the committed library on arm64 hardware, which no cross build can stand in for.
- NuGet trusted publishing: a policy for this repository and `test-publish.yml`; `NUGET_USER` secret set to the NuGet account that owns `Nethermind.Crypto.Lean`.
