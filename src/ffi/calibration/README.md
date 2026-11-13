# Gas calibration (EIP-8288, ethereum/EIPs#12664)

A reproducible activation calibration: it measures aggregation on a machine, derives the gas constants from one
published budget, and checks them by proving the worst gas-admissible blocks across workers. It follows the activation
requirements of EIP-8288 (ethereum/EIPs#12654) and the batch-pricing draft (ethereum/EIPs#12664). It is not part of the
library or the package: a workspace member so CI keeps it compiling, with no dependency the library lacks.

## What it does

1. **Preflight.** Sizes the maximum-resource leaf (code `2^11`, inner heights up to `2^30`, inner rate 1/2, 256 claims)
   and the full step (`MAX_INNER_PROOFS_PER_STEP` leaves) to the machine's memory. With `preflight.mode = scale` it
   scales them down and says so in the report; with `refuse` it stops.
2. **Builds** the binaries against library revisions (`calib.py build`): `lib_ref` for EIP-8288 and the key under
   test, `batch_lib_ref` for #12664. Features are detected from each revision; scenarios a revision cannot run are
   reported as skipped.
3. **Corpus.** Proves the generic leaves (distinct keys, inner proving is the dependency owner's cost) and signs the
   signatures, before anything is timed.
4. **Cells.** One aggregation step per process, repeated, the first repetition discarded, waiting for a quiet machine
   before each: signature steps, merges (plain and claim-carrying), the maximum-resource leaf step, the full step and,
   with #12664, sponsored-leaf steps, merges of batch records and finalization.
5. **Constants.** `rate = G / (W · B / margin)` gas per machine-second, then each constant is the rate times its
   measured marginal machine-seconds: `LEANSPHINCS_VERIFICATION_GAS`, `RECURSIVE_PROOF_SHARE_GAS`,
   `LEANSTARK_VERIFICATION_GAS`, the `0x13` charge (STARK + share) and `LEANSTARK_CLAIM_GAS` (claim in its leaf, record
   carry per level times the tree depth, finalization).
6. **Verification.** Builds the gas-admissible worst-case blocks under those constants with complete transaction gas
   accounting (EIP-8141 intrinsic and per-frame costs, EIP-7976 triple data, a sender signature, the EIP-7825
   transaction cap): native-only, distinct-key generic singletons, half native / half generic, generic plus EVM, EVM
   only, one claim per maximum-resource leaf with its payment, full 256-claim leaves, and native plus batch. Each block
   is proved by `calib-coord` on W workers, which ship proofs between themselves; the **measured** makespan, critical
   path, total work, depth, transfers and per-worker peak memory are compared with the budgets. If a block misses, the
   rate is raised by the measured overshoot and the blocks are proved again (`max_iterations`).
7. **Report.** `calibration.json` and `report.md`, every figure labelled measured, imported, extrapolated, modelled or
   configured, with the requirement checklist and what remained unmeasured.

## Run

```sh
cd src/ffi/calibration
python3 calib.py preflight --config configs/smoke-m2max.json
python3 calib.py run --config configs/smoke-m2max.json --out results/smoke
python3 -m unittest discover -s tests          # calibration maths, EVM import
(cd .. && cargo test --release -p gas-calibration)   # scheduler, protocol, encodings
```

`ci/run-calibration.sh --scenarios smoke|reference|CONFIG --out DIR` sizes local workers to the machine (or runs
inside `rust:1.99.0-bookworm` with `--docker`), records the hardware and runs the calibration under a timeout; the
partial report survives a timeout.

## Configuration

See `configs/reference.example.json`. The keys:

| key | meaning |
| --- | --- |
| `key` | `flat` or `committed`; must match what `lib_ref` proves |
| `lib_ref`, `batch_lib_ref` | library revisions (`.` is this checkout) |
| `gas_limits` | each calibrated separately: a calibration covers only its gas limit |
| `builder_budget_s`, `validator_budget_s` | B for aggregation makespan; EVM execution plus block-proof verification |
| `reference_workers`, `threads_per_worker`, `memory_per_worker_gb`, `margin` | the published capacity |
| `workers` | `{"mode": "local", "count": W}` or `{"mode": "remote", "hosts": [...], "launch": "ssh ..."}` |
| `fanin`, `sigs_per_node` | the builder's tree shape (fan-in at most `MAX_INNER_PROOFS_PER_STEP`) |
| `bounds` | `code_log`, `trace_log`, `inner_log_inv_rate`, `claims`, `max_inner_proofs_per_step` |
| `evm.imports` | EVM timings: `gas-benchmarks` results, an `expb` log, or a CSV `name,gas_used,ms` |
| `tx` | `signature_gas`, `frames_per_tx` for the transaction accounting |

### Remote workers

Copy `calib-worker` (from `DIR/bin/<label>/`) to each host and give a `launch` template; `{token_file}` is a private
temporary file holding the run key, which the template copies to the host (see `configs/reference.example.json`).
Workers listen on loopback unless started with `--remote`, and fetch child proofs from each other directly over TCP,
so their addresses must be mutually reachable. Every connection proves knowledge of the per-run key (a
challenge-response, then a Keccak MAC with a sequence number on every frame); frames are bounded (64 KiB before
authentication, 256 MiB after) and buffered only as they arrive; a worker fetches children only from the workers the
coordinator listed and accepts at most 64 connections. Traffic is not encrypted: use a private network.

## EVM execution

The suite imports Nethermind's own measurements rather than reimplementing them (`calib/evm.py`):

- **gas-benchmarks** (what Nethermind's `gas-benchmark` agent skill drives): clone NethermindEth/gas-benchmarks,
  download a release's payloads (e.g. `amsterdam-repricings-*`), and run `run.sh -t <tests> -c nethermind -i
  '{"nethermind":"<image>"}' -f "<filter> and benchmark_<N>M" -K <fork>` on the calibration machine. It needs docker,
  bash 4+ and python3. `evm.run_gas_benchmarks` wraps this; import `results/` with format `gas-benchmarks`.
- **expb** (`run-expb-reproducible-benchmarks.yml` in NethermindEth/nethermind): import the `Run expb scenarios` log
  (`gh run view <run> --log`) with format `expb`. Those runs are real-block payload sets on Nethermind's benchmark
  boxes, so label them with `note` and do not treat them as this machine's or as worst-case EVM blocks.

A block within 5% of an imported block's gas uses that measurement; otherwise the slowest throughput is scaled
linearly and labelled extrapolated.

## What the reference machine must provide

- W workers of the published hardware class, each with the stated threads and enough memory for a full step of
  maximum-resource leaves (preflight `refuse` mode checks it), on a private network.
- A coordinator host that can hold the corpus: one maximum-resource inner proof per distinct-key leaf in the largest
  block (inner proving at `2^30` heights needs far more than 32 GB).
- Rust 1.99, python3; docker and the gas-benchmarks payloads for the EVM figures.
- The final library revisions: the selected key construction and the batch-pricing guest on one revision.

## Running on Nethermind's benchmark boxes

The `reproducible-benchmarks` runners are registered to NethermindEth/nethermind. Today a run uses a push-triggered
vehicle branch there (`test/eip8288-gas-calibration`, never merged): its workflow reads `.github/eip8288-calibration.env`
(`ARCH`, `LEAN_BINDINGS_REF`, `SCENARIOS`, `TIMEOUT_MINUTES`), yields if a manual benchmark run is waiting, checks
out this repository at `LEAN_BINDINGS_REF` and calls `ci/run-calibration.sh --docker`. To re-run, edit that file and
push. Two permanent homes would remove the vehicle:

1. A `workflow_dispatch` / `workflow_call` workflow on nethermind `master`, in the `run-*-benchmarks` pattern, with the
   same four inputs.
2. `.github/workflows/gas-calibration.yml` here, if the org grants this repository the benchmark runner group; it
   already takes `runs_on` as an input.
