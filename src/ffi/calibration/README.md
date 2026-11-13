# Gas calibration (ethereum/EIPs#12664)

A reproducible activation calibration: it measures aggregation on a machine, derives the gas constants from one
published budget, and checks them by proving the worst gas-admissible blocks across workers. It follows the activation
requirements and benchmark methodology of "Generic Proof Verification and Batching" (ethereum/EIPs#12664). It is not part of the
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
   configured, in the methodology's sections (see below), with what remained uncovered.

## Methodology coverage

`report.md` follows the headings of the benchmark methodology (ethereum/EIPs#12664,
`assets/eip-draft_batched_dependency_pricing/benchmarks.md`): Configuration, Workloads, Measurements, Calibration,
then what the run did not cover. Each section ends with a table of its items and what the run did for each.

| methodology item | covered by |
|---|---|
| **Configuration** | |
| Revisions and configurations, commitment construction, hashes | `lib_ref`, `batch_lib_ref`, `key`; builds record SHA and detected features |
| Gas schedule, gas limit | `gas_limits`; derived constants per iteration |
| Verifier resource bounds | `bounds` (program size `code_log`, trace `trace_log`, rate, claims, arity) |
| Hardware, workers, threads and memory per worker, margins | `host` record, `host.txt`/`machine.txt`; `workers`, `threads_per_worker`, `memory_per_worker_gb`, `margin` |
| Time and peak-memory budgets before calibration | `builder_budget_s`, `validator_budget_s`, `memory_per_worker_gb` |
| Memory per worker fixed jointly with commitment construction and arity | preflight: whether a full maximum-resource step fits one worker (`refuse` mode stops if not) |
| **Workloads** | |
| Maximum-resource leaf, claim count included | corpus leaves sized by the preflight; `generic-leaf`, `batch-leaf-r1`/`-r256` cells |
| Jointly valid resource combinations | not covered (see below) |
| Full steps at the proposed arity, distinct keys, recursive inputs, mixtures | `full-step-N`, `merge-*` cells; block trees mix leaves and recursive inputs |
| Outer trace and proof-size bounds | per-cell committed log2 and proof bytes (reported, not checked against a fork limit) |
| Gas-admissible blocks, complete transaction accounting | `calib/gasmath.py` (`tx`) |
| EVM-dominated, native, singleton generic, full batch leaves, one claim per leaf with payment, mixtures | blocks `evm`, `native`, `generic`, `batch_full`, `batch_one_claim`, `mix_*` |
| One leaf per initial step, no shared-key savings | by construction in `plan_for` |
| Overlapping leaves, source selection, payment lookup, pruning, finalization | batch blocks (sources, `retain`, `finalize`); overlapping leaves not exercised |
| Intended application verifiers fit the bounds | not covered |
| **Measurements** | |
| Makespan at W, critical paths, inter-worker transfers | `calib-coord` per block: makespan, critical path, fetch time, bytes |
| Authentication/recursion costs, total work, depth, critical path | per-node cycles and prove/fetch/decode time; block work and depth |
| Per-worker and aggregate peak memory | per-worker peak RSS (aggregate = sum) |
| Proof sizes, transmitted bytes | cell proof bytes; block input, transfer and root bytes |
| Validator execution and verification | root verification time plus imported EVM time vs `validator_budget_s` |
| 192-byte intermediate records | inside transferred bytes; not reported separately |
| Own process, discarded warm-up, >= 3 timed repetitions, median and range | `reps` (default 4: one warm-up, 3 timed) |
| No competing load or swap growth; repeat, then exclude | quiet gate (`quiet`) and swap check; a violated cell repetition or block is repeated once, then excluded |
| Cycle counts alongside times | cycles per cell and per block node |
| Cumulative claim hashing and payment binding, per-record vs amortized | `batch-leaf`, `mergebatch`, `finalize` cells at 1 and 256 claims (slopes = per record) |
| Batch leaf measured separately from a generic leaf | `batch-leaf-r1` vs `generic-leaf` cells |
| Measured separated from modelled | every figure labelled |
| **Calibration** | |
| Native, generic, share and batch-claim charges from the same budgets | `calib/gasmath.py` `derive` from measured marginals |
| Re-prove the blocks with the proposed schedule; all must fit | iterations: verify, raise the rate on a miss (`max_iterations`) |
| Covers only measured limits, configurations and bounds | one calibration per entry in `gas_limits` |

Not covered yet:

- Inter-machine transfers: remote mode exists, but every run so far used local workers over loopback.
- EVM execution on the calibration machine: EVM time is imported (expb, gas-benchmarks), not run alongside.
- Jointly maximal table heights ("jointly valid combinations of all resource bounds"): the generator raises one
  loop's trace; the other tables' maxima under the final verifier resource bounds are not defined.
- Intended application verifiers fitting the resource bounds.
- Overlapping leaves, and the 192-byte intermediate records reported on their own (they are inside the transferred
  bytes).
- The batch guest under the committed key: no library revision has both.

## Run

```sh
cd src/ffi/calibration
python3 calib.py preflight --config configs/smoke-m2max.json
python3 calib.py run --config configs/smoke-m2max.json --out results/smoke
python3 -m unittest discover -s tests          # calibration maths, EVM import
(cd .. && cargo test --release -p gas-calibration)   # scheduler, protocol, encodings
```

`ci/run-calibration.sh --scenarios NAME[,NAME...] --out DIR` (names: `smoke`, `reference`, `box-committed`,
`box-flat`, or a config path) sizes local workers to the machine (a config's `local_workers`, threads and memory split
between them), records the hardware and runs each scenario into `DIR/NAME` under a shared timeout; partial reports
survive it. `--docker IMAGE` runs inside a container that is removed afterwards, `--arch` refuses another
architecture, and `--yield-to-manual-runs OWNER/REPO --runner-label LABEL` exits without running while a manual
benchmark run is waiting for that runner (`ci/manual_runs.py`).

Each cell and block first waits for a quiet machine (`quiet.max_load1`, no competing build or test process), logging
while it waits. A timed cell repetition measured under load or with swap growth, or a block measured under load after
`quiet.timeout_s`, is run once more; if the repeat is violated too it is excluded, so it neither drives the
recalibration nor passes.

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
temporary file holding the run key, which the template copies to the host, and `{allow}` lists the IPs that may
connect: `workers.coordinator_ip` and the worker hosts (see `configs/reference.example.json`). Workers fetch child
proofs from each other directly over TCP, so their addresses must be mutually reachable.

**Remote mode is for trusted networks or ssh tunnels.** Traffic is authenticated, not encrypted:

- A worker listens on loopback and accepts loopback peers only, unless started with `--remote --allow IP,...`; other
  peers are dropped at accept, before they take any handshake slot, and each allowed IP (all of loopback counting as one) may have 4 handshakes open, 16 in all.
- Every connection proves knowledge of the per-run key within 5 s in total (challenge-response), then every frame
  carries a Keccak MAC over the key, the challenge, its direction and a sequence number.
- Frames are bounded (64 KiB before authentication, 256 MiB after) and buffered only as they arrive; at most 64
  authenticated connections are served.
- A worker fetches children only from the workers the coordinator listed.

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
vehicle branch there (`test/eip8288-gas-calibration`, never merged, no PR): its workflow
`.github/workflows/eip8288-gas-calibration.yml` reads `.github/eip8288-calibration.inputs` (`ARCHES`,
`LEAN_BINDINGS_REF`, `SCENARIOS`, `TIMEOUT_MINUTES`), clones this repository at `LEAN_BINDINGS_REF` into the runner's
temporary directory and calls `ci/run-calibration.sh --docker` with `--yield-to-manual-runs`, uploads
`eip8288-calibration-<arch>` and removes the directory and any container. Only manual `workflow_dispatch` runs of
`run-expb-reproducible-benchmarks.yml` and `run-rpc-benchmarks.yml` make it yield; automated runs queue as usual.
To re-run, recreate the branch from `master` with those two files, edit the inputs and push over SSH (the workflow
file needs a token with the `workflow` scope); delete the branch once the artifacts are downloaded. Two permanent
homes would remove the vehicle:

1. A `workflow_dispatch` / `workflow_call` workflow on nethermind `master`, in the `run-*-benchmarks` pattern, with the
   same four inputs.
2. `.github/workflows/gas-calibration.yml` here, if the org grants this repository the benchmark runner group; it
   already takes `runs_on` as an input.
