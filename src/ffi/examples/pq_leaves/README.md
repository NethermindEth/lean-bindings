# Post-quantum signature leaves

Generic leanVM programs that verify N signatures and publish ethereum/EIPs#12664's leaf statement
`get_batch_hash(claims) = keccak256("EIP8288:batch:v1" ‖ claims)`, one 32-byte claim per signature. A leaf proves under
the committed bytecode key and aggregates through guest 1 like any other batch leaf. The claim count is a hint, so one
program, and so one key, serves every N from 1 to 256.

The programs and their hosts live in `src/pq`, which the published package uses for EIP-8437 mode 2's native checks and
leaf proving; they are not consensus code. This example measures their capacity and cost and runs the negative tests.

| scheme | claim | program |
| --- | --- | --- |
| ML-DSA-44 (FIPS 204, pure, empty context) | `keccak256("EIP8288:mldsa44:" ‖ tr ‖ 0x0000 ‖ M ‖ 0^14)`, `tr = SHAKE256(pk, 64)` | 1,889 instructions |
| Falcon-512 (round 3, PADDED 666-byte signatures natively) | `keccak256("EIP8288:fn512:v1" ‖ M ‖ pk)` | 1,966 instructions |
| SLH-DSA-SHAKE-128s (FIPS 205, pure, empty context) | `keccak256("EIP8288:slh128s1" ‖ PK.seed ‖ PK.root ‖ M)` | 1,638 instructions |

`M` is a 32-byte message. Every program pads to 2^11, the bound `MAX_GENERIC_BYTECODE_LOG` sets; the shared skeleton
(`leaf.py`: count, claim digest, publication) is 349 of those instructions. Each verifier proves acceptance from the
signature as a witness:

- ML-DSA recomputes `c~` from `mu` and `w1` (with the NTT of a hinted `w'` checked against `A z − c t1·2^d`) and checks
  the norm of `z` and the weight of `h`.
- Falcon checks `s1 = c − s2·h` and the norm bound for `s2` given as coefficients.
- SLH-DSA recomputes the FORS roots and the hypertree up to `PK.root`.

## Use

From `src/ffi`:

```sh
cargo run --release --example pq_leaves -- size  mldsa44        # instructions against the 2^11 bound
cargo run --release --example pq_leaves -- test  mldsa44        # reference vectors, then the negative tests
cargo run --release --example pq_leaves -- prove mldsa44 2 3    # a 2-signature leaf, one warm-up and 3 timed runs
cargo run --release --example pq_leaves -- prove mldsa44 2 3 --agg   # and the aggregation step verifying it
cargo run --release --example pq_leaves -- vectors              # native/leaf equivalence vectors, as JSON
```

Schemes are `mldsa44`, `falcon512`, `slhdsa128s`, and `null` (hinted claims, the skeleton alone).

`test` checks the host's computation against the scheme's reference implementation (fips204, tide-fn-dsa, fips205):
honest signatures are accepted, signatures over another message are rejected, and the host reproduces what the leaf
recomputes. It then proves a 2-signature leaf and checks that:

- a forged signature (the key's signature over another message, claimed for this one) does not prove;
- the verifier rejects a changed claim list and a subset of the claims;
- a statement over other claims does not prove.

`prove` prints one JSON line per timed run with cycles, the committed witness, peak RSS and, with `--agg`, the cycles of
the aggregation step.

One-signature leaves on a 12-core Apple M-series laptop: ML-DSA-44 4.0 s and 9.5 GB peak RSS, Falcon-512 0.6 s and
2.5 GB, SLH-DSA-SHAKE-128s 0.1 s and 0.27 GB.

GCP measurements (per-signature slopes, the largest N within the 2^29.5 trace bound, the aggregation step) are run by
the calibration suite (`calib.py pq-leaves`, lean-bindings#13). Its results are recorded in that PR.
