# Go correlation: regression and performance evidence

Observed 2026-10-24. Scope: owned synthetic event fixtures, actual locally compiled Go worker, Python/SQLite/catalog integration and local CPU/process measurements. [Implementation](../GO_RUNTIME.md), [registered corpus](../../tests/fixtures/access_correlation_cases.json), [independent review](../research/GO_RUST_EFFICACY_REVIEW.md) and [safe machine-readable record](evidence/go-correlation.json).

## What actually ran

- A dependency-free Go executable validates and correlates one bounded request, using generic authorization decisions and explicit source-health observations.
- Python binds the frozen enrolled case, caps process input/output/lifetime and independently verifies output scope, byte hash, in-window evidence support, counts and mandatory gaps.
- The CLI can analyze an accepted synthetic case; the resident investigator can request the same result through `access_patterns` inside its existing budget. A labelled gateway test double exercises that contract. No real model/provider call occurred.
- The existing Python policy/approval/actuator services retain all authority. No new collector, revocation, production mutation or live protection was enabled.

## Rule consistency versus business truth

All **24/24 independent authored regression cases** match their registered candidate-code sets and required gaps. Only `case.input` reaches Go; `case.truth` stays in the evaluator. Scope separation, replay, old/future events, nanoseconds, equal-time uncertainty, source loss, outages, missing sources and upstream gaps are exercised.

The intentionally selected scenario labels give a different and necessary view:

| Authored business scenario | Candidate raised | No candidate |
|---|---:|---:|
| Harmful | 7 | 5 |
| Benign | 2 | 3 |
| Unknown | 2 | 5 |

These are **selected counterexamples, not estimated population recall or false-positive rates**. Five harmful-labelled scenarios are missed; two benign-labelled scenarios still raise a candidate. In two pairs, a benign scenario and a harmful scenario have byte-identical worker inputs. A detector—or an AI receiving only those same facts—cannot resolve the missing business intent from those inputs alone. Additional independently trustworthy observations are required. Threshold compliance is not account-takeover accuracy or prevention.

## Local performance

Local toolchain: **go1.26.4 windows/amd64**. Hardware descriptor and 12 logical CPUs are recorded with the raw samples; CI uses a separately pinned Go 1.27.3 toolchain. Neither version choice is a security attestation.

Thirty serial trials each launch a fresh Go process for 1,000 synthetic events with a warm OS cache, including pipe transport and strict Python reply validation:

| Measurement | Milliseconds |
|---|---:|
| Median | 43.624 |
| p95, nearest rank | 46.933 |
| Minimum | 40.959 |
| Maximum | 47.543 |

The evidence includes all 30 unrounded samples. These trials exclude production collection, queue contention, remote services, SQLite ingestion, model time, operator approval and actuator verification. A serial capped batch is not sustained stream throughput or an SLO. Warm-cache process launches are not machine-cold starts.

The separate Go `Analyze` microbenchmark validates/parses/correlates a 1,000-event grouped-denial fixture and checks serialized output size. Three samples and allocation counts are retained in the record. It excludes process launch, pipe transport and Python validation; it is not the same measurement boundary as the table. Around 8.5 MB allocated per operation and roughly 219,000 allocations identify profiling work, not proof of a production bottleneck. There is no equivalent Python implementation comparison and no claimed language speedup.

## Validation and review findings

The local Python suite passed **137 tests: 133 passed, four explicit skips**. Three skips are existing opt-in Docker experiments; one is Windows denying unprivileged symlink creation. The new boundary includes six integration tests and **26 independent adversarial tests**; previously measured Docker effects were not rerun for this worker.

Go unit tests, fuzz-seed tests and `go vet` pass. A separate short fuzz smoke run used two workers for three seconds: 44 executions, one additional interesting input, no failure. This is limited fuzzing, not an exhaustive parser assessment, peak-memory measurement or assurance against every malformed input.

Independent review found and verified fixes for equal-time gap dependence on event-ID order, output exceeding its nominal byte cap, and seven forged/unsupported caller-result variants. Nanosecond regression checks ensure a real one-nanosecond ordering difference survives both languages. Real hostile-child tests establish the parent timeout and output cap for a sleeping/overproducing direct child. Store reopen gives the same correlation result at the registered replay clock; new case evidence does not leak into an already frozen catalog request.

## Reproduce and limits

Follow the [build commands](../GO_RUNTIME.md#build-and-run), then:

```text
python -m scripts.check_go_runtime --output output/go-correlation-results.json
go -C runtime-go test -run ^$ -bench BenchmarkAnalyze1000 -benchmem -count=3
go -C runtime-go test -run ^$ -fuzz FuzzAnalyze -fuzztime=3s -parallel=2 -timeout=45s
```

Fingerprints use UTF-8/LF source text; the binary hash is platform/build-specific. Raw latency samples permit recomputing the aggregates. No private telemetry, credential, prompt or external target enters these experiments.

Production source identity, data minimization from real systems, distributed durability/backpressure, sustained load, hard OS memory isolation, cross-host clock correctness and live attack effects remain unverified. The Go worker is stateless; SQLite owns accepted facts and deterministic replay, not a durable network queue. The two generic rules miss low-and-slow/cross-subject scenarios and cannot separate legitimate access changes from malicious use without more evidence. CLIProxyAPI/Codex AI benefit remains **unmeasured**.
