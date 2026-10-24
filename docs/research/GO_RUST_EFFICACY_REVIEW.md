# Independent architecture and efficacy review: Go/Rust expansion

Reviewed 2026-10-24 against the executable Python runtime, its recorded lab results and the proposed first Go correlation worker. This is an independent challenge, not approval for production collection or response. Research breadth is useful when it produces falsifiable, prioritized capabilities; a large technique list does not establish protection.

## Decision before implementation

**Accept a small, offline Go temporal-correlation worker. Reject a blanket rewrite and defer Rust until a measured requirement justifies another toolchain.** Keep Python/SQLite enrollment, evidence, gateway, policy, approvals and action reconciliation unchanged. A worker emits bounded evidence-linked candidates; it acquires no collection, provider or response authority.

The host reports `go version go1.26.4 windows/amd64`. `rustc` and `cargo` are absent from the current PATH; that is a local observation, not proof that Rust is unavailable everywhere. The deployed ingress already uses Caddy/Coraza, and recovery already uses restic. Replacing these proven tools would create a new security and maintenance burden without a demonstrated need.

The [first measured response](../lab/RESULTS.md) took 5.532 seconds, including 0.144 seconds for ingestion/investigation. Even eliminating that entire observed interval saves only approximately 2.6% of that one response. Collection, approval, dispatch, independent verification and ongoing harm remain. This calculation is a bound on one recorded run, not a general performance estimate. A faster correlator may improve high-volume replay, but must earn that claim through equivalent-work measurements.

## Language selection criteria

| Component | Decision | Required evidence before expanding |
| --- | --- | --- |
| Offline bounded event correlation | Go is reasonable: installed toolchain, standard-library JSON/time/sorting, independently testable executable | Same semantics as a simple reference implementation; end-to-end invocation and parse costs; workload limits and rejected inputs |
| Existing policy/approval/state/gateway | Preserve current Python implementation | A profile showing an actual bottleneck plus migration tests for durable state, exact approvals, failure handling and operational rollback |
| Untrusted binary parser or low-level sensor | Consider safe Rust later | A concrete supported format/OS, profiling, maintenance owner, fuzzing, unsafe/FFI inventory and deployment isolation |
| Request enforcement and backup | Reuse pinned existing tools | Supported version/configuration, real attack-path and legitimate-workload tests, independent effect measurements |

Go's [diagnostics guidance](https://go.dev/doc/diagnostics) supports profiling expensive code and tracing latency contributions before optimization. Its [pipeline guidance](https://go.dev/blog/pipelines) explains bounded parallelism and cancellation because abandoned sends and unbounded goroutines can retain resources. For a capped offline batch, a serial algorithm is simpler than inventing a worker pool. Neither concurrency nor language choice establishes better detection.

Go's [GC guide](https://go.dev/doc/gc-guide) explicitly treats its memory target as soft. Input/cardinality/output limits and a supervising process deadline remain necessary; an OS/container limit is needed before claiming hard process-memory containment. Rust's [ownership model](https://doc.rust-lang.org/book/ch04-00-understanding-ownership.html) supports memory safety without garbage collection, but [safe Rust still permits general race conditions and logic errors](https://doc.rust-lang.org/nomicon/races.html). Neither language authenticates telemetry, proves an authorization decision true, prevents a replayed business operation by itself, or calibrates an incident probability.

## Minimum acceptable worker contract

1. The operator selects a trusted executable. Evidence cannot select a command, executable path, source file, plugin, provider or endpoint. One bounded input document produces one bounded result; no shell, target execution, automatic download, network request or persistent daemon is required.
2. Bind schema, project, case, asset, enrolled sources, reference clock and analysis window. Validate independently in both languages. Opaque IDs are references, not identities or permission. Reject cross-scope records, unsupported kinds/data classes, unknown fields, invalid enums, missing fields and noncanonical types.
3. Bound total bytes, event count, field lengths, distinct groups, window duration, candidate count, evidence references, deadline and output. Empty, unavailable, truncated and over-limit inputs must not become a clean result. Exhaustion is a partial/failed run with a visible gap.
4. Reject ambiguous JSON before semantic parsing: duplicate keys, key-case aliases, trailing documents, unsupported nesting, invalid text and inappropriate `null` values. The standard [Go JSON security notes](https://pkg.go.dev/encoding/json#hdr-Security_Considerations) warn about duplicate names, case-insensitive field matching, ignored unknown fields, invalid UTF-8 replacement and numeric interpretation. `DisallowUnknownFields` alone is not an exact-schema validator.
5. Deduplicate exact repeated event IDs; reject a repeated ID with different content. Sort by parsed UTC event time with a specified tie rule. Never compare variable-width timestamp strings as time. At equal time, a successful decision does not prove that a failed decision occurred earlier.
6. Return rule/version, scope, immutable evidence references, parsed time window, counts, explicit gaps and `isFinding: false`. Report authenticity and completeness limitations. No candidate silently becomes confirmed compromise, an action, a permission or an independent verification.
7. Parent timeout/termination and worker errors preserve explicit incompleteness. A job cannot hang waiting for input, output or a downstream consumer. Queue/admission caps belong to the caller; an offline per-process cap does not prove fleet backpressure or fairness.

This is a review requirement, not a claim that every item has already been implemented. The final implementation review below records the actual scope.

## Challenge to the first authentication use case

A deny burst followed by an allow can justify investigation. It cannot alone identify account takeover. The same trace can represent an authorized person correcting a password, a misconfigured client retrying, an access-policy update, or separate actors using the same principal. Object authorization events are not automatically login events. A source that reports `allow` may itself be compromised.

| Risk / negative control | Required behavior or explicit limit |
| --- | --- |
| Three retries then legitimate success | Candidate may be raised only under the declared threshold; never label a confirmed takeover or revoke automatically |
| Password spray across subjects | Preserve grouping semantics; report unsupported cross-subject/source campaign inference rather than claim complete identity coverage |
| Distributed or low-and-slow abuse | Window/threshold evasion remains a known miss; more speed does not fix missing features |
| Burst before the registered window or after the successful event | Exclude it from the sequence; boundary equality must be specified |
| Shuffled input and timestamp fractions | Same semantic result after ordering; disclose reordered observations and clock limitations |
| Replayed denial / conflicting duplicate | No count inflation from an exact duplicate; conflicting input rejects or visibly fails the run |
| Dropped/outage/stale/future evidence | Keep a gap even when a candidate exists; zero candidates must not imply no attack |
| Swapped case, asset, project or unregistered source | Reject before correlation; matching labels never establish enrollment |
| Forged but schema-valid source fact | Remains possible without authenticated collection; a signature still cannot prove a compromised collector tells the truth |

Keep the narrower rule name and description aligned with the actual event semantics. Synthetic access decisions exercise correlation correctness. They do not establish real credential-stuffing detection, identity-provider support, attack attribution or prevention.

## PM/BA gate for a broad security portfolio

Each proposed case needs an owner, protected asset/business invariant, adversary capability, observable signal, missing inputs, immediate control point, response authority, independent success/failure observation, recovery limits, benign lookalike and a measurable stop/go test. List the actual algorithm and its assumptions separately from an untested research hypothesis. ATT&CK mapping, a paper result or the number of cases is not an efficacy score.

Prioritize cases that reuse accepted controls and can be measured safely: ingress abuse, authorization misuse, release exposure and isolated restore failures. Before host/ransomware/exfiltration/AI-agent expansion, identify accepted collectors and what relevant containment can actually stop. New-ingress maintenance does not end existing sessions, background work, persistence or data egress. Restore cannot reverse disclosure.

The resident AI layer remains an investigation/planning hypothesis. The CLIProxyAPI/Codex transport exists, but the current repository records no configured real provider and no measured incremental AI value. Adding a deterministic Go worker does not close that gap. Require the same evidence, available reads, static controls, budgets and authority in both arms, plus a fresh held-out incident set and adverse outcomes. A published synthetic regression corpus is not unseen evidence for later tuned rules or prompts.

## Benchmark and release review gates

- Compare the same algorithm, validated input, ordering, duplicate handling, thresholds, coverage and serialized output. Include Go process startup and JSON overhead separately from its internal algorithm time. Do not compare Go correlation with unrelated Python SQLite ingestion or an intentionally weaker rule.
- Report workload size, grouping/cardinality, hardware/toolchain/source hashes, repeated distributions and failure rates. Include boundary-size valid input and hostile input. A tiny warm-cache run or one latency sample cannot support a broad speed claim.
- Measure detection usefulness separately from processing speed. A faster false positive, unsupported hypothesis or unsafe action is worse defense. Include real operator review before claiming analyst work saved.
- Default CI must build/test the Go code, run Python integration/hostile-contract tests and fail on a broken or unavailable required worker. A developer without Go may have an explicit test skip, but CI cannot silently exercise only a Python fallback while presenting a Go implementation as validated.

## Implementation review record

The reviewer inspected `runtime-go/correlation.go`, the executable entry point, Python caller, resident catalog integration and CI build, then ran [26 independent executable/caller tests](../../tests/test_go_correlation_adversarial.py). All 26 passed on 2026-10-24 in 1.223 seconds. These are synthetic contract/correlation tests, not attack-detection or speed results. No provider, target network or action adapter was used.

| Review concern | Observed disposition |
| --- | --- |
| Go/Python JSON interpretation mismatch | Actual executable rejected missing/unknown/case-variant/null fields, duplicate names, trailing documents, malformed UTF-8, unsupported types, invalid time/enums, cross-scope/source records and recognizable credential canaries |
| Denial inflation and causal order | Exact duplicates did not inflate thresholds; conflicting replay was rejected; shuffled input preserved candidates; equal-time allow/deny never established a sequence |
| Equal-time uncertainty depended on ID sort order | First inspected implementation could miss a gap when an allow sorted before same-time denials. Root's concurrent fix pre-scans the time group; independent regression now passes with the allow ID before denial IDs |
| Nominal candidate/ref caps could exceed serialized output cap | Raised during review; worker now prunes output with an explicit gap. A 960-event case with 64-character IDs/labels stayed within 64 KiB and reported partial candidate coverage |
| Visibility loss could disappear after a healthy record | Outage/dropped-event gaps survived later health, and upstream gaps survived candidate generation |
| Python trusted known references without checking their meaning | Independent tests reproduced seven forged-output acceptances: all-allow/old/future references, invented/below-threshold counts and erased upstream/source-loss gaps. Fixed: caller checks window/accounting, supported rule evidence/counts and mandatory visibility gaps |
| Go/Python time precision differed | Independent genuine one-nanosecond sequence passes both executable and caller; the caller preserves nine fractional digits rather than truncating causal order to Python microseconds |
| Result could look like safety or confirmed compromise | Empty input stayed incomplete; all accepted outputs and candidate objects explicitly remained `isFinding: false`; no action authority exists in the worker |

The first worker implements fixed 60-second generic subject/object access-decision correlation: five denials, or three strictly earlier denials followed by an allow. It does not implement login analysis, password spraying, production source authentication, a live collector or a response control. The 500 ms cooperative analysis deadline starts after input reading; the caller must enforce a hard process/I/O deadline. A soft 64 MiB Go target is not a hard memory sandbox.

The resident `access_patterns` read stays in the existing episode/case snapshot and bounded read catalog. Tool failure produces explicit degraded investigation; it grants no action. CI selects Go 1.27.3 and builds/tests/vets the actual worker before Python tests; the local measured executable and module minimum remain Go 1.26.4. A maintained CI patch selection does not establish a completed dependency/security assessment. These are useful integration boundaries, not production source authentication or throughput/fairness proof.

The reviewer inspected the actual safe `artifacts/go-runtime/results.json` and the measurement script. All recorded source, executable and corpus fingerprints matched the files inspected. The record reports 24/24 selected semantic regressions, but its separate authored business table contains **seven candidate / five no-candidate harmful cases, two candidate / three no-candidate benign cases, and two candidate / five no-candidate unknown cases**. Two pairs have identical worker input but opposite authored business truth. This directly demonstrates that these observations cannot identify intent or compromise by themselves. These selected authored labels are not independently observed real attack effects or a representative accuracy estimate.

The final recorded 30 serial 1,000-event fresh-process/caller trials reported median **43.624 ms**, p95 **46.933 ms**, range **40.959–47.543 ms**, with warm OS cache on Windows/AMD64 and Go 1.26.4. The record retains the CPU description, 12 logical CPUs and all 30 raw latency samples; the reviewer independently recomputed these aggregates and verified the measurement-script fingerprint. Three `Analyze` microbenchmarks reported **20.485 / 19.321 / 20.340 ms**, approximately **8.53–8.54 MB allocated and 218,600 allocations per operation**. Internal analysis excludes process launch, transport, Python checks and real services; caller latency includes process transport and strict reply validation. Neither measures collection, queueing, operator, model or actuator delay. High token-parser allocation is a possible later profiling target, not evidence that Rust is needed.

No equivalent Python algorithm was compared, so **no language speedup is established**. The reviewer inspected the measurement method and recorded aggregates, and independently reran the hostile/temporal executable tests; this is not an independent reproduction of every benchmark trial. Broader fuzzing, peak process RSS/hard memory isolation, sustained load, fairness, authenticated collection, production deployment and incremental AI value remain unverified.

**Disposition: accept the bounded S1 synthetic Go candidate/read integration and its explicitly scoped local measurements. Reject promotion to account-takeover detection, production prevention, end-to-end response improvement or AI advantage.** The portfolio and hypothesis register are proposed experiment plans; they do not implement their listed incident families. Full S2/S3 acceptance remains open.
