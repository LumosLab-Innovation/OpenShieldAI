# Publication audit of measured evidence

Reviewed 2026-10-24 against the committed records. This is an independent consistency review, **not a fresh lab rerun or production acceptance**. Every number below belongs to its stated fixture and measurement boundary. Do not add assertion counts across increments or present them as independent attacks.

## Real model comparison

Source: [final record](evidence/next-wave.json), `comparison.arms.{baseline,ai}.metrics`; [trial manifest](evidence/next-wave-trials.json); [interpretation](NEXT_WAVE_RESULTS.md).

| Registered metric | Baseline v1 | Codex through CLIProxyAPI |
|---|---:|---:|
| Accepted case decisions / policy-acceptable assessments | 16/16 / 16/16 | 16/16 / 16/16 |
| Observed harmful effects identified | 4/4 | 4/4 |
| False suspicious assessments among four benign cases | 0 | 0 |
| Correct unknowns | 8/8 | 8/8 |
| Decisive benign / benign abstentions | 2 / 2 | 4 / 0 |
| Acceptable proposals | 12/16 | 16/16 |
| Registered required-code presence | 13/16 | 14/16 |
| Degraded cases | 0 | 0 |
| Model calls | 0 | 41 |
| Conservative visible-token reservations | 0 | 171,631 |
| Triage-arm elapsed time, seconds | 4.078 | 318.469 |

The four proposal differences are three recovery failures and one source-loss escalation. Coarse assessments tie. Code presence is not semantic precision; `16/16` is not representative detection accuracy. The public corpus contains four harmful, four benign and eight unknown cases, with partly observer-resolved facts. Both arms receive the same frozen facts/catalog and zero actuators. Enforcement does not depend on the model. No human work/time measurement or operational AI advantage is established. Model alias `gpt-6.1-sol` is proxy-reported, not independently attested.

All completed attempts must remain visible:

| Protocol | Valid / degraded cases | Calls | Reserved tokens | AI-arm seconds |
|---|---:|---:|---:|---:|
| [Original catalog](evidence/next-wave-first.json) | 3 / 13 | 25 | 93,386 | 165.141 |
| [Derived catalog v2](evidence/next-wave-catalog-fixed.json) | 3 / 13 | 42 | 166,021 | 308.313 |
| [Bounded reads v3](evidence/next-wave.json) | 16 / 0 | 41 | 171,631 | 318.469 |

The interrupted older 48-case attempt has no scored record or complete usage accounting. The [one-case diagnostic](evidence/proxy-diagnostic.json) is separate from these totals. Repairs changed generic protocol/adapter behavior, not truth/facts/scoring. This is not a first-unseen trial or a held-out improvement estimate. Reservations are not billed tokens, full provider consumption or account-wide usage. Per-case final-call reported usage cannot substitute for whole-run accounting.

## Separate post-hoc deterministic comparator

The later [rules-plus-lookup v2 study](BASELINE_V2_RESULTS.md) and [record](evidence/baseline-v2.json) reuse v1 and add failed/inconclusive-restore gap detection plus human escalation for existing recovery/visibility gaps. Current core source hashes match the retained actual-AI experiment; neither v1 nor the actual-AI record was changed. The decision receives only the accepted snapshot, without evaluator labels. Eight focused tests pass, including relabeling, order, unused-truth poisoning, historical-failure review and frozen-input mutation rejection.

V2 scores **16/16 policy-acceptable assessments, 4/4 supported effects, zero false suspicious among four benign cases, 8/8 correct unknowns, 16/16 acceptable proposals and 16/16 required-code matches**. It retains two decisive benign decisions and two benign abstentions, makes zero model calls and reserves zero tokens. This closes the four proposal differences and three v1 missing recovery codes on already examined cases. It is explicitly tuned after public results and does not establish held-out generalization or an AI/non-AI operational winner.

Its recorded **2.375 seconds** uses direct function calls with Store setup/intake, omitting Supervisor episode persistence; retained v1/AI elapsed times use a different harness and historical run. Do not calculate a matched speedup ratio. A failed verification followed by a verified recovery still triggers review of the earlier failure: this comparator is conservative case-level triage, not temporal current-readiness reconciliation. No model rerun or new protection experiment occurred.

## Effect and performance inventory

| Experiment and record | Exact observed measures | Publication boundary |
|---|---|---|
| [Original prevention](evidence/prevention.json) | Three planted effects blocked in On mode; Off/DetectionOnly permit them. Nine benign requests return 200 across modes | CRS-shaped planted operations, not demonstrated SQLi/XSS/RCE exploitation, recall or population false-positive rate. Request-only CRS policy |
| [Approved response](evidence/approved-runtime-response.json) | Source-to-verified ingress effect 5.532s; 11 additional planted effects during response. Collection 0.773s, planning 0.144s, scripted approval 0.865s, dispatch/readback 1.793s, checks 1.958s | Single local interval; approval wait scripted, actual human time null. New ingress stops; in-flight/background/host/session/egress are not contained |
| [Original recovery](evidence/recovery.json) | Actual restore/app-check 3.162s; synthetic checkpoint-to-incident 5.348s, one later transaction. Missing/wrong key, corrupt pack, planted contaminated marker and application inconsistency reject | One historical restic/HTTP-application drill, not production RPO/RTO or malware eradication |
| [Original 48-case comparison](evidence/decision-comparison.json) | Baseline 12/12 supported, 0/12 false suspicious; 2 decisive benign/10 benign abstentions; 12/12 correct unknowns; 12 invalid inputs rejected; accepted decisions 36/36; 10.250s, zero calls. AI not run | Historical provider-unconfigured experiment. Never replace missing AI metrics with zero accuracy or reuse these denominators for the later 16-case run |
| [Original anti-REA](evidence/anti-rea.json) | 16 HTTP checks, four real Chrome checks. Release 3 files/1,906 bytes → 2 files/1,134 bytes. REA parses 1 JS on each side, zero parse failures/skips, AST nodes 94→140, static observations 3→3; both overall partial/semantic unknown | Neither parser failure nor fewer nodes is the defense mechanism. Two authorized outputs still reveal the linear formula. Captured browser/REA runs were not rerun by subsequent increments |
| [Go correlation](evidence/go-correlation.json) | 24 authored rule-set matches. Harmful candidate/no-candidate 7/5, benign 2/3, unknown 2/5. Thirty fresh-process 1,000-event samples: median43.624ms, p9546.933ms, min40.959ms, max47.543ms | Warm OS cache; includes pipe/Python validation, excludes collection/model/operator/action. Not stream throughput/SLO or Go-versus-Python speedup. Identical observable inputs can have different business truth |
| [Go microbenchmark](evidence/go-correlation.json), `goMicrobenchmark.lines` | Three samples: 20,484,533 / 19,321,400 / 20,339,967 ns/op; 8,528,148 / 8,541,986 / 8,535,444 B/op; 218,608 / 218,605 / 218,600 allocations/op | Analyze-only boundary; excludes process/pipe/Python. Samples are not the end-to-end latency table |
| [Parallel effects](evidence/parallel-defense.json) | 83 named checks: 43 Go tool, 16 original anti-REA, 11 durable quote, 13 delivery cases | These overlap historical original anti-REA; never sum as unique attacks. No model calls |
| Parallel Go tool authority | Unsafe one forbidden mark/one outside receipt; protected zero forbidden effects. Allowed nine reads, one approved mark, one approved receipt; one of16 concurrent mark consumers succeeds | Three fixed synthetic operations, ephemeral process; no actual model prompt-injection trial or general DLP |
| Parallel durable quote | Three HTTP server instances preserve revocation, one-use grants and four-query principal quota across restarts; backward time503 and expired grant denied | Local SQLite durability, not off-host anti-rollback, production identity or protection from authorized output inference |
| Parallel delivery | Thirteen authored modes cover clean identity/gzip, stale maps/headers/gzip/root, redirects, malformed/concatenated gzip, bomb and unsupported coding | Declaration-bound promotion audit, not interception of all live/CDN/browser bytes |
| [Next-wave effects](evidence/next-wave.json), `effectCheckCounts` | 103 named checks: flow48, promotion27, recovery28 | Assertions over fixtures, not103 independent attacks; no model on enforcement path |
| Next-wave flow | Unsafe four reads/three charges/three units; protected two allowed reads/two charges/two units and zero forbidden effects. Outside deliveries2→0; protected forbidden receiver zero requests; one allowed delivery; 16 distinct grants yield one idempotent commit | Main counters exclude separate quota/admission fixtures. Eight legitimate reads before ninth denied; four paused reads resume after fifth concurrent admission denied. Synthetic proof throttling has measured legitimate lockout cost |
| Next-wave promotion | Eight requests/phase. Old edge4 private deliveries; clean origin0, stale edge still4; approved purge removes eight cached representations. Final origin/edge0 private deliveries, six required GET successes and two denied map representations each | Fixed identity/gzip origin/owned-edge paths. Previously downloaded bytes remain disclosed; no real CDN/service-worker recall or production deployment identity |
| Next-wave restore readiness | Seven cases/28 checks. Availability-only produces five false-ready cases; exact-copy/hash still four. Actual application checks reject them; clean restore rollback preserves state and committed transfer observed independently at balances599/401, ledger row1 | Local unencrypted SQLite scratch restore. No new key, interrupted restore, HTTP service, malware or production RPO/RTO result |

The [24-case coverage ledger](../NEXT_WAVE.md) lists eleven newly exercised slices, three earlier tool-authority slices, three limited existing proofs and seven unsupported cases. It does not represent24/24 protection. Unsupported: I3, I4, H1, H2, D1, C1 and V2.

## Consistency checks and required copy corrections

- Recomputed the 30 Go samples' median and nearest-rank p95; published rounded values agree. Summed final per-case calls/reservations;41/171,631 agree with arm totals. Verified48+27+28=103 and43+16+11+13=83.
- Final corpus and all three trial artifact commitments match **UTF-8/LF text hashing**, as used by the evaluator. Windows CRLF checkout byte hashes differ; a publication checker must use the same normalization. These commitments are integrity checks, not authenticity or exact historical upstream reproducibility.
- Earlier test counts57/105/137/178 belong to those increment snapshots. The prior final local suite was227:223 pass/four skip; Linux CI227:224 pass/three Docker skips. Current edits need their own observed validation, rather than calling an old count current. Seven historical Docker tests passed; default CI skips actual Docker effects.
- Landing claims that no real endpoint exists and AI evaluation is pending are stale. Replace with the completed comparison and explicit absence of measured operational advantage.
- `RESULTS.md` and the original anti-REA/Go notes retain historical unconfigured-provider wording. Label it historical and point to the later actual comparison; do not rewrite their raw captured evidence or imply those exact experiments were rerun with AI.
- README/landing must show uncertainty and failures beside the favorable measurements, link the exact safe artifacts, and preserve the distinct enforcement, AI-decision, latency, recovery and authored-check denominators.

No API calls, model reruns, production assets or new attack executions were used in this review. The measurements remain S1 engineering evidence and historical isolated labs.
