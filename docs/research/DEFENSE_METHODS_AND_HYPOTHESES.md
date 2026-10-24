# Defense methods, assumptions and falsifiable hypotheses

Research reviewed 2026-10-24. This is a BA/research specification, not a coverage or production claim. Proposed experiment sizes, thresholds and acceptance limits below are **our preregistration proposals**, not recommendations copied from a standard or measured OpenShieldAI results. Changes to authority remain subject to [guardrails](../SECURITY_GUARDRAILS.md) and [acceptance](../ACCEPTANCE_CRITERIA.md).

The useful unit of delivery is an incident family with sufficient observations, an explicit decision rule, an effective control point, an independent effect test and a known failure envelope. Counting agents, ATT&CK IDs, installed rules or model opinions does not establish defense. [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final), published April 2025, places preparation, detection, response and recovery within continuing risk management; that lifecycle motivates this separation, rather than a one-shot alert product.

## What exists and what this research changes

At review time, `openshield/core.py` accepts bounded synthetic events, has immutable enrollment, retains gaps, runs a deterministic case baseline and restricts AI to evidence-linked proposals. The baseline recognizes five WAF denials, explicitly unauthorized application effects/deployments, release exposures and backup gaps. Although `auth_decision` is accepted, the baseline does not correlate its account/object sequences. The [first lab](../lab/RESULTS.md) demonstrates selected planted ingress effects and isolated application recovery; the [anti-REA lab](../lab/ANTI_REA_RESULTS.md) demonstrates selected distribution and server-authorization boundaries. Neither establishes a representative security classifier, production protection or incremental AI benefit.

This document proposes a bounded Go correlation slice first, while specifying the evidence required before broadening to other cases. Go is a practical standard-library implementation choice for bounded JSON/event processing. Rust remains an option for a demonstrated parser/isolation need. A language change by itself neither authenticates telemetry nor improves detection. Keep the Python supervisor/policy path until a measured migration justifies replacing it.

## Case map: broad research, narrow executable claims

`Available` means a minimized synthetic fact exists; it does not mean a real collector is accepted. `Needed` means a future contract and source acceptance are required. Each row remains an independently gated capability.

| Case and operator question | Minimum observation and independent truth | Method / immediate control point | Current limit and useful negative control |
|---|---|---|---|
| Repeated authorization denial: who is repeatedly refused? | Available subject/object/decision, time and source health; controller-owned fixture intent | Sliding count; existing application authorization remains the control | A denied object request is not necessarily a login. User retry/error loop must be included. |
| Denials followed by allowance: did access change? | Available same subject/object decisions; independent account/session history needed to assess compromise | Ordered sequence candidate and competing benign explanation | Password reset, corrected object selection and permission grant can produce the same sequence. |
| Distributed guessing / spraying / stuffing: what is the mechanism? | Needed authenticator outcome, stable origin/session labels, target account and approved credential-risk context; never password values | Multi-axis counts/cardinality and existing IdP throttling/phishing-resistant authentication | Existing `auth_decision` cannot distinguish these mechanisms. Rotating origins and slow attacks defeat simple windows. |
| Cross-tenant/object access: can a principal reach another tenant's object? | Needed policy context and independent allowed-object matrix; available lab deny/allow labels alone are insufficient | Server-side authorization invariant; denied cross-object fanout is a triage signal | WAF scores and unpredictable IDs cannot supply authorization. Authorized shared objects are a negative control. |
| HTTP input attack: did the request reach a harmful sink? | Available WAF decision plus independent planted effect/application reach | Pinned CRS request policy at the ingress; replay allowed traffic | A matched rule is not exploitation proof. Encodings, bypass paths and legitimate rich text matter. |
| Business flow abuse: is a valid operation being used harmfully? | Needed operation semantics, principal-wide quotas, domain invariants and side effects | Capability/parameter binding, idempotency and invariant checks in the application | Legitimate automation/batch jobs resemble abuse. A generic WAF cannot infer business entitlement. |
| Unauthorized deployment/configuration: was the change approved? | Available deployment/control facts; needed external trusted change receipt and effective config readback | Exact revision/policy comparison; approval-bound rollback proposal | The supplied `authorized` boolean is an assertion. Emergency changes and compromised change systems confound it. |
| Host execution/persistence: what executed, with what ancestry? | Needed accepted process/file collector, identities, dropped-event counters and independent host evidence | Pinned host rules and bounded entity joins; later approved host control | No current EDR integration. Admin tools, package updates, collector compromise and lost ancestry matter. |
| Lateral movement/cloud persistence: was a new trust edge created? | Needed identity grants, cloud/network audit, dependency inventory and change approval | Bounded graph edge-delta review; existing least privilege/segmentation | No network scanning or new cloud integration is implied. Approved provisioning and shared service accounts matter. |
| Exfiltration: what data actually left? | Needed classified access/egress counts and separate destination/transfer evidence | Volume/change detection plus authorization and approved egress control | Large backup/analytics exports are benign lookalikes; small covert channels and missing egress logs remain unknown. |
| Ransomware/deletion: can damage be limited and service restored? | Needed file/data-effect observations, trust boundary and recoverable snapshot; independent app invariants | Existing segmentation, approved containment and isolated restore drill | File entropy alone is not ransomware proof. Compression/encrypted legitimate data are negative controls. No malware execution is needed for fixtures. |
| Backup failure/contamination: is recovery actually usable? | Available key/integrity/consistency/contamination facts; actual isolated restore and business transaction | Readiness predicate, then pinned-snapshot restore verification | A successful backup job or checksum is insufficient; missing key and inconsistent snapshot are mandatory failures. |
| Supply-chain/release exposure: what was distributed? | Available bounded release audit; needed independent signed build provenance and full served closure | Read-only exposure gate, pinning, server authority | Minification is not confidentiality. Alternate maps/compressed exports/caches and authorized output inference remain limits. |
| AI tool/agent compromise: did untrusted content change authority? | Needed typed tool requests, capability decisions and lineage, without raw prompts/secrets | Deterministic capability/policy gate and cross-case reference denial | A prompt-injection classifier is not an authorization boundary. Benign instructions quoted in a document are a negative control. |
| Telemetry impairment: can any negative conclusion be trusted? | Available source health; needed authenticated source identity, sequence continuity and clock bound | Freshness/loss checks, explicit incomplete status and bounded-state refusal | Quiet traffic, routine restart and sampling differ from hostile loss. Source signatures do not prove factual truth. |

The mechanism distinction in the third row follows MITRE's definitions: [T1110.003](https://attack.mitre.org/techniques/T1110/003/) describes a small password set across accounts and deliberate throttling; [T1110.004](https://attack.mitre.org/techniques/T1110/004/) describes reuse of credentials from unrelated breaches. Without password collection, a detector can find compatible patterns but generally cannot prove which mechanism occurred. The mitigation taxonomy is not our measured attack coverage.

## Method catalog and decision boundaries

All methods below produce observations/candidates first. A detector's matched evidence is distinct from an AI hypothesis, an approved action, an execution receipt and independent effect verification. No score automatically enters the action broker. Unknown data, unsupported semantics and exceeded bounds remain visible gaps; a method cannot clear another source's gap.

### M01 — Schema, authority and invariant checks

Inputs are typed minimized facts, immutable scope, an independently maintained entitlement/change matrix and evidence references. Evaluate a predicate such as `allowed(subject, object, operation, policyVersion)` at the authoritative application, rather than trusting a browser field or model. Reject unsupported fields/types and conflicting duplicate IDs before aggregation. No statistical calibration is necessary, but the entitlement matrix and parser edge cases require review.

Per-record cost is bounded parsing plus indexed policy lookup; cap document bytes, fields, identifier length and state. False positives arise from stale entitlements or legitimate emergency changes. Evasion includes a compromised authoritative source or an overbroad policy. Negative controls include delegated/shared objects and authorized changes; falsification is any accepted forbidden operation or rejected allowed operation in the independently defined matrix. [OWASP API1:2023](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/) requires object-level permission checks for operations on supplied object IDs; matching a session user ID alone is insufficient. Adopt that principle, not a new policy engine.

### M02 — Exact sliding-window denial counts

For grouping key `g=(project, asset, source, subject, object)`, define `D_g(t)=sum(1[decision_i=deny and t-W < observedAt_i <= t])`. A candidate occurs when `D_g(t) >= K`. Start the fixture with `W=60s, K=5`; these are reproducible test parameters, not a production threshold. Compare other frozen pairs on development data, then lock one before held-out evaluation. Add a separate subject-wide view only with explicit semantics; cross-source joins require accepted identity equivalence.

An exact deque gives amortized O(1) updates for sorted input and O(events retained) state. Bound total events/groups/IDs before processing and report incomplete on saturation. Retry loops, buggy clients and shared subjects are confounders. Attackers can spread attempts or stay below K; this is a known detection envelope. Negative controls cross minute boundaries and include K-1 events. Any missed in-window Kth denial, invented match outside the window, or grouping collision falsifies implementation correctness. A match does not prove compromise or even password guessing.

[OWASP Authentication, Login Throttling](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#login-throttling) distinguishes count, observation window and lockout duration, recommends account-associated counters over IP-only counters, and warns about lockout denial of service. Shield's read-only candidate uses none of that as permission to lock accounts. [NIST SP 800-63B-4 §3.2.2](https://pages.nist.gov/800-63-4/sp800-63b.html#rate-limiting) concerns verifier controls for authentication attempts; its upper limit is not an alert threshold and cannot be transplanted to generic authorization events.

### M03 — Distinct fanout and multi-axis counts

Inputs require stable pseudonymous origin, subject, authenticator-outcome and service labels. Count distinct subjects per origin and distinct origins per subject within W, paired with denominator/attempt counts. Use exact bounded sets initially; an approximate sketch requires a separate error contract and offers no benefit for small fixtures. Parameters `(W, distinct_min, attempts_min)` are tuned only on development cohorts; stratify by service and shared network context.

Memory is O(bounded distinct key-value pairs); refuse excess rather than silently evicting data and returning clear status. NATs, corporate proxies, health checks and password-expiry campaigns cause benign fanout. Distributed/slow traffic, label churn and collisions evade it. Falsify with these controls plus a split-origin positive that an IP-only rule misses. Do not implement this on today's subject/object schema and call the object an account or the source collector an attacker origin. [Sigma correlation specification 2.1.0, Value Count](https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html#value-count-value_count) supplies a useful explicit grouping/time/count vocabulary, not evidence that a Sigma query has the same semantics on every backend.

### M04 — Bounded event-time state machine

Inputs are accepted auth decisions for the same explicit key. Keep up to K preceding denial references within W; emit `denial_then_allow` only when an allowance has **strictly later** event time than those denials. Equal timestamps without trusted sequence numbers do not establish order. A stable ID tie-break ensures reproducible serialization, not causality. Reset/consume episode state only by a declared rule, to prevent a single burst generating unbounded repeated candidates.

Sorted offline input costs O(N log N) time and O(N) memory under an input cap; later live processing requires a watermark/lateness contract. Forgotten credentials, corrected object selection and legitimate permission changes produce the same sequence. Source clock skew, duplicate delivery, missing denies and session mixing affect conclusions. Required falsifiers: reversed sequence, equal-time ambiguity, different subject/object/source, cross-window boundary, duplicate and late delivery. [Sigma Temporal Ordered](https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html#ordered-temporal-proximity-temporal_ordered) provides the correlation concept; its compatibility section explicitly warns about lost order and fixed-window boundary errors. Shield must expose such limits rather than claim full Sigma compatibility.

### M05 — EWMA for sustained rate change: research only

For non-overlapping time buckets with sufficient traffic, let `x_t=denials_t/attempts_t`; mark an empty bucket missing, not zero. Use `z_t=lambda*x_t+(1-lambda)*z_(t-1)`, with a proposed starting `lambda=0.2`, frozen clean-development mean `mu0` and independently validated control limit. Require a denominator floor and a warm-up period. Estimate limits from time-blocked benign runs and test correlated/bursty traffic; do not claim a normal-theory false-alarm guarantee for dependent bounded ratios.

State is O(1) per bounded service cohort. Login campaigns, seasonality and outages can shift the rate benignly. Baseline poisoning or gradual drift can evade adaptive variants; freeze reference data during suspected incidents. A matched-budget constant threshold and benign traffic surge are negative controls. Abandon if a clean baseline cannot be identified or it fails to improve held-out detection delay at equal false-alarm load. [NIST EWMA §6.3.2.4](https://www.itl.nist.gov/div898/handbook/pmc/section3/pmc324.htm) supplies the recurrence, dependence on representative in-control data and independence/normality assumptions of common control limits. Security-specific calibration remains our unvalidated work.

### M06 — One-sided CUSUM for smaller persistent shifts: research only

On standardized bucket measurements `y_t=(x_t-mu0)/sigma0`, compute `S_t=max(0,S_(t-1)+y_t-k)` and signal when `S_t>h`. Proposed development grid is `k in {0.25,0.5,1}` and h chosen against a preregistered benign average-run-length target. `sigma0=0`, missing buckets and inadequate warm-up produce unsupported/incomplete status, not division by zero or a zero-risk verdict. Retain bounded evidence refs for the buildup separately from the scalar statistic.

Time/state are O(1) per bounded cohort. Autocorrelation and seasonal changes invalidate naive false-alarm expectations; threshold hugging and baseline poisoning remain possible. Test a persistent low-amplitude shift, a one-bucket benign spike and service-level drift. Falsification is no useful delay/recall improvement over M02/M05 at equal alert cost on chronological holdout. [NIST CUSUM §6.3.2.3](https://www.itl.nist.gov/div898/handbook/pmc/section3/pmc323.htm) explains accumulation around an in-control mean and sensitivity to smaller mean shifts. This is a reason to experiment, not a cybersecurity efficacy result.

### M07 — Existing rule engines with explicit execution semantics

For HTTP, use a pinned CRS policy and capture rule/decision metadata only after source minimization; score aggregation belongs to the configured WAF. For host telemetry, a pinned Falco rule is a source-specific predicate, not a generic alert that Shield can reconstruct from absent process fields. Rule acceptance requires legitimate traffic, known bypass controls, source loss and actual effect tests. Pin exact rule versions and local exceptions; no floating rule synchronization.

Cost depends on enabled rules, buffers and input volume; bound all imports and carry collector drops as gaps. Legitimate encodings/admin tools create matches; parser differences and absent events create misses. Test a detect-only/off arm, actual enforcement and direct-path bypass. [CRS Anomaly Scoring](https://coreruleset.org/docs/2-how-crs-works/2-1-anomaly_scoring/) separates matching/scoring from threshold blocking; blocking a response does not undo a request's backend effects. [Falco Condition Syntax](https://falco.org/docs/concepts/rules/conditions/) defines source-dependent per-event predicates; [Dropped Events](https://falco.org/docs/concepts/event-sources/kernel/dropped-events/) notes that loss can also impair reconstructed context. Reuse these tools later through separately accepted adapters; do not rebuild them as a Go/Rust collector in this slice.

### M08 — Bounded entity/sequence joins for multi-step incidents

Represent accepted observations as labeled edges among opaque identities/assets/objects; join only reviewed edge types within a fixed horizon, e.g. new privilege grant → object access → classified egress. Require an external entitlement/change ledger and explicit join confidence; a same-name account is not an identity proof. Keep graph nodes/edges/depth and retained refs bounded; exact joins on capped data are preferable to unrestricted graph search.

The proposed benefit is fewer isolated-alert ambiguities. Shared service identities, approved deployments and backup transfers form similar paths. A compromised/missing edge, label churn or horizon escape can hide the chain; unrelated edges can falsely connect it. Falsifiers include permuted entities, missing authorization context and a full benign maintenance chain. Measure incremental value against the same individual predicates with identical observations. This is a proposed application of bounded relational reasoning, not a claim of an installed knowledge graph or causal inference.

### M09 — Independent effect and service probes

Inputs are a controlled stimulus, target-side effect counter/invariant and independent observation identity. Compare prevention/response arms with the same planted stimulus and legitimate requests. Record observed new effects during `stimulus → collection → decision → approval → dispatch → independent verification`, including human wait when present. Keep existing/in-flight work separate from new ingress. Probes have fixed attempts/deadlines and never return success after a missing observer.

Per-test cost is bounded requests plus target checks; keep the test identity independent of execution where feasible. Fixture coupling, observer compromise and a control that disables all traffic are confounders. Negative controls include detect-only, origin bypass, failed readback and valid service traffic. Falsification is harmful new effects continuing despite a claimed block, or the service-impact envelope being exceeded. Current [lab results](../lab/RESULTS.md) support only selected ingress and synthetic effects, not host/session/egress containment.

### M10 — Recovery readiness followed by isolated application validation

First evaluate `keyAvailable AND integrity=pass AND applicationConsistent AND NOT contaminated`; this is readiness metadata, not recovery. Then restore a pinned snapshot to an isolated empty target and execute independent integrity/business/health checks. Measure `RTO_observed=usable_check_time-drill_start` and `RPO_observed=incident_boundary-last_accepted_recoverable_commit`, with lost transaction count where possible. Define whether provisioning and human time are included.

Cost is bounded storage/restore volume plus application checks; guard scratch scope and never overwrite production. A planted clean marker may miss real persistence; a corrupt but readable snapshot may violate business invariants. Missing/wrong key, corruption, contamination and app inconsistency are mandatory negative controls. Abandon readiness-as-success wording on any such counterexample. [CISA StopRansomware Guide, prevention and recovery sections](https://www.cisa.gov/stopransomware/ransomware-guide) recommends offline encrypted backups, regular availability/integrity testing and avoiding reinfection during recovery. It does not guarantee that backups erase data disclosure or establish clean trust.

### M11 — Release minimization and bounded server authority

Audit all served exports under a declared closure and move privileged decisions/private code to an authoritative server. Cap operation/object/normalized-parameter/session-bound capabilities, lifetime and principal-wide budgets; atomic replay rejection is necessary. A source map removed from one bundle is insufficient when an alternate export distributes the same source. Keep exact output minimization and allowed-operation tests alongside the exposure gate.

Cost/state are a bounded file inventory plus application-side capability/quota state. Shared legitimate sessions and concurrency are negative controls. Public JavaScript remains inspectable; valid output queries can reveal a function and historical caches can retain source. Falsify with leaked private markers, wrong-object accepted effects, replay/race/quota bypass and authorized black-box inference. The [REA research](REA_DEFENSE_RESEARCH.md) and [anti-REA results](../lab/ANTI_REA_RESULTS.md) distinguish reduction of shipped information from claims to defeat reverse engineering. No anti-debugging, parser abuse or model poisoning is justified.

### M12 — AI as a bounded investigator, not an actuator or truth oracle

Give the model minimized accepted facts, candidate refs, gaps and reviewed read catalog. It must return competing hypotheses, counterevidence and a typed bounded next observation or proposal. Compare rules-only, rules+catalog lookup, rules+AI and rules+AI+challenge with equal evidence/read/time budgets. Change one component at a time; the challenger must not be scored as independent ground truth merely because it is a different context.

Cost is the existing episode/call/token/deadline policy, with explicit unavailable/degraded outcomes. Fluent unsupported explanations, instruction injection, unnecessary reads and longer operator time are adverse outcomes. Negative controls quote benign instructions and inject forbidden/cross-case action requests. Falsifiers are fabricated refs, unauthorized authority, or no material quality/time benefit after costs. [OWASP LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) describes the content/instruction boundary problem; its mitigations do not make a classifier or prompt an authorization boundary. An actual provider and separately accepted data policy are required before scoring AI; none is presumed here.

### M13 — Calibration, abstention and probability claims: defer until data exists

Current `suspicious/benign/insufficient_evidence` labels are policy outputs, not calibrated probabilities. If a later learned score exists, fit calibration only on a separate development/calibration set and report reliability diagrams, Brier score and selective risk versus coverage by incident family. Equal average calibration can hide badly miscalibrated rare incidents. Do not treat LLM self-reported confidence as a calibrated compromise probability.

[Guo et al., ICML 2017](https://proceedings.mlr.press/v70/guo17a.html) studies post-hoc neural classifier calibration on image/document tasks; it supplies a method to evaluate, not validation for an LLM SOC. [Angelopoulos and Bates, arXiv:2107.07511v6](https://arxiv.org/abs/2107.07511v6) explains conformal prediction with calibration data and validity assumptions. Ordinary split conformal needs exchangeability for its marginal guarantee; time drift/adversarial adaptation can break it, and marginal coverage is not conditional coverage for each rare attack. Defer conformal/Bayesian probability output until a defined label process, sufficient independent data and shift tests exist. Bounded abstention remains useful now without pretending to a statistical guarantee.

## Preregistered experiment protocol

All hypotheses below are **unrun proposals** unless an individual existing lab record is cited. Authoring this table passes no efficacy gate. A public deterministic regression fixture is necessary for implementation semantics but is no longer hidden test data. No result on that fixture may be described as new held-out performance after tuning.

1. Freeze source contract, input policy, exact detector/config/hash, clocks, corpus manifest, scorer and accept/abandon criteria before scoring. Keep generator seeds and labels outside model/rule inputs. The controller records intent and actual effect independently of detector labels. Known-source synthetic facts test semantics; later raw-telemetry discovery requires a separate trial.
2. Use a development/calibration partition and an untouched chronological holdout, grouped by complete incident run, identity cohort, application and generator family. Never split near-duplicate events/windows from one run across partitions. Include service upgrades, temporal drift, missingness and a fresh scenario author. Hold out generator families as well as seeds; changing only random seed is weak generalization evidence.
3. Initial engineering regression minimum is 20 positive, 20 benign-lookalike and 20 incomplete/adversarial runs per implemented family, with explicit boundary variants. A proposed offline efficacy trial uses at least 100 independent incident runs and 300 benign runs per family, plus 100 missing/drift runs; these sizes are a starting feasibility budget, not a universal power analysis. Run a prospective pilot only after scope/data gates and pilot-specific power/precision requirements are accepted.
4. Report incident-level precision, recall, false alerts per active asset-hour, first correct-candidate delay, missed/late cases, abstention, contradictions, analyst time, service harm, CPU/RSS, throughput and total cost. Keep decisive benign coverage separate from zero false positives. Report clustered uncertainty by run/site/time block; events within a run are not independent samples. Zero errors in 300 independent negatives gives only an approximate one-sided 95% upper bound near 1% under a binomial model; it says little about a different site or correlated traffic.
5. Include no-incident and no-effect controls, event duplication/reorder/skew/drop, cap exhaustion and model outage. Score wrong confident closure more severely than an honest gap. An incomplete run remains in the denominator; never discard difficult imports or provider failures to improve accuracy.
6. Predeclare the operational loss tradeoff. For the first candidate-only slice, the proposed gate is zero authority/secret/scope violations, exact semantic boundary behavior, no false `complete` on loss/caps, and useful candidate improvement at matched false-alert/abstention budgets. Later containment has a stricter legitimate-service impact envelope approved by the owner. No aggregate average can offset an always-blocking guardrail failure.

## Hypothesis register

Here `H0` is the no-benefit or failure explanation, not a claim that a fixture p-value can establish production safety. `Baseline` always receives identical input and time/access budget. Engineering invariants require exhaustive selected boundary/property tests; statistical efficacy uses the split protocol above. Acceptance margins below are proposed owner-review values and must be frozen before experimentation.

### H01 — Denial burst semantics

- **H0 / H1:** A bounded sliding correlator offers no correct new auth candidate / it identifies exactly the declared K-in-W pattern without cross-key mixing.
- **Baseline and truth:** Current Python baseline; independently authored synthetic timestamps/keys and a simple offline reference enumerator, not Go output as its own oracle.
- **Design and measures:** At least 60 regression runs, K-1/K/K+1, t-W/t and minute-boundary cases; fresh chronological/generator holdout for efficacy. Measure exact matched IDs, alert count, latency and incomplete status.
- **Accept / abandon:** All semantic cases agree with the reference and no cap is silent; then require improved recall for the declared pattern at a frozen benign budget. Abandon an attack claim if only fixture count consistency is established.

### H02 — Denial then allowance

- **H0 / H1:** Ordered correlation adds only noise / it adds evidence-referenced access-change candidates beyond M02.
- **Baseline and truth:** Denial count alone; controller labels distinct successful retry, approved permission change and planted unauthorized allowance separately.
- **Design and measures:** At least 20 of each sequence plus equal-time, reversed, different-entity/source and missing-denial controls; grouped/temporal holdout. Measure sequence recall, benign candidate rate and proportion correctly retained as unknown compromise.
- **Accept / abandon:** Every tied/reversed/cross-key negative behaves as specified, and correct candidate recall improves at matched alert volume. Abandon account-takeover wording whenever independent session/intent evidence is absent.

### H03 — Visibility-aware abstention

- **H0 / H1:** Missing/drop/stale handling hides uncertainty / the correlator preserves a gap while retaining any still-supported positive observation.
- **Baseline and truth:** Same rules with health checks disabled; controller's source-loss schedule, receive clock and expected-source inventory.
- **Design and measures:** At least 60 complete/loss/recovery runs with no-health, per-source loss, old healthy event after loss, cap exhaustion and skew. Hold out outage duration/source patterns. Score false complete verdicts, unnecessary abstention and gap recovery semantics.
- **Accept / abandon:** Zero false complete outcomes in boundary tests; complete normal traffic remains analyzable. Abandon if clearing one source erases another source's gap or an outage is called safety.

### H04 — Stable delivery and duplicate semantics

- **H0 / H1:** Delivery artifacts change results / offline order normalization and strict ID checks make supported output independent of file arrival order and identical redelivery.
- **Baseline and truth:** Single canonical run versus its independently generated permutations/duplicates; conflicting duplicates have an explicit rejection oracle.
- **Design and measures:** At least 100 bounded randomized permutations across 20 runs, equal timestamps, conflicting fields and late records. Keep new boundary combinations for holdout. Measure byte-equivalent normalized candidates and exact rejection/incomplete outcomes.
- **Accept / abandon:** Semantic output agrees for all supported permutations; conflict never silently wins. Abandon a live-stream claim until watermark, lateness and checkpoint/crash semantics are separately tested.

### H05 — Multi-axis auth visibility

- **H0 / H1:** Distinct-origin/subject aggregation adds no value / it detects distributed patterns missed by a single-origin count at matched benign alert load.
- **Baseline and truth:** Account-only and origin-only rules, equal source fields; controller knows campaign membership, shared NAT and legitimate reset campaign.
- **Design and measures:** Proposed efficacy minimum 100 incident/300 benign/100 drift runs after a new source contract is accepted; split complete campaigns and identity pools. Measure recall, NAT false alerts and label sensitivity; never supply password values.
- **Accept / abandon:** Proposed >=10 percentage-point recall gain at <=1% benign-run candidate rate with uncertainty reported. Abandon a mechanism-specific label if outcomes cannot distinguish spraying from stuffing; current schema cannot run this experiment honestly.

### H06 — EWMA drift benefit

- **H0 / H1:** EWMA only changes the threshold tradeoff / it detects a sustained shift sooner at equal false-alert exposure than M02.
- **Baseline and truth:** Frozen fixed-window rule, same buckets and clean calibration data; independent shift onset and benign seasonal schedule.
- **Design and measures:** At least 100 shifted and 300 benign chronological runs, correlated traffic, low denominators and poisoned warm-up; separate calibration and generator-family holdout. Measure delay distribution, false alerts per asset-hour and unknown rate.
- **Accept / abandon:** Proposed >=20% median delay reduction without a material false-alert/abstention increase; abandon if credible in-control calibration is unavailable or drift overwhelms benefit. Do not implement by default before this test.

### H07 — CUSUM incremental benefit

- **H0 / H1:** CUSUM adds no value beyond M02/M05 / it catches small persistent shifts at an acceptable time/state cost.
- **Baseline and truth:** Best frozen M02/M05 at identical false-alert budget; independently placed low-amplitude shift and no-shift controls.
- **Design and measures:** Same minimum and blocked split as H06, with zero-variance/missing-bucket controls. Measure delay, worst cohort false alerts, sensitivity to k/h and bounded buildup evidence.
- **Accept / abandon:** Proposed >=20% additional delay improvement or meaningful missed-case reduction, with stable held-out behavior. Abandon if the simpler method is within the preregistered equivalence margin or parameters are fragile across cohorts.

### H08 — WAF prevention with legitimate service preservation

- **H0 / H1:** A rule match does not stop a selected harmful effect / the supported request policy stops that effect while allowed traffic remains functional.
- **Baseline and truth:** Off and detect-only versus enforce; separate origin effect/reach probes and known legitimate application outcomes.
- **Design and measures:** Existing three planted patterns are regression evidence only; future efficacy needs independently authored attack-family/encoding holdouts and at least 300 diverse benign runs. Measure effect delta, bypasses, false denials, service latency and source leakage.
- **Accept / abandon:** Zero planted effects through the claimed path and approved legitimate-traffic envelope. Abandon general exploitation/recall claims from marker-only stimuli; any untested bypass stays explicit.

### H09 — Server authority survives client reconstruction

- **H0 / H1:** Removing browser logic alone protects privileged behavior / server-side object/operation/parameter binding prevents unauthorized effects despite readable client/API structure.
- **Baseline and truth:** Client-only gate and the same legitimate outputs; independent allowed-object matrix, effect counter and all served exports.
- **Design and measures:** Retain current anti-REA regression; add held-out concurrency/replay/quota and alternate-export tests. Measure forbidden accepted effects, valid completion and shipped private markers. Include authorized output inference as a residual counterexample.
- **Accept / abandon:** Zero forbidden effects in declared cases, equivalent legitimate outputs and complete claimed export audit. Abandon any promise to stop all reverse engineering or infer algorithm confidentiality from parser failure.

### H10 — Multi-step context improves triage

- **H0 / H1:** Entity joins create coincidental narratives / a reviewed grant→access→egress sequence improves correctly scoped incident triage over independent rules.
- **Baseline and truth:** Same individual predicates/evidence budget; controller knows entitlement changes, export intent and actual transfer effects.
- **Design and measures:** At least 100 incident/300 maintenance-lookalike runs once necessary sources exist; hold out organizations, entities and benign maintenance templates. Score precision/recall, cross-identity joins, missing-edge abstention and analyst time.
- **Accept / abandon:** Proposed >=10 percentage-point incident recall gain at matched false-alert load, no invented joins. Abandon if identity equivalence or required edges cannot be established; a prettier graph is insufficient.

### H11 — Effect verification catches false containment

- **H0 / H1:** Executor success is adequate / independent probes reveal continued harm or excessive service impact that a receipt misses.
- **Baseline and truth:** Executor/readback receipt alone versus independent observer; controller injects successful receipt with bypass, lost response, in-flight work and failed management path.
- **Design and measures:** At least 20 per failure class, repeated timing trials and independent holdout failures; measure false verified outcomes, damage window, benign outage and unknown completion.
- **Accept / abandon:** Zero verified containment when the declared effect continues; preserve correct narrower new-ingress statements. Abandon full-containment claims whenever identity/host/egress/in-flight paths remain untested.

### H12 — Recovery metadata is insufficient

- **H0 / H1:** Successful job/hash/readiness implies usable recovery / isolated application validation catches unusable snapshots that metadata accepts.
- **Baseline and truth:** Backup job/readiness status; independently checked application transactions, integrity and seeded trust/consistency invariants.
- **Design and measures:** At least 20 usable and 20 for each key/corruption/contamination/consistency failure class; hold out snapshot layout and failure combinations. Measure false recovery success, actual lost transactions, restore delay and service usability.
- **Accept / abandon:** Every known unusable case fails or stays inconclusive; no production overwrite. Abandon eradication/no-exfiltration claims from a passed restore or planted clean marker.

### H13 — AI adds useful investigation under equal access

- **H0 / H1:** Rules+lookup performs as well as AI after costs / bounded AI materially improves correct competing hypotheses or useful evidence selection.
- **Baseline and truth:** Frozen rules+lookup and human-only workflow, then AI and AI+challenge; independent scenario labels plus blinded expert adjudication with recorded disagreements.
- **Design and measures:** Requires an actual permitted provider and fresh ambiguous multi-step cases, >=100 incident/300 benign runs and repeated seeds/model runs. Randomize operator crossover order, isolate learning effects and keep evidence/read/time budgets equal. Report paired/clustered uncertainty, supported conclusions, fabricated refs, decisions, cost and analyst time.
- **Accept / abandon:** Proposed >=15% analyst-time improvement with noninferior supported decision quality and zero guardrail failures. Abandon/defer AI if benefit is absent, evidence access differs or a test double supplies the result. Current endpoint/AI benefit remain unmeasured.

### H14 — Challenge improves safety rather than merely agreement

- **H0 / H1:** A second model adds cost or correlated confidence / challenge finds material contradictions without making correct cases worse.
- **Baseline and truth:** Same AI arm without challenge, with a total budget matched alternative such as one more catalog read; independent effect truth and adjudicated contradiction labels.
- **Design and measures:** H13 grouped/temporal cases, injected unsupported claims and benign explanations; no shared answer key. Measure corrected errors, introduced errors, residual unsupported claims, time/cost and useful coverage.
- **Accept / abandon:** Proposed >=20% unsupported-conclusion reduction with no material loss of decisive coverage at matched budget. Abandon if agreement is the only evidence or gains disappear against the extra-read baseline.

### H15 — Resource bounds preserve honest outcomes

- **H0 / H1:** Go throughput makes caps unnecessary / explicit input/time/state/output bounds prevent runaway work and expose incomplete coverage under adversarial volume.
- **Baseline and truth:** Supported small runs plus boundary/cap-exceeding corpora; independent process wall time/RSS/output size and reference semantics for accepted prefixes/full runs as declared.
- **Design and measures:** Fuzz malformed JSON, huge identifiers, duplicate floods, high-cardinality churn and truncated files; at least 100 deterministic seeds, race tests where concurrent and repeated local benchmark sizes. Record Go/toolchain/OS/CPU/config and read/parse/sort/analysis times separately; hold out stress shapes.
- **Accept / abandon:** Zero silent truncation, panic, authority escape or false complete outcome. Freeze a measured machine-specific latency/RSS budget before release. Abandon unsupported scale claims; a microbenchmark cannot establish lower end-to-end incident latency or Rust necessity.

### H16 — Confidence claims remain calibrated under selection

- **H0 / H1:** A learned/self-reported confidence is reliable enough / a separately calibrated system improves probability quality and selective risk on fresh data.
- **Baseline and truth:** Current categorical abstention and uncalibrated learned score; independently adjudicated outcomes with unresolved cases retained as unresolved.
- **Design and measures:** Separate training/calibration/temporal test sets with no incident/identity overlap; prospective sample size determined for rare-event uncertainty, not the 60-case regression minimum. Report Brier score, reliability, risk-coverage, per-family uncertainty, shift and poisoning failure.
- **Accept / abandon:** Require a preregistered material improvement with stable cohort coverage; abandon numeric probabilities if labels/data/assumptions cannot support them. Ordinary conformal marginal coverage must not be sold as per-attack or adversarial reliability. This remains deferred research.

## First Go delivery contract recommendation

Implement only M01/M02/M04 and visibility accounting needed by H01–H04/H15. Use a standard-library executable over a bounded offline synthetic file; no listener, network, provider, host collector or actuator. Accept only the reviewed schema and reject unsupported kinds/fields explicitly rather than quietly treating the whole project as analyzed. Reuse opaque IDs and source/asset/case boundaries; do not add raw usernames/IPs/tokens for convenience.

The result should carry schema/config/input digest, actual evaluated time range, matched evidence refs, per-rule candidate code, source trust assertion, gaps and explicit `targetCodeExecuted=false`, `networkRequestsMade=false`, `actionAuthority=none`. Candidate absence is not a safety verdict. Keep `candidateCount=0` separate from `coverageComplete`; missing health, loss, untrusted clock, unsupported order or exhausted caps must remain inspectable. A local source label is an operator assertion, not authenticated telemetry.

Freeze exact event-time window boundaries, timestamp tie behavior, duplicate/conflict semantics, source-health recovery and saturation behavior in golden fixtures before comparing implementations. Prefer sorting a fully bounded offline input to inventing a streaming watermark system. Unknown object semantics must not become a login or attacker origin. The next implementation can be useful by detecting a previously ignored sequence while honestly abstaining on its cause.

Compare Go and the simplest equivalent Python reference using the same semantics and fixture manifests; report end-to-end cold start, JSON ingestion, analysis, output, CPU/RSS and correctness before speed claims. Keep language migration independent of efficacy. Add Rust only if a measured parsing/memory-safety/isolation requirement survives review and its foreign-function/build/deployment cost is justified. No all-at-once rewrite, broker, generic plugin system, custom SIEM or host agent is needed for this experiment.

## Source adoption and limits

All external materials above are primary project documentation, standards bodies or original papers, reviewed on 2026-10-24. This file imports no rule/code/model/dataset and executes none of them. Standards revision, Sigma specification version and paper version are stated where fixed; live OWASP/Falco/MITRE/CRS pages may change and must be re-reviewed/pinned before implementation-level imports. Their links support the named definition/mechanism only; proposed parameters, trial sizes, effect margins and incident designs are OpenShieldAI research decisions. References confer no source authentication, deploy authority, license exemption or measured local effectiveness.

Any later imported artifact must separately record exact commit/version, license/notice, modifications and tests under the [manual upstream policy](../MANUAL_UPSTREAM_ENRICHMENT_POLICY.md). Keep the current root PolyForm Noncommercial license. Open research hypotheses, missing sources, unconfigured real AI and unaccepted production identity/actuation remain explicit limitations.
