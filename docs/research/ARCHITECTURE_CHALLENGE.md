# Architecture challenge: does the defense actually work?

Review date: **2026-10-24**. Reviewer role: independent, deliberately skeptical architecture reviewer. Initial review scope: the original S0 specification, including the PRD, architecture, guardrails, acceptance criteria, worker/model contracts, evaluation plan, and incident playbooks. The final section records the review of the subsequent deeper design. **No runtime, attack replay, response adapter, or restore drill was executed.**

## Verdict and the four required answers

The existing specification establishes useful authorization and evidence boundaries. Those boundaries prevent some mistakes by the defender; they do not, by themselves, stop an attacker. The architecture needs an explicit chain from observable behavior to a deployed control and an independently measured outcome.

| Owner question | Honest answer at S0 | What would justify a stronger answer |
| --- | --- | --- |
| Can it actually prevent attacks, and how? | No demonstrated prevention exists. The proposed system can assess preparedness and propose controls. Actual prevention must happen in an installed enforcement mechanism. | Name the control point, attack property it blocks, configuration, bypasses and failure behavior; demonstrate a blocked harmful effect while legitimate work succeeds. |
| Can it respond while an attack is happening, and how? | No live response exists. Investigation and bounded action proposals are a plausible path, but human approval and source delay may exceed the attack's damage window. | Show the complete detection-to-verified-containment trace, including approval delay, growing damage, response failures, and whether the chosen control cuts the attacker path. |
| Can it handle the aftermath, and how? | Recovery guidance is specified. Successful restoration and removal of persistence have not been demonstrated. | Restore usable application state from a trusted recovery point into isolation, test actual business invariants, address entry/persistence, and record the remaining confidentiality loss. |
| Where is AI continuously present, and how? | Listed model use cases are not an operational supervision loop. No scheduler, triggers, evidence-delta policy or measured AI benefit exists yet. | Specify bounded lifecycle triggers, available context, typed outputs, cadence/deadlines, stale-state handling and outage behavior; show incremental value against the same workflow without AI. |

The acceptable goal is **measurably better defense for declared scenarios**. Neither an unbounded promise nor an indefinitely advisory chatbot answers these questions.

## Missing-mechanism register

These are review requirements, not additional integrations or permission to implement them. `Unproven` means a design or implementation gate remains open; it does not mean the mechanism is impossible.

| ID | What the current specification already does | Missing mechanism or unresolved decision | Required evidence before the claim |
| --- | --- | --- | --- |
| M1 | Evaluates Coraza/CRS or CrowdSec as candidates | No selected first deployment topology, enforcement point, supported version or configuration transaction | One declared path from ingress to application; exact adapter operations and observation path; direct-origin and alternative-route bypass tests |
| M2 | Requires a deterministic detection baseline | No scenario-specific features, field mapping, event window, thresholds, deduplication or benign exceptions | Executable rule contract and held-out incident/benign fixtures; missed-event and schema-drift tests; precision/recall with `unknown` included |
| M3 | Requires bounded jobs and coverage gaps | No end-to-end freshness/latency budget or overload policy tied to ongoing harm | Source-to-decision and decision-to-verified-effect p50/p95; approval time included; queue age/drop metrics; alert flood and slow-source results |
| M4 | Defines typed proposed actions and immutable approval | The sample `temporary_ingress_rule` has no catalog implementation, configuration CAS/version semantics, dependency effect or target-side TTL behavior | Exact allowlisted action, pre/post-state, per-action capability, smallest affected scope, known rollback/compensation and crash reconciliation |
| M5 | Separates action receipts from verification | No concrete verifier inputs, success predicate, observation duration or failed-verification escalation for the selected scenario | Read actual installed state plus an independent probe/telemetry source; demonstrate intended effect, legitimate traffic and residual bypasses |
| M6 | Identifies integrity-uncertain hosts and clean rebuild needs | An ingress WAF/rate limit does not remove an already-running process, stop all egress or invalidate stolen credentials | Explicit action-to-threat coverage; mark unsupported persistence, egress and credential paths; human-run or separately accepted containment for those paths |
| M7 | Requires isolated restore and application invariants | No selected dataset, recovery-point selection rule, consistency procedure or reconnect gate | Actual known-good records/transactions, declared loss bound, isolated restore, application queries and contamination checks; missing-key/corrupt/compromised-backup failures |
| M8 | Lists model use cases and budgets | No lifecycle trigger matrix, delta reasoning, priority/cancellation rules or AI health/coverage state | Per-phase invocation contract; evidence-version binding; bounded scheduling; stale answer invalidation; explicit model-degraded operation |
| M9 | Requires baseline and AI ablations | No held-out run results show an AI advantage over rules, timelines and playbooks | Same inputs, permissions and time budget; measure correctness, harmful mistakes, operator minutes, end-to-end latency and cost; report non-improvements |
| M10 | Uses single-operator local architecture and external evidence references | No measured availability/failure-domain boundary for defending the service that hosts Shield | Separate management/backup trust paths in the lab; Shield loss does not disable installed protection; operators can use the runbook without the model/UI |

The mechanism register should shrink through concrete decisions and experiments. Adding more tool names or model roles does not close it.

## 1. Prevention: questions that must be answered

- **Which harmful operation is prevented?** Distinguish exploit request, unauthorized application operation, credential misuse, unwanted process execution and resource exhaustion. Each needs a compatible control point.
- **Where is the control on the actual path?** Show edge/proxy, identity provider, host/workload, egress and backup boundaries only where they exist. An attacker bypassing the proxy through a reachable origin invalidates an ingress-only claim.
- **What is already installed before an incident?** Fast protection cannot depend on a fresh LLM answer or an operator noticing an alert. Existing reviewed controls continue enforcing their own configuration independently of Shield.
- **What does AI add before the attack?** It can propose evidence-backed control gaps, evaluate exposure paths and help prepare reviewed policies. A proposal alone does not reduce risk; the installed configuration and its tested effect do.
- **How is collateral harm bounded?** Include authenticated legitimate traffic, shared IP/NAT, APIs, large requests, deployment changes and recovery/administrator access in the negative controls.
- **What still bypasses the control?** A WAF does not establish object-level authorization, remove a stolen session or absorb an upstream-saturating volumetric attack. Supported claims must name these limits.
- **How do we know it kept working?** Monitor source/control heartbeat, active configuration/version, expiry, dropped events, bypass path changes and service health. No alerts is not the success predicate.

**Pass criterion:** in the declared environment, the expected harmful effect succeeds in the unprotected lab baseline, fails under the reviewed control, and does not become a false claim when the observation source is missing. Legitimate-task and service-health budgets must pass as well. A blocked request counter is insufficient.

## 2. Ongoing attack: questions that must be answered

- **What turns observations into a case?** State exact features/windows, required corroboration, confidence basis, competing benign causes and what missing telemetry does to the decision.
- **How old is the decision?** Capture source event time, receive time, case revision, model context revision, approval time, dispatch and verified-effect time. A model answer based on superseded state cannot authorize the new state.
- **What can happen while humans deliberate?** Measure damage accumulation and declare which existing fast controls operate meanwhile. If no supported control acts in the attack's time window, classify the result as investigation assistance rather than real-time prevention.
- **Does the proposed action break the attack chain?** Restricting a URL is irrelevant if stolen credentials still access the database; removing a route is incomplete if the workload maintains outbound access. Inventory live attacker paths, not only the initial trigger.
- **What is the narrowest useful scope?** Prefer a declared rule/route/workload only when it actually contains the threat. A narrow action that cannot stop the damage is not better merely because it is low risk.
- **What if the API times out after applying the control?** Persist intent, mark unknown outcome, inspect state and reconcile before retry. Demonstrate the response under crash and lost-reply faults.
- **What if nobody can approve in time?** The current release boundary requires explicit action approval. Escalate through the operator's existing emergency process, keep installed controls running, and expose the delay. Do not silently create model authority or promise unattended containment.
- **What if protection breaks the service?** Check real user requests and dependency health, preserve management access, and use the declared rollback/compensation or operator escalation. A command exiting zero is not containment.

**Pass criterion:** independently generated lab harm decreases or stops within the registered scenario deadline, without exceeding the accepted collateral-impact bound. The latency calculation includes detection, queueing, AI, human approval, execution and verification. If the sample cannot demonstrate this, remain in shadow/advisory mode for that scenario.

## 3. After the attack: questions that must be answered

- **Which security properties are being restored?** Track availability, integrity and confidentiality separately. Restoring availability cannot undo stolen data.
- **What proves the recovery point is usable?** Backup existence, encryption and a manifest hash do not establish clean application state. Identify keys, retention, snapshot consistency, protected copies and the earliest known compromise interval.
- **What if compromise predates every retained backup?** Record that no known-clean point exists. Clean rebuild plus reviewed data salvage may be a human investigation path; AI cannot fabricate trustworthy missing records.
- **What is rebuilt and what is copied?** Use trusted artifacts/configuration for compromised executable state. Do not restore untrusted persistence or reuse exposed identity material because an application starts.
- **What are the business invariants?** Define concrete expected transactions/records, referential consistency, owner access, dependency functionality and acceptable loss. A file hash check alone does not answer them.
- **What prevents reinfection?** Address initial entry, persistence, exposed identities/secrets and vulnerable configuration before approved reconnection. State the paths that could not be investigated.
- **Who verifies the result and for how long?** Use separate observations, declared duration/coverage and reopening conditions. An arbitrary quiet period cannot prove eradication of unknown persistence.
- **What is permanently lost or still uncertain?** Preserve actual RPO/RTO, unavailable records, possible disclosure, unsupported systems and owner acceptance separately from a case's closed workflow status.

**Pass criterion:** a real isolated drill restores a usable application meeting its registered data/service assertions; bad keys, inconsistent snapshots and known-contaminated restore points cannot produce `recovery_verified`. Independent return-of-service evidence and residual compromise/exposure statements are mandatory.

## 4. AI presence: questions that must be answered

“Always present” should mean a continuously available, bounded supervisory workflow over changing evidence. It should not mean inference on every packet, uninterrupted token generation, unrestricted agents, or claiming that a loaded model is protection.

| Lifecycle point | Proposed AI contribution worth testing | Required trigger/input | Required output and non-AI continuation |
| --- | --- | --- | --- |
| Enrollment/readiness | Explain control/dependency gaps and recovery priorities | Accepted inventory/control-state revision or an explicit operator review | Evidence-linked gap list; deterministic posture checks/runbook still available |
| New observation/case | Correlate related signals and competing explanations | Deduplicated candidate batch with declared window/priority | Typed hypotheses, contradictions and missing evidence; deterministic alerts remain visible |
| Active investigation | Rank next permitted evidence requests | New relevant facts, failed collection, changed impact, or operator request | Known request IDs and expected information value; operator can follow fixed investigation steps |
| Action preparation | Tailor a reviewed playbook to the observed case and challenge dependency risks | Stable evidence revision and declared action catalog | Typed proposal with cited preconditions; policy/human authority unchanged |
| Action monitoring | Explain failed or partial effects and changing incident scope | Independent postcheck, new source state or timeout | Revised hypotheses/proposal; actual verifier determines state, not the explanation |
| Recovery | Explain snapshot/readiness differences and failed application assertions | Versioned backup metadata and actual isolated-drill observations | Evidence-linked recovery options and unresolved loss; existing recovery procedure remains usable |
| Post-incident improvement | Propose reviewed rule/control/runbook changes | Operator-reviewed case/verification outcome | Draft changes tied to the failure; held-out evaluation before activation |

Every trigger needs an evidence revision, queue priority, debounce/coalescing rule, context limit, deadline, cancellation rule, per-case budget and retry ceiling. Record `enabled`, `healthy`, `degraded`, `disabled` and actual last completed evidence revision; a UI presence indicator must not imply continuous coverage.

On a model outage, retain deterministic detection, installed protections, case state and operator runbooks. On telemetry loss, expose a visibility gap. The system must not infer “no attack” from either failure. On renewed evidence, schedule only bounded useful work and invalidate stale model conclusions. Never let the model's own output recursively create endless new work.

**Pass criterion:** for at least one declared workflow, AI improves the registered operator/correctness outcome beyond the identical deterministic system without violating safety/service budgets. Measure no-AI, AI and AI-plus-challenge variants separately. If AI adds only words, remove or redesign that use case; preserving AI branding is not an acceptance criterion.

## Mandatory scenario traces

The deeper design must provide runnable specifications for these traces before claiming corresponding capabilities. Later-family traces can remain explicit unsupported research cases; they do not force all families into the first release.

| Trace | The architectural question it must settle | Required discriminating case |
| --- | --- | --- |
| T1: exploit attempt at the enrolled web ingress | Does a selected control block the harmful effect on the real path? | Legitimate lookalike, direct-origin bypass and delayed/missing logs |
| T2: compromised web workload continues after ingress blocking | Does the response understand the difference between entry mitigation and containment? | Existing outbound connection/persistence remains; output must not claim eradication |
| T3: abnormal login or export | Can it distinguish successful abuse from failed attempts and legitimate bursts? | Shared NAT/legitimate bulk export; stolen valid session; unsupported identity enforcement |
| T4: destructive changes plus suspicious backup activity | Can recovery remain trustworthy when production identity/storage is compromised? | Simulated data loss, missing/corrupt/keyless snapshot and a restore point inside the compromise window; no malware execution |
| T5: malicious log/tool output instructs the defender to disable protection | Is AI useful while hostile evidence remains powerless over authority? | Untrusted instruction preserved as evidence; no additional tool/capability/egress permission |
| T6: alert flood, model outage and stale approval during an active case | Does the system degrade honestly while the existing protections keep working? | Queue expiry, unsupported source, revised target state and ambiguous action reply |

Each trace must state: enrolled asset and topology; attacker objective and bounded lab stimulus; independent ground truth; benign lookalike; inputs and telemetry limitations; rule decision; AI's exact task; control/action catalog ID; authority; state/version checks; blast radius; full latency timestamps; independent effect and service-health predicates; failure/rollback path; and allowable final claims. Missing any part means that trace is still a design hypothesis.

## Review gates and stop conditions

1. **Design gate:** every claimed family has a complete trace, control point, source mapping and explicit unsupported paths. A “future adapter” box cannot close an efficacy question.
2. **Replay gate:** deterministic and AI variants run on incident-level held-out positives, benign lookalikes, missing/contradictory telemetry and hostile-input cases. Count misses and inconclusive results; do not discard failures.
3. **Enforcement gate:** a supported installed control changes actual lab outcomes; false blocking, bypasses, latency, TTL cleanup, rollback and lost-reply reconciliation are exercised.
4. **Recovery gate:** an isolated application restore actually runs; integrity, business invariants and recovery objectives are observed, not inferred from a listing.
5. **Pilot gate:** publish the exact environment/version, accepted workload, owner-approved impact/latency envelope, uncertainty and residual risk. A large-system or enterprise claim needs separate load, tenancy, availability and failure-domain evidence.

Any unauthorized effect, fabricated verified result, secret disclosure, destruction of original evidence or unsafe production overwrite blocks the release. A system that safely refuses all useful work also fails the value gate. If a scenario is too fast for this approval design, narrow the claim and use proven existing prevention; do not hide the limitation by renaming a proposal “response”.

## Primary references and interpretation

- [NIST SP 800-61 Rev. 3, final April 2025](https://csrc.nist.gov/pubs/sp/800/61/r3/final) places incident response inside wider preparation, detection, response and recovery activities. This review uses that lifecycle, not a claim of NIST validation.
- [CISA #StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide), consulted 2026-10-24, supports coordinated containment, protected backups, clean restoration and dependency-based recovery. Those practices motivate the recovery tests; they do not prove a Shield implementation.
- [MITRE D3FEND Restore tactics](https://d3fend.mitre.org/tactic/d3f%3ARestore/), consulted 2026-10-24, distinguishes restoration operations such as data/network access and credential reissue. Taxonomy is a vocabulary, not a control test.

This review does not supply runtime measurements, independently reproduce the papers in the research inventory, select a production integration or authorize response actions. The missing mechanisms and pass criteria above are project design judgments; numerical response/service thresholds must be registered with the actual scenario owner before evaluating a release.

## Review of the deeper design and disposition

Reviewed the new [core questions](../CORE_QUESTIONS.md), [operating architecture](../OPERATING_ARCHITECTURE.md) and [ADR 0002](../adr/0002-continuous-ai-and-enforcement-planes.md). The missing-mechanism table above records the original design baseline, not a claim that no subsequent decisions were made. A design decision closes an ambiguity; only an experiment can close the corresponding efficacy gate.

The new design selects a real traffic control point, separates fast enforcement from AI supervision, defines temporal state and bounded scheduling, picks one ingress-maintenance actuator and describes independent application/restore assertions. That is a substantial architectural improvement. It still demonstrates no actual prevention, containment or recovery.

| Original gap | Deeper-design disposition | Remaining requirement |
| --- | --- | --- |
| M1: no first control point/topology | **Addressed in design:** Caddy/Coraza/CRS, private origin and separate management environment | Select/pin the resolved build and demonstrate connector order, route coverage, bypasses and source minimization |
| M2: detection semantics | **Partially addressed:** temporal state/windows and an explicit first-lab scheduler trigger catalog are selected; denial counts are correctly not incident verdicts | Actual source mappings, detector behavior and benign/attack fixtures still need a supported-scenario contract; test low-rate/multi-step attacks that do not cross the wake-up thresholds |
| M3: latency/overload | **Addressed as an experiment plan:** individual clocks, queue/budget ceilings, proposal targets and human-inclusive total | Measure nominal/overload behavior and harm; a target or deadline is not an observed SLO |
| M4: exact response operation | **Addressed in design after D1-D3 corrections:** impact-bound maintenance, target-side conditional mutation, separated grant/review/lifetime and no generic config | Demonstrate real build conflict handling, reconciliation, approved compensation and outage behavior |
| M5: verification predicates | **Addressed in design:** separate request counter, management probes and application invariants | Implement trustworthy observations and scenario-specific success/service-impact predicates, including D4 |
| M6: false ingress-to-host containment | **Addressed in claim scope:** explicit host, identity, session and egress limitations | Test that reports preserve those limits and do not promote an ingress result to whole-incident closure |
| M7: actual recovery protocol | **Partially addressed:** pinned snapshot, isolated application/DB restore and known-good assertions | Freeze consistent snapshot/export procedure, recovery-point trust and key custody; actually perform the drill |
| M8: AI lifecycle | **Addressed in design:** triggers, watermarks, evidence deltas, bounded reads and visible health | Implement restart-safe state, admission/fairness and actual freshness; demonstrate useful AI rather than repeated prose |
| M9: AI added value | **Still open:** matched ablation is specified | Publish held-out results including misses, harmful/incorrect suggestions, analyst work and cost |
| M10: failure domain | **Partially addressed:** Shield, proxy/application and backup identities are separated | Demonstrate durable proxy startup policy and operator access/recovery while Shield or its management host is down |

### Concrete corrections required in the actuator contract

| ID | Finding and consequence | Required correction / discriminating test |
| --- | --- | --- |
| D1 | Calling site-wide maintenance R2 by name ignores the actual availability impact. A single site can be a critical dependency or the entire business. | Limit R2 eligibility to a declared owner-accepted interruption/dependency envelope; classify high-impact availability loss under the existing R3/human-run boundary. Test a service whose interruption exceeds its accepted budget: deny the brokered action. |
| D2 | Reading an expected release and taking Shield's own writer lease does not prevent an external Caddy administrator from editing between read and apply. A successful `/load` alone is not compare-and-swap. | Use target-side atomic conditional mutation on the supported API operation, including the relevant ETag/If-Match semantics; stale/conflicting state requires a new plan/approval. Test an external edit at the read/apply boundary and prove it cannot be overwritten. If the chosen endpoint cannot enforce this condition, reject that execution route. |
| D3 | A parameter named `expires_at` appears to expire the maintenance rule, while the selected policy retains maintenance until explicit review. Approval/capability expiry, re-evaluation time and configuration lifetime are different. | Separate action-grant expiry from `review_due_at` and the selected retained-overlay posture. Explicitly define disconnected/crashed-reconciler behavior: maintenance persists, authority cannot be reused, the overdue/degraded state escalates, and a qualified operator has an out-of-band recovery procedure. Never promise bounded downtime through a timer that cannot reach the edge. |
| D4 | “New ingress stopped” may be read as stopping existing HTTP requests or upgraded/streaming sessions. Route replacement does not establish their termination. | Define the claim as new supported request admission through the changed route. Include already admitted requests, WebSocket/streaming sessions and alternate listeners in negative controls; surviving work remains visible and cannot produce a total-containment verdict. |

These corrections do not require a broader product or more autonomous authority. They make the selected actuator precise enough to implement and test. After they are incorporated, the architecture is a reviewable implementation hypothesis; all replay, enforcement, recovery and pilot efficacy gates remain unpassed.

### Second-pass correction disposition

Reviewed the updated operating architecture, security guardrails, data contracts, acceptance criteria and LLM specification after the root incorporated D1-D4.

| Finding | Updated design disposition | What remains unproven |
| --- | --- | --- |
| D1: impact classification | **Addressed in design.** R2 requires an explicitly accepted low-impact site/dependency envelope; critical/business-wide interruption is R3/human-run. The example contract describes a low-impact demo site. | Enforced eligibility, actual dependency knowledge, measured interruption and rejection of high-impact actions |
| D2: configuration race | **Addressed in design.** The selected route reads the quoted root ETag and uses target-side conditional PATCH on the fixed enrolled route. The design rejects `/load` as this mutation route, invalidates `412` proposals and confines raw configuration to the local enforcer. | Source-inspected semantics must still hold for the resolved built artifact; exercise external edits between read/apply, changed slot identity, lost responses and compensation races |
| D3: lifetime ambiguity | **Addressed in design.** `expiresAt` limits grant dispatch; `reviewDueAt` requests review. Applied maintenance persists until approved removal or qualified intervention. Disconnection can extend downtime, with independent degraded monitoring and emergency procedure. | Crash/restart persistence, out-of-band monitoring/runbook, actual owner acceptance and removal without overwriting concurrent changes |
| D4: existing work and streams | **Addressed in claim scope.** Existing in-flight work, upgraded connections, streams and host/identity/egress activity cannot be declared contained by new-ingress denial. Their actual behavior is an acceptance test. | A configuration change may itself reload handlers and disrupt existing connections: measure both surviving malicious work and collateral termination on the dedicated lab proxy. Exclude unsupported protocols and never assume route-local edits have route-local runtime effects. |

The review accepts these corrections as specification clarifications only. It does not approve a production adapter or change any unpassed execution/efficacy gate. A final consistency pass confirms that the threat model distinguishes normal restricted AI from its degraded baseline, acceptance uses review/compensation semantics rather than implied TTL removal, and the actuator requires a dedicated single-application proxy with an accepted reload-impact envelope. Shared-proxy execution and unsupported long-lived protocols remain excluded. Historical ADR 0001 is explicitly refined by ADR 0002, so its original optional-AI wording is historical rather than the current decision.

### Canonical experiment parameters

The operating architecture is the canonical source for the selected pilot budgets. Different numbers in exploratory research notes are alternatives, not simultaneous requirements: one episode has a 180-second hard deadline, at most eight model calls and 64,000 aggregate input/output tokens; each call has a 20-second deadline, with at most one permitted transient retry only inside the remaining episode budget. At most two evidence-request rounds and three typed reads per round remain inside that episode. One active episode per case and two globally bound concurrency.

Final cross-file check confirms the operating architecture and LLM specification also charge model-requested read results, their case revisions and follow-up reasoning to the originating episode. Those results cannot be relabeled as external evidence to reset call/token/deadline limits. This closes the identified budget-reset ambiguity in design; implementation still needs a test that exhausted episodes cannot restart themselves through their own observations. Independent external changes remain subject to case/global concurrency and spend caps.

The proposed first-useful-proposal target is not a promise that a complete challenged, approved, applied and independently verified response finishes in that time. Approval delay remains included in the total response result. Neither the model-call ceilings nor a fast preliminary proposal establish effective containment.
