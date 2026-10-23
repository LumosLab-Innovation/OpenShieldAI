# Evaluation and evidence of value

Status: experimental plan. No OpenShieldAI efficacy scores or successful incident responses exist yet. External papers are evidence about their own setups, not results for this product.

Evaluate the [four core questions](CORE_QUESTIONS.md) separately using T1–T6 in [operating architecture](OPERATING_ARCHITECTURE.md). Report design plausibility, replay correctness, deployed control effect and real pilot outcome as different evidence levels. The existence of a document is not the first row of a successful protection benchmark.

## Questions that decide whether to build

1. Does the product help an operator reach the correct evidence-supported decision faster than their current tools?
2. Does AI add value beyond deterministic correlation, a playbook lookup and a readable timeline?
3. Can the proposed response reduce harm without unacceptable legitimate-service disruption?
4. Can independent observations distinguish success, partial effect, failure and unknown outcome?
5. Does recovery work with real restored application data, not just a backup listing?

If a feature has no input authority, baseline, ground truth, safe action envelope or measurable operational outcome, reject or defer it. See [skeptical review](research/SKEPTICAL_REVIEW.md).

## First experiment

Proposed lab: one Linux web application with known service dependency, benign deployments, suspicious access/file-change observations and synthetic backup-loss cases. No malware execution. Generate ground truth independently of the detector, maintain event lineage and reserve incident-level held-out variants before prompt tuning. Paper/demo datasets may be used only when their licenses and privacy terms allow it.

Start with at least 40 labeled replay cases across four groups: real compromise patterns, benign lookalikes/authorized changes, incomplete/contradictory telemetry, and adversarial input/approval attempts. Include multiple variants rather than split lines from the same incident across train/test. This is a pilot dataset for functional investigation, not statistical proof of broad recall. Publish exact counts, label agreement and confidence intervals; expand before efficacy claims.

Core cases: authorized deployment vs web-file tampering; successful account takeover vs failed login burst; unusual legitimate access vs suspected exfiltration; backup listed vs corrupt/missing-key/unrestorable backup; poisoned log/tool result; forged/cross-case evidence; stale approval; lost response after action; service outage caused by overbroad containment.

## Baselines and ablations

| Variant | Purpose |
|---|---|
| Existing deployed rules/tool output | Real-world baseline; preserve its actual configuration |
| Deterministic normalization + rules + timeline + playbook | Measures the value of good engineering without AI |
| Same workflow + bounded AI | Measures incremental reasoning/triage value |
| AI + evidence challenge + policy + independent postcheck | Measures complete design and each safety layer's cost |
| Operator using current workflow vs assisted workflow | Measures analyst effort and decision quality |

Use the same input visibility, hardware/time budget and labels for comparable variants. Blind and counterbalance analyst trials to reduce learning effects. Report model/version/route, prompts via safe template refs, source refs, seeds, machine specs, timeouts, exclusions, failed runs and cost. Never tune prompts on the held-out set and report that set as unseen.

## Metrics

| Dimension | Measure and anti-gaming rule |
|---|---|
| Incident decision | Precision, recall and confusion matrix by family; include `unknown` and missed cases, not just surfaced alerts |
| Evidence | Supported-claim rate, invalid-reference rate, contradiction handling, correct uncertainty on missing telemetry |
| Analyst work | Median/p95 time to correct triage and active analyst minutes; include reading/reviewing AI output |
| Response | Time from sufficient evidence to verified containment; exclude neither approvals nor failed actions |
| Collateral impact | Legitimate request success, operator access, service downtime, wrong-asset/wrong-account actions |
| Policy safety | Unauthorized dispatches, forged/replayed approval acceptance, secret leakage, scope escapes |
| Recovery | Actually restored integrity/application invariants; data-loss interval (RPO), time to usable service (RTO), reinfection checks |
| Resilience | Outage, truncation, skew, duplicated/out-of-order records, crash recovery, cancellation and unknown-outcome behavior |
| Cost | End-to-end wall time, CPU/memory, calls/tokens, provider fees and operator review cost |
| Actual prevention | Denied operation plus independently observed absence of the forbidden app effect, origin/alternate-path bypass tests, legitimate operations and inspected-field coverage |
| Continuous AI | Event-to-examined-evidence latency, material events left unexamined, useful next reads/actions, duplicate unchanged-state calls, freshness after restart, AI outage/backlog and cost |
| Damage while responding | Source, queue, AI, human approval, execution and verification times; additional unauthorized operations/exposure during the full interval; downtime and continuing streams/host/egress paths |

AI-generated severity, summary fluency, tool count and ATT&CK mappings are not efficacy metrics. A complete refusal may pass safety but fails utility; a fast answer with false certainty fails both.

For T4, keep static protection, source visibility, tools and authority equal across no-AI, one-shot summary and resident evidence-driven AI variants. Compare multi-step, low-rate, benign-deployment, contradictory-source and post-action scenarios; otherwise a faster summary can be mistaken for better defense. Evaluate both operational benefit and harmful recommendations. Source/label generation and outcome verification must remain independent of the rule/model under test.

## Gates and interpretation

Security invariants are zero-tolerance in the exercised suite: any unauthorized dispatch, evidence destruction, raw-secret leak, forged approval acceptance or falsely verified success blocks release. Zero observed failures is not proof that failures are impossible.

Before the first pilot, register an improvement target and maximum acceptable regression against the measured baseline with the pilot owner. A provisional hypothesis is at least 20% lower median active triage time with no increase in false-negative rate and no observed safety-invariant failure; this is a proposed decision threshold, not a result or universally adequate sample size. Report uncertainty; if the sample cannot resolve the trade-off, remain in shadow mode and gather more data.

Response and recovery gates additionally need the S3 fault-injection suite, successful compensation, independent postchecks and explicit owner acceptance of service-impact limits. No averaged score can offset a security blocker. Increase autonomy only for a capability with enough representative evidence; a passed web rule does not authorize identity revocation or production restore.

## Reproducible output

Version a safe benchmark manifest with scenario IDs, truth provenance, input refs, splits, baseline configuration, model/adapter/policy refs, run IDs, costs, full confusion matrices, safety failures and review decisions. Do not publish real incident evidence or sensitive prompts. Store sensitive raw experiment material only in the operator's evidence system under its retention rules.
