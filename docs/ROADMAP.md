# Roadmap: earn capability before autonomy

Stages are gated by evidence, not promised dates. An experimental S1 synthetic runtime and isolated control/recovery experiments now exist; see [runtime scope](RUNTIME.md) and [measured results](lab/RESULTS.md). Real AI value and full S2/S3 release gates remain open.

The engineering spine is now the [four core questions](CORE_QUESTIONS.md) and [operating architecture](OPERATING_ARCHITECTURE.md): actual control points, a continuously present AI supervisor, a narrowly scoped ingress response and isolated application recovery. This is a design selection, not support or efficacy evidence.

| Stage | Work | Exit evidence |
|---|---|---|
| S0 — research foundation | Primary research, upstream/license registry, architecture, strict rules, skeptical review | Reviewable docs; unresolved assumptions explicit |
| S1 — offline investigation | Native contracts, temporal evidence state, resident AI investigation, deterministic ablation, typed response and recovery-readiness output | Held-out replay + utility/safety evaluation; no live writes |
| S2 — read-only pilot | Choose one actual source already used by a pilot; enroll assets; shadow investigations | Real adapter/version, source quality, operator study, data controls |
| S3 — approved response | Choose one narrow reversible enforcement path; separate observer; fault injection; isolated restore drill | Verified effect, service safety, compensation, recovery RPO/RTO and operator acceptance |
| S4 — deeper defense | Expand proven identity/web/host/data-loss/AI-agent playbooks and prevention checks | Per-capability replay and environment acceptance |
| S5 — optional Hunter loop | Sanitized report import, asset reconciliation, response evidence, manual retest exchange | Contract and authority separation tests; both sides' actual capabilities verified |

## Initial implementation work packages

1. Encode [contracts](DATA_CONTRACTS.md), enrollments and evidence lineage; establish safe replay fixtures and labels.
2. Build the deterministic baseline and typed temporal state; use it for ablation and visibly degraded operation.
3. Build resident gateway-isolated AI triggers, bounded observation requests and challenge; reject unsupported claims and measure incremental value on changed event sequences, not only report summaries.
4. Build recovery-readiness checks and an isolated manual drill protocol; never confuse backup metadata with recovery proof.
5. Select one read-only adapter using [upstream evaluation](research/UPSTREAM_EVALUATION.md) and pilot inputs.
6. Prove the selected S3 low-impact ingress-maintenance action after baseline/scope/authority/dependency acceptance; do not infer host/identity/egress containment from that result.

Every work package includes negative cases, failure/coverage states, provenance, operator outputs and relevant tests. No agent is assigned a broad toolset before a specific action earns it.

Prevention begins as observed-gap recommendations. Promoting a recommendation to an effective prevention capability requires control-specific attack/benign replay, independently observed blocking and legitimate-service SLO checks; installed-rule counts and taxonomy mappings do not satisfy that gate.

## Long-term research tracks

- AI-agent defense: tool capability abuse, poisoned context/retrieval, identity misuse and data egress; compare runtime authorization with text filters.
- Incident reasoning under adversarial or incomplete telemetry: cross-source contradiction, trust/freshness and explicit evidence requests.
- Safe rapid containment: preapproved narrow procedures, state freshness, availability constraints and durable reconciliation. Autonomous execution remains an experiment requiring new policy and evidence.
- Recovery confidence: backup integrity, clean rebuild, dependency-aware restore and application invariants; no magical data reconstruction.
- Defense feedback: verified incidents improve reviewed playbooks and prevention recommendations through human-controlled enrichment.

## Deliberately deferred

Global autonomous SOC, universal EDR/SIEM replacement, automatic malware analysis/detonation, hack-back, generic root agents, production data restore, bulk credential rotation, threat-feed firehose, premature microservices/Kubernetes, multi-tenant SaaS, billing, and automatic Hunter scan loops. Revisit only with concrete user need, authority, baseline and acceptance evidence.
