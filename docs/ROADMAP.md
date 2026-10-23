# Roadmap: earn capability before autonomy

Stages are gated by evidence, not promised dates. Current stage is S0. No runtime milestone is complete.

| Stage | Work | Exit evidence |
|---|---|---|
| S0 — research foundation | Primary research, upstream/license registry, architecture, strict rules, skeptical review | Reviewable docs; unresolved assumptions explicit |
| S1 — offline investigation | Native contracts, bounded import, evidence timeline, deterministic baseline, optional AI, typed response proposal, recovery-readiness output | Held-out replay + utility/safety evaluation; no live writes |
| S2 — read-only pilot | Choose one actual source already used by a pilot; enroll assets; shadow investigations | Real adapter/version, source quality, operator study, data controls |
| S3 — approved response | Choose one narrow reversible enforcement path; separate observer; fault injection; isolated restore drill | Verified effect, service safety, compensation, recovery RPO/RTO and operator acceptance |
| S4 — deeper defense | Expand proven identity/web/host/data-loss/AI-agent playbooks and prevention checks | Per-capability replay and environment acceptance |
| S5 — optional Hunter loop | Sanitized report import, asset reconciliation, response evidence, manual retest exchange | Contract and authority separation tests; both sides' actual capabilities verified |

## Initial implementation work packages

1. Encode [contracts](DATA_CONTRACTS.md), enrollments and evidence lineage; establish safe replay fixtures and labels.
2. Build deterministic investigation and no-AI response playbook lookup; measure the baseline before adding models.
3. Add gateway-isolated hypotheses and challenge; reject unsupported claims and measure incremental value.
4. Build recovery-readiness checks and an isolated manual drill protocol; never confuse backup metadata with recovery proof.
5. Select one read-only adapter using [upstream evaluation](research/UPSTREAM_EVALUATION.md) and pilot inputs.
6. Select one S3 containment action only after baseline, scope, authority and service dependencies are understood.

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
