# Product requirements

Status: proposed specification, not implemented. Research cut-off: 2026-10-24.

## Problem and mission

An operator who receives an alert needs to know what happened, which services and data may be affected, which facts are missing, which response is safe, and whether containment and recovery worked. Existing telemetry and response tools can supply much of the machinery. OpenShieldAI's proposed contribution is an evidence-grounded decision and verification layer across that workflow.

AI-enabled attacks motivate faster and more adaptive defense, but the product must also work on conventional attacks. Do not require attribution to an AI attacker before protecting a system. Do not claim to prevent every attack or recover irrecoverable data.

## Primary users and first environment

First users are application/platform operators with authority over their service and an incident responder who can approve operational changes. Proposed first lab: one Linux-hosted web application, exported access/auth/file-integrity observations, declared service dependencies and a test backup repository. Large-enterprise breadth is a roadmap objective; a single-service lab does not demonstrate it.

## Capability stages

| Stage | Deliverable | Authority |
|---|---|---|
| S0 — current | Research, rules, architecture, measurable test design | No runtime |
| S1 — first implementation | Offline replay; bounded event ingestion; incident timeline, hypotheses, missing evidence, response proposal, recovery readiness | Local file inputs; no live actions |
| S2 | One supported read-only telemetry adapter in a pilot; shadow decisions | Read-only, enrolled assets |
| S3 | One reversible containment adapter and isolated restore validation | Explicit per-action approval; lab first, then narrowly accepted pilot |
| S4 | Additional independently proven playbooks and environments | Capability-specific release gates |
| S5 | Optional OpenHunterAI evidence and manual retest exchange | Neither product inherits the other's authority |

S4 may expand to AI-agent/tool-chain compromise, identity abuse, exfiltration, network/host compromise and resilience at larger scale. The order is driven by evidence and pilot need, not number of agents.

## First valuable workflow

1. Operator defines enrolled asset, ownership, telemetry origin, service dependencies, data sensitivity and allowed access. Uploading an alert never enrolls an asset.
2. Import bounded sanitized events and backup metadata; validate schema, source identity, integrity, time range and coverage. Preserve source references.
3. Deterministic rules provide the baseline; optional AI correlates facts, proposes competing hypotheses and asks for specific missing evidence.
4. Present incident state, timeline, evidence for/against each claim, business dependencies and next safe steps. A user can complete the workflow with AI unavailable.
5. Produce a typed containment/recovery proposal: asset, reason, preconditions, exact intended operation, service impact, approver, verification and compensation.
6. In S1/S2, the operator executes through their existing approved process and imports receipts/postchecks. In S3, a narrow broker can execute an approved action through an allowlisted adapter.
7. Verify observable effects and service health independently. Record unresolved persistence, possible exfiltration, stale telemetry and recovery gaps.

## Incident and prevention coverage

| Family | Needed inputs | Useful outputs | First release boundary |
|---|---|---|---|
| Suspicious access / account takeover | Authentication/access audit and identity context | Timeline, session scope, revocation proposal, evidence requests | S1 replay; identity execution deferred |
| Web/host compromise | Access and file-integrity observations, deployment history | Distinguish authorized deployment from suspicious change; isolation/rebuild plan | First lab family; no free-form shell |
| Ransomware / data deletion | File/backup events, retention, key availability | Containment proposal, evidence preservation, restore readiness and drill plan | No malware execution; metadata is not a successful restore |
| Exfiltration | Egress/data access events and data classification | Exposure hypothesis and bounded investigation | Cannot prove absence of exfiltration from missing logs |
| AI agent compromise | Tool/identity/policy audit and tool result provenance | Unauthorized-tool and data-leakage evidence, revoke capability proposal | Replay safety cases first; live adapter later |
| Prevention / preparedness | Asset/dependency inventory, control posture and restore drills | Prioritized control gaps with owner, rationale and verification | Recommendations backed by observations |

## Required output

Every case states facts versus hypotheses, source trust, affected scope, severity basis, confidence basis, missing evidence, coverage window, action state, verification evidence, residual risk and next owner action. `unknown` is a legitimate result. An approved action is not a successful action; a successful command is not verified containment; a restored file is not a recovered application.

## Success and non-goals

Success is measured against deterministic/existing-tool/manual baselines: time to correct triage, evidence-supported accuracy, time to verified containment, analyst work, service disruption, integrity and actual recovery RPO/RTO. See [evaluation](EVALUATION.md). No measurements exist yet.

Do not build a replacement SIEM, EDR, packet collector, backup engine, global threat feed, unsupervised SOC, agent marketplace or enterprise control plane in the first release. No offensive testing or production writes from uploaded reports. No integration is considered supported until its acceptance tests pass.

Standards and papers inform the design; source-specific findings and limitations are recorded in [research](UPSTREAM_SOURCES.md).
