# ADR 0001 — independent, evidence-first defense

Date: 2026-10-24. Status: selected specification direction; implementation unstarted.

Refined by [ADR 0002](0002-continuous-ai-and-enforcement-planes.md): continuous AI is the normal supervisory mode; no-AI remains the baseline/degraded path. Explicit enforcement/control points and scenario traces complement this original foundation.

## Context

The project vision spans prevention, active incident response and recovery under faster AI-enabled attacks. A report-to-chat wrapper cannot establish that vision. Existing open tools already collect telemetry, enforce controls and store backups; rebuilding them increases risk and delays useful experiments. Published agent results are task/environment dependent and cannot authorize unsupervised response.

## Decision

Build an independent evidence-to-decision-to-verification layer. Start with a Python modular monolith and CLI offline replay, a deterministic baseline, optional bounded AI, a sanitized metadata index and operator-owned original evidence. Add one actual read-only source and one narrow approved response only after per-capability evaluation. Separate model reasoning, deterministic policy, human approval, scoped executor and independent observer. Use existing security/backup tools through separately installed versioned adapters. Defer Hunter integration until standalone value is demonstrated.

## Alternatives

| Option | Reason not selected initially |
|---|---|
| Autonomous multi-agent SOC with broad shell | High authority, unclear baseline, weak verification and excessive blast radius |
| Fork SIEM/EDR/SOAR/backup suite | Duplicates mature capability and creates maintenance/license burden |
| Hunter report wrapper first | Depends on pentest findings rather than operational telemetry; does not prove incident defense |
| Distributed services/event bus from day one | Unmeasured scale and larger failure surface |
| Prompt/filter-only injection defense | Cannot enforce runtime authority |
| No AI at all | Keep as baseline/fallback; evaluate whether bounded AI adds measurable value |

## Consequences

Early releases are useful only within a narrow evidence/telemetry envelope and require real operator involvement. Independent verification and data separation add work but prevent unsafe success claims. An offline pilot is not production readiness or enterprise scalability. Switching storage/deployment, adding autonomous actions or changing the license requires a new explicit decision and evidence.
