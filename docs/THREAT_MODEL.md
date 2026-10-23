# Proposed threat model

Design-stage model, not a repository security audit or validated implementation. Assumptions: single-organization local pilot, enrolled Linux service, untrusted imported telemetry, optional restricted model, operator-controlled evidence/backup/secret systems. The first pilot must confirm these assumptions before live access.

## Assets and adversaries

Protect service availability, data integrity/confidentiality, incident evidence, backup recoverability, operator access, action authority and audit integrity. An attacker may control an application/log line/tool result, compromise a telemetry source, steal an operator session, poison an upstream rule, or interrupt the control plane. A fully compromised host/control plane requires external trust and expert response; local signatures and hash chains alone cannot defeat it.

| Abuse path | Impact | Required design control / test |
|---|---|---|
| Malicious log/report/tool output instructs a model to revoke users or exfiltrate data | Shield becomes an attacker actuator | No direct model tools; typed catalogs; deterministic policy; injected-evidence fixtures |
| Compromised collector sends authentic but false/stale observations | Wrong containment or missed compromise | Source trust/freshness, cross-source contradiction and independent observation; no single-source certainty |
| Uploaded archive or evidence reference escapes parser boundaries | Code execution, local disclosure or denial of service | Strict bounded parser, no active content/dereference, path/size/decompression tests |
| Stolen/replayed approval or changed parameters after review | Unauthorized action | Action digest, actor/role, expiry, nonce, state freshness, single-use dispatch and direct-adapter tests |
| Overbroad isolation removes legitimate traffic/operator access | Self-inflicted outage | Dependency/access checks, narrow TTL action, tested compensation, independent health and kill switch |
| Executor retries after a lost response | Duplicate/destructive effect | Durable intent, idempotency, `unknown_outcome`, target reconciliation before retry |
| Model/provider receives incident secrets or retained private data | Secondary breach | Minimized derived context, data classification/egress controls, secret canaries, no raw prompt logs |
| Compromised rule/catalog/update expands execution | Supply-chain authority bypass | Manual pinned provenance/license review, immutable catalogs, no runtime update/install |
| Original evidence overwritten or audit history rewritten | Lost forensics and false closure | Operator vault, derived copies, access controls, off-host checkpoints; disclose residual host-compromise risk |
| Backup is encrypted, corrupt or contains persistence | Failed/reinfected recovery | Key and snapshot checks, isolated restore, application and contamination checks, no recovery claim from metadata |
| Case evidence or approvals cross organization/asset boundary | Data leak or wrong-target action | Case-scoped IDs, enrollment, API/worker authorization and cross-project tests |
| Event flood or recursive agent loop consumes all resources | Lost visibility/response | Intake/rate/resource limits, bounded context/jobs, cancellation and explicit gaps |

Priority is highest where an input can become action authority, evidence can be destroyed or recovery can overwrite data. Exact likelihood/risk scoring awaits the pilot environment, topology, privileges and data classification. [Guardrails](SECURITY_GUARDRAILS.md) and [acceptance](ACCEPTANCE_CRITERIA.md) define mandatory tests rather than assuming controls already exist.
