# Mandatory security guardrails

Status: normative requirements for future implementation; none are validated runtime controls yet.

## 1. Defensive authorization

Require an authenticated operator, explicit enrollment/ownership attestation, immutable asset IDs, environment, allowed operations, time window, named approvers and dependency/criticality context. Assets supplied in alerts/reports do not expand scope. Recheck authorization at ingestion access, evidence retrieval and every action. Enrolled private systems are legitimate defensive targets; network discovery and lateral movement are not authorized by enrollment.

No hack-back, exploit delivery, malware deployment, persistence, credential theft or retaliation. No free-form root shell and no external code execution from model output. No production mutation during S1/S2.

## 2. Untrusted input and model isolation

Logs, artifacts, retrieved text, rules, reports and tool results may contain adversarial instructions. Parse as data with content-type/schema, size, archive depth, decompression, field count and runtime limits. Disable active content, macro execution, path traversal, unsafe deserialization and automatic URL dereferencing. Uploaded evidence cannot select plugins or model tools.

Never rely on an injection classifier or prompt alone as an authorization boundary. Models cannot obtain executor secrets, write policy, sign approval, enroll assets or create arbitrary operations. Restrict provider egress; no model-side browsing or remote tools in the first slice. Unknown output fields/IDs are rejected.

## 3. Data separation

Original forensic evidence belongs in the operator's secured evidence repository. Shield's ordinary store contains sanitized facts and opaque references only. Record collector identity, source, capture/receive times, integrity, transformations, trust level and retention. Preserve originals and record chain of custody; redaction happens on derived copies.

Secrets, personal/sensitive data, raw traffic, memory/disk images and live credential files must not enter prompts, normal logs, fixtures or public reports. Sanitize at intake and again at model/export boundaries, and test encoded/structured/error-path leakage. A sanitizer is not a universal PII guarantee; reject unsupported data classes. No remote provider for restricted data without an explicit approved policy. Local models follow the same minimization rules.

Separate secret broker from evidence and case storage. Encrypt sensitive storage/backups and transport; key lifecycle is owned by the operator. Use scoped, short-lived adapter credentials with auditable access; never put credential values in action records.

## 4. Action policy

| Risk | Example | Authority |
|---|---|---|
| R0 | Reason over already sanitized local evidence | Authorized case access; bounded resource policy |
| R1 | Read telemetry from an enrolled service | Explicit read grant; bounded allowlisted queries |
| R2 | Narrow reversible isolation/rule change | Per-action human approval, state check, compensation and postcheck |
| R3 | Bulk isolation, revoke/rotate credentials, data deletion, production restore | Qualified human-run procedure; two-person review; no autonomous executor in initial releases |

Read operations that can expose sensitive data or overload services are not automatically R1; classify by actual impact. No model can lower risk classification. No bulk expansion from one asset to a group. Irreversible actions require explicit impact/lockout planning; approval does not make them reversible.

Approval binds project/case/asset, action type, normalized parameters, evidence references/version, expected state/version, policy version, impact, compensation, postchecks, operator and expiry into an immutable digest. A changed field or stale state invalidates approval. Enforce replay resistance, least privilege, separation of duties and single-use dispatch. Approval UI must display the exact effect and dependencies; never hide unknowns under an AI confidence score.

## 5. Operational containment and evidence trade-offs

Time-critical containment can conflict with volatile evidence preservation. The incident commander records the reason, expected loss and service impact using a preapproved emergency procedure. No AI automatically chooses an exception. Preserve available evidence where feasible; do not insist on complete forensics while harm spreads. Notify through the operator's existing incident process; no unsolicited external communications.

## 6. Execution and recovery

Every worker/action has hard deadlines, cancellation, bounded retry, audit, idempotency, endpoint allowlists, request-time scope validation and resource ceilings. Mutations with ambiguous completion become `unknown_outcome` and require reconciliation. No shell interpolation, model-supplied URLs, unpinned runtime downloads, silent tool installation or blind retry.

Recovery requires known backup/snapshot, available keys, custody/integrity and a clean isolated target. Production restore is human-run in initial releases. Check reinfection risk, persistence, application consistency and service availability before declaring recovery. No backup/no key means no guaranteed recovery; ransomware decryption and attribution are not promised. Exfiltration remains an exposure even after restore.

## 7. Verification and audit

Execution receipt, verification evidence and incident closure are separate. A second model is not independent proof. Read back actual target state using a separate observer identity where feasible; check intended effect and collateral service damage. Independent here means separate evidence/observation, not merely a separate prompt.

Record immutable versioned decisions and attempts, source/policy/model/adapter provenance, approvals, denials, cost, coverage gaps and operator closure. Protect access and export checkpoints off-host. Hash chains alone cannot prove completeness against a fully compromised Shield host. If audit integrity or policy availability is lost, block new mutations and escalate.

## 8. Release blockers

Block release for scope/approval bypass, raw secret leakage, unsafe parser behavior, arbitrary execution, evidence overwrite, unbounded workers, replayed approvals, fake success, production mock results, destructive restore, inability to cancel/reconcile, or unmeasured high-impact behavior. Do not label a case `safe`, `contained`, `recovered` or `fixed` based only on silence, command exit code, a summary, a hash, or a model's judgment.
