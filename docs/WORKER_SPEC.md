# Worker and adapter specification

Status: requirements only. A worker is a bounded job in the initial application, not a justification for a separate service or agent.

## Common input and isolation

Every job carries `schemaVersion`, `projectId`, `caseId`, `runId`, task type, frozen enrollment/scope/policy refs, permitted evidence IDs, deadline, budget, cancellation lease, adapter/runtime ref and idempotency key. Evidence/model text cannot supply executable paths, endpoint URLs, raw commands, credentials or plugins.

Only the action broker can obtain an execution capability. A direct adapter invocation without a valid action-bound grant fails closed. Scope and state are rechecked at the adapter boundary. Read-only and response credentials/processes remain separate. Limit network, filesystem, CPU, memory, output size and subprocess lifetime; avoid a shell and use fixed typed APIs/argv.

## Job categories

| Category | Allowed output | Limit |
|---|---|---|
| Ingest/normalize | Sanitized evidence envelopes, provenance and coverage | No active collection or execution in S1 |
| Detect/investigate | Signals, competing hypotheses, evidence requests | No confirmed claim without defined evidence decision |
| Plan/challenge | Typed catalog proposals and contradictions | No approval, new policy or arbitrary tools |
| Response adapter (S3) | Reconciled operation receipt | One scoped approved capability |
| Observer | Independent target/service observations | Separate from executor claim |
| Recovery drill | Isolated-restore receipts and checks | No production overwrite or source-evidence write |

## Outcome contract

```json
{
  "schemaVersion": "worker_result_v1",
  "id": "result_demo_1",
  "createdAt": "2026-10-24T03:00:00Z",
  "producer": "openshield-investigation/design-fixture",
  "projectId": "project_demo",
  "caseId": "case_demo_1",
  "runId": "run_demo_1",
  "workerType": "investigation",
  "status": "partial",
  "evidenceIds": [],
  "coverage": {"attempted": ["auth-log-window"], "completed": [], "gaps": ["source-unavailable"]},
  "errorCode": "SOURCE_UNAVAILABLE",
  "limitations": ["Account compromise cannot be determined from this input"],
  "retryable": true,
  "provenance": {"adapterRef": "design-only", "policyVersion": "policy_demo_1"}
}
```

Canonical job status: `succeeded | partial | failed | skipped | cancelled | unknown_outcome`. Missing tool is `skipped` with `TOOL_UNAVAILABLE`, never simulated success. A response worker never sets `containment_verified` or `recovery_verified`.

## Retry and audit

Initial proposed ceiling: one attempt plus at most two retries for idempotent reads, each within the job's total deadline. Configure exact time/resource ceilings per supported adapter before release; zero/unbounded values are invalid. Mutations receive no automatic retry after uncertain completion. Reconcile actual target state and obtain new authorization when required.

Persist intent before dispatch and reconcile expired leases. Deduplicate result callbacks by run/attempt ID; retain late output as evidence without restoring authority. Sanitize ordinary/error logs. Audit policy denial, approval, dispatch, cancellation, capability access, unknown outcome, compensation, verification and closure. Audit failure blocks mutations.

## Required tests

Malformed input, oversize/traversal payload, scope drift, deadline, cancellation, tool unavailable, source/LLM failure, duplicate callback, ambiguous mutation, stale approval, bypass by direct invocation, secret leakage and independent postcheck. A test double is labeled synthetic and cannot be selected in live mode.
