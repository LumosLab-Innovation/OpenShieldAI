# Proposed data contracts

Status: normative design for S1; no schemas or runtime API implemented yet. Implement versioned machine schemas and compatibility tests before accepting external inputs. Examples use synthetic IDs, never credentials or real incident data.

## Common envelope

All records carry `schemaVersion`, stable `id`, `projectId`, `caseId` where relevant, `createdAt` (UTC), `producer`, and provenance. Use opaque case-scoped asset/evidence IDs, bounded arrays/strings, explicit enums, canonical serialization for hashes, and rejection of unknown fields at trust boundaries. References must resolve within the authorized project/case. Display times with explicit timezone; retain source/capture/receive timestamps and clock uncertainty separately.

| Record | Required semantics |
|---|---|
| `asset_enrollment_v1` | Asset ID, owner attestation, environment, criticality, service dependencies, registered endpoints, allowed read/action capabilities, approvers, expiry and immutable scope version |
| `evidence_envelope_v1` | Evidence ID, source/collector identity, capture/receive times, source trust, opaque original reference, integrity algorithm/digest, sanitizer version, derived facts, lineage, time range, completeness and gaps |
| `incident_case_v1` | Incident family, asset IDs, impact, evidence-backed facts, competing hypotheses, contradictions, priority basis, visibility limitations, assigned operator and phase |
| `action_proposal_v1` | Catalog action type, exact asset/parameters, rationale evidence IDs, expected current state/version, risk, dependencies/service impact, preconditions, compensation, verification steps, policy/scope versions and expiry |
| `approval_v1` | Proposal digest, actor/role, allow/deny, exact scope, expiry, policy version, nonce and single-use dispatch state; no credentials |
| `action_receipt_v1` | Proposal/approval/attempt IDs, adapter ref, start/end, idempotency key, reconciled actual effect, status, opaque evidence refs, safe error and limitations |
| `verification_v1` | Observer/procedure identity, relevant baseline, independent post-observations, service/integrity checks, result, remaining risks and coverage |
| `recovery_check_v1` | Backup product/ref/snapshot, backup time, key availability status, isolated destination ID, integrity/application/contamination checks, observed RPO/RTO or explicitly unmeasured |
| `case_report_v1` | Scope/window, evidence trust, facts/hypotheses, coverage, actions/approvals, verification, recovery state, residual exposure, next owner actions and provenance |

An evidence digest does not make the source trustworthy. A field named `sanitized` does not establish sanitizer correctness. Validate provenance, transformations and policy rather than trusting producer assertions.

## State machines

Incident phase is workflow, not proof of safety:

```text
new → investigating → response_planned → responding → recovering → observing → closed
                       ↘ needs_human / visibility_gap / suspended
closed → reopened (new evidence or failed verification)
```

Track evidence status independently (`suspected | supported | refuted | insufficient_evidence`) and operational condition independently (`unknown | affected | containment_verified | recovery_verified`). Operator closure records scope, reasons, unresolved risks and acceptance; it does not convert unsupported claims into truth.

```text
proposal: draft → policy_denied | needs_evidence | awaiting_approval
approval: granted | denied | expired | revoked | consumed
attempt:  queued → running → succeeded | failed | partial | cancelled | unknown_outcome
verification: verified | not_verified | inconclusive
```

`succeeded` describes only the adapter operation. Verification and service health determine whether its objective was achieved. After `unknown_outcome`, reconcile before retry. After stale evidence/state or scope change, create a new proposal and new approval. A proposal can have multiple attempts, each with receipts; approval consumption governs dispatch, and a reconciled retry requires fresh authorization unless a tested idempotent operation is explicitly covered by policy.

## Example action proposal (design fixture)

```json
{
  "schemaVersion": "action_proposal_v1",
  "id": "proposal_demo_1",
  "projectId": "project_demo",
  "caseId": "case_demo_1",
  "createdAt": "2026-10-24T03:00:00Z",
  "producer": "openshield-planner/design-fixture",
  "assetId": "asset_demo_web",
  "actionType": "temporary_ingress_rule",
  "parameters": {"ruleId": "curated_rule_demo", "ttlSeconds": 300},
  "evidenceIds": ["evidence_demo_1"],
  "expectedStateVersion": "state_demo_7",
  "risk": "R2",
  "policyVersion": "policy_demo_1",
  "scopeVersion": "scope_demo_1",
  "preconditions": ["operator-access-path-preserved", "baseline-health-observed"],
  "serviceImpact": "May reject legitimate requests matching the curated rule",
  "compensation": {"catalogProcedureId": "remove_exact_rule_and_check_health"},
  "verification": {"catalogProcedureId": "observe_rule_effect_and_service_health"},
  "expiresAt": "2026-10-24T03:05:00Z"
}
```

This fixture authorizes nothing and defines no executable adapter. Catalog IDs must resolve to reviewed immutable procedures before S3; parameters cannot carry arbitrary rule programs or shell content. TTL expiration requires a durable reconciliation procedure and verified removal, not just a timer or a claimed rollback.

## Retention and export

Retention, access and deletion follow the operator's classification policy. Reports contain sanitized evidence references and minimal derived context; exports re-sanitize. Original evidence deletion is never an automatic side effect of case closure. Audit retention and operator legal obligations are deployment decisions, not universal compliance claims.
