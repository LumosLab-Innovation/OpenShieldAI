# Production readiness

**Current status: S0 research/specification only. Not deployable. All runtime gates below are open.** The repository documentation check verifies structure and links; it does not validate security efficacy.

## Before any implementation claim

- [ ] Versioned machine schemas and real domain tests exist for the implemented slice.
- [ ] Deterministic no-LLM path works on held-out positive/negative replay.
- [ ] Tool availability, failed/partial results, missing telemetry and limitations are visible.
- [ ] Research conclusions are traceable; dependencies/rules are pinned and license-reviewed.
- [ ] No production path can select synthetic fixtures or simulate successful execution.

## Before a read-only pilot

- [ ] Named environment, owner, asset enrollment, incident commander and data policy accepted.
- [ ] Authentication, authorization, retention, transport/storage protection and key management tested.
- [ ] Actual read-only source adapter/version tested, including compromised/stale/missing sources.
- [ ] Parser limits, sanitizer/model/export/error paths and cross-project isolation pass.
- [ ] Provider locality/retention/egress terms accepted; deterministic degraded operation tested.
- [ ] Held-out evaluation and operator trial published with limitations; no extrapolated production claims.
- [ ] Support/update/incident-disclosure process and rollback of application updates documented.

## Before any brokered mutation

- [ ] Per-action typed capability, immutable approval hash, expiry, roles and replay resistance tested.
- [ ] Adapter enforces scope even when called directly; no free-form shell or runtime downloads.
- [ ] Expected-state freshness, dependencies, operator access and resource limits enforced.
- [ ] Crash/duplicate/lost-response/partition/late-callback cases reconcile without blind retry.
- [ ] Kill switch, capability revocation, cancellation and audited in-flight reconciliation work.
- [ ] Compensation and independent intended-effect/service-health checks pass in the actual environment.
- [ ] Audit/policy/secret-broker failure blocks execution; off-host audit checkpoints verified.
- [ ] Incident commander accepts the measured blast radius and residual uncertainty.

## Before a recovery claim

- [ ] Snapshot/source custody, encryption keys and isolated target verified.
- [ ] Restore actually performed without production overwrite; data/application checks pass.
- [ ] Missing-key, corrupt/incomplete/compromised backup and interrupted restore tested.
- [ ] Persistence/reinfection risks and disclosure exposure remain visible.
- [ ] RPO/RTO measured from real drill; operator authorizes reconnection/closure.

## Before broadening support

- [ ] Each new incident family, action, tool version, OS or environment has its own test evidence.
- [ ] Load, failure domain, tenancy and high-availability decisions use an ADR and real measurements.
- [ ] No root-license claim erases third-party restrictions or commercial obligations.
- [ ] OpenHunterAI exchange waits for standalone gates; no inherited scan/action authority.

Release blockers in [SECURITY_GUARDRAILS.md](SECURITY_GUARDRAILS.md) override the checklist. A green CI badge or complete documentation never changes these boxes automatically.
