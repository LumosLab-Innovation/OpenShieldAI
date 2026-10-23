# Production readiness

**Current scope: experimental S1 synthetic runtime plus isolated control/recovery experiments. No accepted production pilot or measured AI advantage.** See [individual lab assertions](lab/RESULTS.md) and [review](lab/EFFICACY_REVIEW.md). Full release gates below remain open unless exact reproducible evidence closes the entire requirement. Documentation checks validate structure, not security efficacy.

## Before any implementation claim

- [ ] Each of the four core questions maps to an actual control/observation/recovery mechanism and falsifiable T1–T6 trace.
- [ ] Resident AI triggers/state/budgets/freshness work; no-AI is visibly baseline/degraded, not silently normal coverage.
- [ ] Versioned machine schemas and real domain tests exist for the implemented slice.
- [ ] Deterministic no-LLM path works on held-out positive/negative replay.
- [ ] Tool availability, failed/partial results, missing telemetry and limitations are visible.
- [ ] Research conclusions are traceable; dependencies/rules are pinned and license-reviewed.
- [ ] No production path can select synthetic fixtures or simulate successful execution.

## Before a read-only pilot

- [ ] Actual ingress blocking mode/order, origin bypass, source-side sensitive-log exposure, clock/loss and control availability are measured.
- [ ] Named environment, owner, asset enrollment, incident commander and data policy accepted.
- [ ] Authentication, authorization, retention, transport/storage protection and key management tested.
- [ ] Actual read-only source adapter/version tested, including compromised/stale/missing sources.
- [ ] Parser limits, sanitizer/model/export/error paths and cross-project isolation pass.
- [ ] Provider locality/retention/egress terms accepted; deterministic degraded operation tested.
- [ ] Held-out evaluation and operator trial published with limitations; no extrapolated production claims.
- [ ] Support/update/incident-disclosure process and rollback of application updates documented.

## Before any brokered mutation

- [ ] Maintenance classification matches actual business impact; the accepted low-impact envelope, existing streams and unaddressed host/identity/egress paths are explicit.
- [ ] Conditional target-side config updates reject concurrent edits; grant expiry, review deadline and retained control lifetime are distinct.
- [ ] Disconnected/crashed reconciliation, extended downtime and an independent emergency management path are tested.
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
