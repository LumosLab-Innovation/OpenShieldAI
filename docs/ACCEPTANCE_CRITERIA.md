# Acceptance criteria

All gates below are unpassed. Documentation completeness is the only deliverable in S0. Do not check an execution gate without reproducible evidence.

## S0 — reviewable foundation

- README distinguishes mission, research, proposed design and nonexistent runtime; license and security reporting are accurate.
- Research sources have direct primary links, dates, limitations and adoption decisions. Upstream registry carries exact reviewed refs and license evidence; nothing is silently vendored or enabled.
- Independent skeptical review records accepted/rejected/deferred features and unresolved risks. No paper result becomes an OpenShieldAI metric.
- Architecture defines enrollment, evidence trust, model boundary, action/approval/verification separation, kill switch and recovery limits.
- Local links, registry structure and basic repository hygiene checks pass. No application is claimed to run.

## S1 — offline replay and useful investigation

- Accept only bounded synthetic/sanitized fixtures; reject malformed schemas, unsafe archives/paths, duplicate/replayed records, unknown/cross-case references and unsupported data classes.
- Deterministic baseline produces rule decisions, timeline, scope, missing evidence and response proposals without an LLM.
- Optional AI adds only evidence-linked hypotheses/proposals. Hallucinated evidence, action IDs or asset IDs are rejected; injected log/report instructions cannot change policy or cause tool use.
- All outputs expose source trust, collection window, gaps, contradictory evidence, uncertainty, cost and whether AI ran. Model timeout/refusal/budget stop preserves partial case state.
- Compare against baseline and human/operator workflow using held-out positive, benign lookalike, missing-telemetry and injection cases. Record effect size, uncertainty and adverse outcomes as described in [EVALUATION.md](EVALUATION.md).
- No live credentials, target network access, mutable adapter or fake execution success exists in this slice.

## S2 — read-only pilot

- Named owner confirms enrolled assets, endpoint allowlist, telemetry source, data policy and incident commander. Authentication, authorization and cross-project denial tests pass.
- One actual source adapter is pinned and tested against its supported version; identity, freshness, clock skew, truncation, collector outage and tampering are visible.
- Least-privilege read grants, bounded queries, endpoint/DNS/redirect restrictions, encryption, sanitizer and log/error-path leakage tests pass.
- Shadow decisions are reviewed by an operator; no change occurs on a protected service. Report observed performance and visibility limits, including source compromise.
- Pilot data stays within approved locality/retention/provider rules. Data from this pilot does not enter public fixtures or external training without explicit authorization.

## S3 — one approved response and isolated recovery drill

- Implement one catalog action against one explicitly supported environment; API/CLI share the same policy, proposal, approval, execution and verification services.
- Deny expired/replayed/forged approval, modified parameters, stale state, scope drift, insufficient role, unknown action and bypass through direct worker invocation.
- Prove preservation of operator access, service dependency check, narrow blast radius, cancellation, compensation and independent postcheck in an isolated lab first.
- Test crashes before/after dispatch, duplicate callbacks, lost responses, network partitions, ambiguous completion and durable TTL-rule cleanup/reconciliation. Never blind-retry a mutation.
- A separate observer checks intended effect and legitimate service traffic. Executor exit code or model verdict cannot close the incident.
- Policy/audit/secret-broker failures block dispatch. Kill switch revokes pending capabilities and records all in-flight attempts for reconciliation.
- Restore only a pinned snapshot to an isolated destination using a separate identity. Validate data integrity, application invariants, contamination, key availability and measured RPO/RTO. No production overwrite.
- No-backup, corrupt backup, missing key, compromised snapshot and application-inconsistent restore fixtures must end in explicit failure/inconclusive status.
- The pilot owner accepts the measured false-positive/service-impact envelope and residual risks before limited live use. No autonomous high-impact actions.

## S4/S5 — expansion and optional Hunter collaboration

Each new incident family, OS, integration or action repeats the same evidence, safety and held-out efficacy gates; it is not covered by a prior successful adapter. AI-agent cases include poisoned tool results and attempted privilege/approval escalation.

A prevention claim additionally requires control-specific attack and legitimate-traffic replay, an independently observed blocked effect, bypass/negative controls and service-health/SLO checks in the supported environment. A rule being installed or mapped to D3FEND is not evidence of prevention.

The [OpenHunterAI exchange](OPENHUNTER_COLLABORATION.md) must validate contract/provenance, reject embedded instructions, preserve uncertain/legacy status, reconcile asset identity with enrollment, and never inherit authorization. Manual finding-scoped retest returns an independently evidenced outcome or `inconclusive`/`unsupported`; no automatic rescan loop or credential exchange.

## Always-blocking failures

Unauthorized action, cross-case evidence disclosure, raw secret/PII leakage, original evidence mutation, arbitrary code execution, forged approval acceptance, unbounded workers, destructive restore, production demo data or a falsely verified outcome blocks release regardless of average benchmark scores.
