# ADR 0003 — bounded Go analysis workers beside the existing supervisor

Date: **2026-10-24**. Status: **selected for the first offline synthetic analysis increment**. This records the owner's request for broad PM/BA security research followed by practical Go/Rust implementation. It does not accept a production collector, new response authority or a wholesale runtime migration.

## Problem

The [24-scenario PM portfolio](../research/SECURITY_PORTFOLIO.md) spans identity, web/API, host, data/recovery, cloud/supply chain, AI tools and availability. Its cases need distinct observations, controls, deterministic baselines, independent effect checks and failure envelopes. More scenarios, subagents or algorithms do not establish implemented protection.

The Python runtime already owns enrollment, SQLite case state, the restricted LLM Gateway, policy, exact approvals, audit and action reconciliation. Replacing those boundaries while adding unrelated incident families would multiply validation and migration risk. Existing generic `auth_decision` facts offer a smaller useful increment: correlate access-decision patterns and expose visibility gaps without acquiring collection or execution authority.

Language choice also has a limited effect on the complete response path. The [first measured lab](../lab/RESULTS.md) recorded **0.144 seconds** for ingestion/investigation inside **5.532 seconds** source-to-independent-verification. Eliminating that whole observed component would remove approximately **2.6%** of that single run. It would not remove collection, approval, dispatch, verification or harm during the interval. These values are not workload-independent performance estimates.

## Decision

Keep Python/SQLite as the canonical supervisor and authority plane. Add one independently bounded **offline Go analysis worker**, invoked with a fixed trusted executable and a versioned typed request/result contract. The worker returns evidence-linked candidates and coverage limitations only. It cannot call a provider, collect target telemetry, alter state, enroll a source, approve or execute a response.

The Go module under `runtime-go/` is independent and uses the standard library. Do not import the existing Caddy lab module or its dependency graph just to parse and correlate a bounded JSON batch. Existing Caddy/Coraza/restic integrations retain their separately pinned artifacts and acceptance boundaries. This keeps the new worker's dependency and review surface small.

The local toolchain reports **Go 1.26.4**. Rust's `rustc` and `cargo` were not present on the inspected PATH; that is a local toolchain observation, not a claim that Rust is universally unavailable. Defer a Rust component until there is a concrete supported binary parser, low-level sensor or other measured need, with an owner, toolchain, isolation requirements, benchmark and fuzzing plan. Neither Go nor Rust supplies source authenticity, correct business authorization or incident efficacy by itself.

## First rule semantics

The first rule version is `access_window_v1`, using the registered reference clock and a **60-second event-time window**, `asOf - 60s < observedAt <= asOf`. Group generic access decisions by the same pseudonymous subject and object within the frozen project/case/asset scope.

| Candidate | Predicate | Interpretation and limit |
|---|---|---|
| `repeated_access_denials` | At least **five** accepted unique `deny` decisions in the window | Repeated authorization denial merits investigation; it does not prove login guessing, a malicious subject or compromised credentials |
| `denied_access_then_allow` | An `allow` with at least **three strictly earlier** accepted unique denials for that subject/object in the window | A change in observed access merits investigation; equal timestamps do not establish causal order, and a legitimate permission change/retry can produce this pattern |

These are generic **authorization/access-decision patterns**, not credential-stuffing, password-spray or account-takeover detectors. The event contract lacks the authenticator, origin/session and mechanism evidence required to make those claims. Fixed thresholds are uncalibrated experiment parameters. Results remain `isFinding: false`; no candidate becomes an action or confirmed compromise.

## Trust, limits and integration

- Validate scope, exact schema/types, time, accepted event kinds, identifiers and data class before correlation; reject ambiguous JSON, conflicting duplicate IDs and cross-scope references. Exact duplicates cannot inflate counts.
- Bound bytes, events, grouping/cardinality, time window, parser depth, evidence references, result size and execution deadline. Parent and worker each enforce their own boundary. A process soft memory setting is not a hard OS memory guarantee.
- Preserve missing, unavailable, dropped, future, stale and ambiguous-order evidence as explicit limitations. Empty output is not evidence that no attack occurred. Stable deterministic ordering does not create a trusted causal sequence.
- Treat enrolled source labels as operator assertions. The worker adds replay/conflict/missing/loss accounting; it does **not** add an authenticated live collector, trusted sequence/epoch protocol, off-host audit anchor or proof that a compromised collector is truthful. The portfolio's H3/V3 source-reliability objective therefore remains only partially addressed.
- Keep Python validation and the shared contract authoritative at the caller boundary. Reject unknown/forged output fields, references and findings; preserve worker absence, timeout, invalid output or budget failure as explicit incomplete analysis. No shell, evidence-selected executable, runtime download or silent fallback is permitted.
- Keep the LLM Gateway, configured aliases, budgets and sanitized context unchanged. Adding deterministic Go analysis does not demonstrate incremental AI benefit or configure a real CLIProxyAPI/Codex endpoint.

The executable scope, reproduction commands and observed checks belong in [Go runtime documentation](../GO_RUNTIME.md). The [BA methods and hypotheses](../research/DEFENSE_METHODS_AND_HYPOTHESES.md) define algorithm assumptions and research alternatives. The [independent efficacy review](../research/GO_RUST_EFFICACY_REVIEW.md) records adversarial, language-placement and benchmark objections. Those documents do not expand action authority.

## Alternatives and consequences

**Whole-runtime rewrite:** rejected for this increment. It would require re-proving durable state, migration, enrollment, approval, failure and operational semantics before offering equivalent behavior. A profile and contract-compatible measured gain must justify a later replacement.

**Add Go and Rust services, queues or an agent mesh immediately:** rejected. A capped offline job needs no new public API, distributed service, SIEM, EDR, event bus or generic remote executor. Rust remains available for a concrete later component rather than a mandatory second implementation language.

**Keep all correlation in Python:** retain the current operational baseline; an equivalent Python implementation of these temporal rules has not been benchmarked. Go is a reasonable bounded worker implementation on the available toolchain, but speed is an empirical question. Compare equivalent semantics, accepted/rejected/lost counts, serialization/startup and durability costs, resource use, p50/p95/p99 and failure behavior. A fast inner loop is not end-to-end incident-response improvement.

The next control-point labs should be separately gated: downstream AI-tool capability enforcement, session/resource-server revocation semantics and isolated recovery prerequisites. Reuse the PM/BA scenario contracts and independent observers. No new live identity, host, cloud, egress or recovery actuator is accepted by this ADR. Broad portfolio coverage remains proposed until each capability publishes its own measured effects, benign controls and residual limits.
