# LLM Gateway specification

Status: a [CLIProxyAPI/Codex adapter](RUNTIME.md#cliproxyapi--codex-adapter) is implemented and HTTP-contract tested. No real provider endpoint/model is configured, no provider SDK is installed, and no real inference or AI-benefit result is claimed. Operator proxy client credentials are needed only when enabling that route.

AI is resident supervision in the proposed normal product mode. New material evidence, changed posture, verification/recovery events and bounded recurring review trigger it; a request or an unchanged timer tick does not automatically call an LLM. [Operating architecture](OPERATING_ARCHITECTURE.md) defines persistent state, scheduling, health and the canonical pilot budget.

## Gateway-only access

Domain modules submit typed use cases and bounded sanitized context. All provider/API or local-model calls pass through the gateway:

```text
case authorization → data classification / sanitization → budget + egress policy
→ alias routing → provider adapter → timeout → schema/reference validation
→ evidence-bound output → safe cost/audit metadata
```

No business module calls a provider SDK directly. No model identifier is hardcoded in domain code. Proposed aliases are `triage_model` and `reasoning_model`; approved configuration defines provider, actual model/version and fallback. Model selection is a benchmark decision, not a brand promise.

## Allowed use cases

| Use case | Purpose | Output restriction |
|---|---|---|
| `event_summary` | Summarize a bounded evidence window | Known evidence IDs and stated gaps |
| `control_gap_review` | Review changed posture, dependencies and control/restore evidence | Evidence-linked gaps and reviewed-control proposals; no activation |
| `incident_hypotheses` | Correlate observations; explain competing causes | Facts separate from hypotheses |
| `evidence_request` | Suggest missing observations | Catalog read request; no new authority |
| `response_plan` | Instantiate a reviewed playbook | Known action IDs and typed parameters |
| `plan_challenge` | Seek contradictions, dependency risks and missing evidence | Cannot approve or authorize |
| `recovery_explanation` | Explain readiness/drill outcomes | Cannot infer successful recovery |
| `case_report` | Draft operator-readable wording | Cannot invent evidence or erase limitations |
| `lessons_review` | Review verified outcomes for prevention/playbook improvements | Draft changes and tests; no automatic retraining or promotion |

The deterministic path is the evaluation baseline and supplies degraded rule triage, timeline, playbook lookup and uncertainty during model failure. An outage is visibly degraded defense, not normal AI coverage. Existing approved request controls remain independent of inference. A challenger can use a separate context, but model agreement is not independent verification.

## Data, tools and budget

Prompts contain minimized sanitized facts with lineage. No raw original evidence, PII, credential, memory image, packet payload, private request/response, secret-broker reference dereference or provider-side tools. Models cannot browse, run code, access incident systems or write case authority. Retrieval is from a reviewed bounded catalog and treats all content as data.

The operator chooses permitted data classes, locality, provider retention/training terms and remote egress before enabling a route. Unknown data classification fails closed. Local inference uses the same controls. Repeated use of sanitized data still needs access control and retention policy.

Each case freezes route configuration/version and caps total calls, tokens, elapsed time, concurrency and monetary cost where applicable. No recursive model loops. Retry at most once for a transient read-only model failure within the overall case budget. Only an explicitly permitted fallback receives the same approved data class; no silent remote-provider fallback. Model outage, invalid schema, unknown references, timeout or budget stop produces a visible limitation and deterministic output.

Canonical pilot budget: 180 seconds per reasoning episode, at most eight calls and 64,000 total input/output tokens; 20 seconds per call and one transient retry inside the remaining episode budget. One run per case and two globally; also enforce an owner-set global cost ceiling. The initial useful-proposal latency target is separate from this maximum duration and does not promise a complete challenged or verified response. Research-note experimental numbers do not override this specification.

Deduplicate by case version/evidence watermark/use case/configuration. Permit at most two evidence-request rounds and three typed reads per round inside the episode. Each read requires an existing R1 grant and independent broker validation. The provider receives no tools/credentials; S1 reads are fixtures and S2 reads need an accepted adapter. New material evidence can create another bounded episode; unchanged input, timeout or model insistence cannot restart the budget.

Model-requested read results, resulting case-version updates and follow-up reasoning stay charged to the originating episode. They cannot reset its budget by being relabeled as new external evidence. Independent source changes remain subject to the same per-case/global concurrency and spend limits.

## Audit and tests

Record use case, actual provider/model/version, configuration hash, safe input/evidence manifest hash, latency, token/cost totals, fallback and safe error. Do not log raw prompt or completion. Unversioned models reduce reproducibility and must be disclosed.

Test sanitizer/error paths, injection in evidence, unknown/cross-case references, fake action IDs, schema refusal, over-budget, timeout, forbidden fallback/egress and unavailable routes. Measure baseline versus AI, AI without challenge and full bounded pipeline. Evaluate both safety and useful work; a model that refuses everything is not successful defense.
