# LLM Gateway specification

Status: proposed; no provider configured, SDK installed, model selected or API key required by this repository.

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
| `incident_hypotheses` | Correlate observations; explain competing causes | Facts separate from hypotheses |
| `evidence_request` | Suggest missing observations | Catalog read request; no new authority |
| `response_plan` | Instantiate a reviewed playbook | Known action IDs and typed parameters |
| `plan_challenge` | Seek contradictions, dependency risks and missing evidence | Cannot approve or authorize |
| `recovery_explanation` | Explain readiness/drill outcomes | Cannot infer successful recovery |
| `case_report` | Draft operator-readable wording | Cannot invent evidence or erase limitations |

The deterministic path supplies rule triage, timeline, playbook lookup and uncertainty when models are unavailable. A challenger can use a separate context, but agreement between models does not constitute independent verification.

## Data, tools and budget

Prompts contain minimized sanitized facts with lineage. No raw original evidence, PII, credential, memory image, packet payload, private request/response, secret-broker reference dereference or provider-side tools. Models cannot browse, run code, access incident systems or write case authority. Retrieval is from a reviewed bounded catalog and treats all content as data.

The operator chooses permitted data classes, locality, provider retention/training terms and remote egress before enabling a route. Unknown data classification fails closed. Local inference uses the same controls. Repeated use of sanitized data still needs access control and retention policy.

Each case freezes route configuration/version and caps total calls, tokens, elapsed time, concurrency and monetary cost where applicable. No recursive model loops. Retry at most once for a transient read-only model failure within the overall case budget. Only an explicitly permitted fallback receives the same approved data class; no silent remote-provider fallback. Model outage, invalid schema, unknown references, timeout or budget stop produces a visible limitation and deterministic output.

## Audit and tests

Record use case, actual provider/model/version, configuration hash, safe input/evidence manifest hash, latency, token/cost totals, fallback and safe error. Do not log raw prompt or completion. Unversioned models reduce reproducibility and must be disclosed.

Test sanitizer/error paths, injection in evidence, unknown/cross-case references, fake action IDs, schema refusal, over-budget, timeout, forbidden fallback/egress and unavailable routes. Measure baseline versus AI, AI without challenge and full bounded pipeline. Evaluate both safety and useful work; a model that refuses everything is not successful defense.
