# First isolated lab: measured results

Recorded 2026-10-24. Scope: **experimental synthetic runtime plus isolated Caddy/Coraza/restic trials**. This is not production protection, a representative exploit benchmark or a demonstrated AI advantage. The [independent reviewer](EFFICACY_REVIEW.md) inspected the records and challenged the claims; it did not independently rerun the complete Docker suite.

## Four questions, four separate conclusions

| Question | Actual observation | Supported conclusion / limit |
|---|---|---|
| Prevent an attack? | Three CRS-shaped inputs reached a planted harmful operation with WAF Off and DetectionOnly. On returned 403 with zero app reach/harm delta. Nine benign requests across three modes returned 200. | The selected request-rule policy prevented these three planted effects. This is not demonstrated SQLi/XSS/RCE exploitation or a general recall/false-positive result. |
| Respond during an attack? | Exact approved runtime maintenance stopped new ingress, returned deliberate 503, preserved management, and separately approved reopening restored 200. The measured source-inclusive interval was **5.532 seconds**, during which **11 additional planted effects** occurred. | New-ingress stop is observed. Existing HTTP/background activity continued; host, session and egress containment are not established. Approval was a scripted fixture, with **no human-time measurement**. |
| Recover afterward? | Controlled account-row loss caused an actual transaction to return 409. A pinned snapshot restored to empty isolated scratch passed SQLite integrity, 600+400 balance invariants, the planted trust marker and a real HTTP transaction. | A usable synthetic application was recovered. Measured restore-to-app-check time was **3.162 seconds**; synthetic checkpoint-to-incident interval **5.348 seconds / one subsequent transaction**. These are single-drill values, not production RPO/RTO guarantees. |
| Is AI continuously present and useful? | Durable scheduler, changed-evidence/freshness triggers, restart dedup, bounded reads/budgets, concurrent duplicate suppression and explicit provider failure passed tests. CLIProxyAPI/Codex transport passed local HTTP contract tests. | Scheduling/adapter behavior is implemented. **At this historical capture no real endpoint was configured.** Later [actual Codex trials](NEXT_WAVE_RESULTS.md) evaluate a separate 16-case corpus; operational AI value remains unproven. A test double is not an AI efficacy result. |

## Actual control and recovery evidence

- [Prevention record](evidence/prevention.json): Off/DetectionOnly/On rows include HTTP status, app reach delta and independent harm delta. The origin has no published port; `/_lab*` returns 404 publicly. The seeded query marker was absent from actual proxy/app stdout/stderr. IPv6/alternate-host bypasses and a general source-sanitization guarantee remain untested.
- [Direct control record](evidence/response.json): stale root ETag was rejected with **412**, three post-maintenance fixture requests returned 503 with zero new harm, administration stayed available and maintenance survived an actual proxy restart. Previously admitted HTTP and background work continued. WebSockets are outside this fixture.
- [Runtime approval bridge](evidence/approved-runtime-response.json): real SQLite state → deterministic proposal → exact digest approval → Caddy conditional update → separate app probes → separately approved reopening. Persistent synthetic audit/state paths are retained locally under the record's `auditStateRef`; no raw credentials or incident material are published.
- [Recovery record](evidence/recovery.json): full snapshot `76cd7f44266d7f6e1591e4cc220e016df80a5d821e0fc8e45892ea53fb494002`; repository `check --read-data`; actual loss/409 before clean restore. **Missing key, wrong key, corrupt pack, contaminated marker and application-inconsistent data all failed.** The marker is a planted trust invariant, not a malware scanner or proof of persistence eradication.
- [Build provenance](evidence/build-provenance.json): actual binary/image hashes, dependency tuple, source hashes and the explicit request-only policy. Local module-cache paths and backup credentials are omitted.

The runtime response chain measured collection **0.773s**, ingestion/baseline investigation **0.144s**, proposal/scripted approval **0.865s**, dispatch/readback **1.793s**, and independent checks **1.958s**. The scripted wait was 0.25s; actual human wait is `null`. The full interval starts before the first stimulus and collection, and ongoing fixture requests run during collection, planning and action. These are local single-run observations, not an incident-response SLO.

## AI versus no AI

The [frozen functional comparison](evidence/decision-comparison.json) separates labels from runtime/model inputs and records source/corpus hashes, actual host time and the independently registered replay clock `2026-10-24T00:42:00Z`. Both arms use that same logical clock for freshness; provider deadlines use real clocks. Historical gaps remain visible. No baseline rule was tuned to the scored outcomes.

| Measure | Deterministic baseline | Real AI arm |
|---|---|---|
| Supported-incident traces | 12/12 flagged suspicious | Not run |
| Benign traces | 0/12 false alarms; **2 decisive benign, 10 abstentions** | Not run |
| Incomplete/conflicting traces | 12/12 retained uncertainty | Not run |
| Invalid input cases | 12/12 rejected | Not run |
| Model calls | 0 | 0 |
| Incremental AI benefit | Baseline reference only | `blocked_provider_unconfigured`; metrics `null` |

The 36 accepted decisions were policy-acceptable under the registered scoring rule, but that is **not 100% decisive classification accuracy**. Inputs already contain facts such as authorization outcomes, so this measures rule/contract consistency, not discovery from raw incident telemetry. Published labels now make this a regression corpus; future prompt/rule tuning needs a fresh held-out set. A genuine AI-value experiment additionally requires ambiguous multi-step incidents, useful observations not already in the prompt, equal baseline/operator access, repeated runs, adverse outcomes, cost and an actual operator trial.

## Integration findings and open gates

The pinned full embedded CRS 4.30.0 bundle failed real provisioning: a response rule references missing `web-shells-php.data`. The lab explicitly selects **`REQUEST-*.conf` only**, with response-body inspection off. No full-CRS compatibility is claimed. Logging suppression avoids the tested source leak but sacrifices detailed WAF telemetry; production telemetry/minimization needs separate work.

The actual Docker suite passed **7/7 tests** (four boundary tests, three deployed trials) in 78.889s. Separate runtime/policy/transport tests cover strict schemas, atomic import, exact scope/digest, expiry/replay, stale/clock/gap denial, kill switch, audit tampering, ambiguous completion, model output/transport failures, budget reset, timer freshness and SQLite concurrency. Unit doubles are explicitly labeled; they never count as deployed-control evidence.

Full production source authentication, identity isolation, concurrent ingestion/dispatch atomicity, off-host audit trust, broad crash/partition/cancellation coverage, representative attack/benign workloads, dependency/security review, scale, real model/account budgets and AI advantage remain open. Imported source-role labels are operator assertions; they do not authenticate an observer. Disclosure cannot be undone by restore. Full S2/S3 acceptance has not been granted.

## Reproduce

Follow [runtime instructions](../RUNTIME.md) and [lab setup](../../lab/README.md). Run the actual Docker assertions explicitly:

```powershell
python -m lab.control build
python -m lab.control start
$env:SHIELD_RUN_LAB_TESTS='1'
python -m unittest discover -s tests -p test_lab.py -v
python -m openshield lab approved --output output/approved-runtime-response.json
python -m openshield benchmark --output output/comparison.json
python -m lab.control stop
```

`python -m openshield lab verify` records and grades the full control/recovery/approval exercise; it returns nonzero when an observed requirement fails. Neither this command nor the default benchmark calls a real model. Enabling `benchmark --with-ai` requires the separately configured operator proxy and budget; endpoint availability alone does not prove AI value.
