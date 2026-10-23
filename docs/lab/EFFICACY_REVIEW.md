# Independent efficacy review: first runtime and lab

Status: independent runtime boundary tests pass; recorded ingress, approved runtime response and restore experiments support the narrow synthetic claims below. Incremental AI value is unmeasured. This is an experimental S1 runtime plus privileged isolated control/recovery experiments, not S2/S3 production acceptance. The reviewer does not implement production runtime or supply the detector's answers. Functional lab success and incremental AI value are separate claims.

## Registered claim boundaries

| Question | Evidence required | A result that does not establish the claim |
| --- | --- | --- |
| Prevention | An actual supported ingress control rejects the operation before an independently observed application effect; legitimate operations and bypass paths are exercised | An installed rule, WAF alert, HTTP status or fluent explanation alone |
| Response during an attack | Continued lab activity, complete source-to-verification timing including approval wait, a relevant approved actuator and an independent effect/availability observation | A command receipt, or new-ingress maintenance described as host/session/egress containment |
| Recovery | A pinned restore into a new isolated target, usable application/business invariants, provenance and contamination checks, actual measured data-loss interval and restoration time | A backup listing, byte copy, default repository check or merely starting a process |
| Continuous AI and incremental value | Durable changed-evidence scheduling, restart/dedup/degradation tests and matched real-provider evaluation against the same deterministic workflow | A continuously running process, a scripted AI answer, or a comparison with a deliberately weak baseline |

No real-provider efficacy result may be reported until the selected gateway endpoint exists and actual inference succeeds through the configured route. A missing route is `unavailable`/degraded; a synthetic provider double tests failure handling only and cannot count as an AI arm.

## Matched evaluation requirements

- Freeze the deterministic baseline and prompt/configuration before opening held-out truth. Reserve complete incident variants rather than randomly splitting lines from an incident.
- Keep source visibility, static protection, available catalog reads, tools, action authority, evidence windows and operational budgets equal. Record differences explicitly.
- Keep truth labels and oracle expectations outside the model context and runtime input. The evaluator may read them; investigators may not. Ground-truth field names, scenario names and paths must not leak answers into the prompt.
- Include positives, authorized benign lookalikes, incomplete/contradictory visibility and hostile inputs. Count abstentions, misses, failed runs and harmful proposals. Do not silently omit unavailable or timed-out AI runs.
- Report per-case decisions and a full confusion matrix, supported-evidence/action rates, benign interruption, latency, tokens/cost and limitations. A small synthetic lab does not estimate real-world attack recall.
- Observe application effects independently of detector decisions and executor receipts. A second LLM is not an outcome oracle.
- Separate investigation quality from execution: an approved maintenance action need not establish the hypothesis, and safe refusal of all useful work fails the value test.
- Human triage speed needs an actual blinded/counterbalanced operator trial; machine response latency cannot be renamed analyst time saved.

## Blocking adversarial checks

Exact action binding, forged/expired/replayed approvals, scope/case/evidence drift, direct-dispatch bypass, target state conflict, ambiguous completion, cancellation and audit failure must fail closed. Evidence cannot create an asset, policy permission, provider route or executable command. The gateway must reject unknown/cross-case references, unknown output fields and action IDs. Source/model/export/error paths cannot disclose raw secrets.

Recovery negatives include missing keys, corrupt objects, a contaminated/wrong snapshot and an application-inconsistent restored database. An unsafe target cannot become the restore destination. An intact snapshot inside an unresolved compromise interval does not establish cleanliness.

Resident AI checks include restart-safe watermarks, no repeated calls on unchanged input, bounded requests and calls, degraded provider/source/control health, and no episode-budget reset through model-requested evidence. Existing approved ingress enforcement must survive an unavailable provider or Shield process.

## Review disposition

The reviewer independently created [48 synthetic cases](../../tests/fixtures/heldout_cases.json): 12 supported-incident traces, 12 benign lookalikes, 12 incomplete/conflicting traces and 12 inputs expected to be rejected. The 36 accepted cases are eligible for decision comparison; rejection tests are reported separately. Truth means evidence-supported unauthorized effect/change, absence of such support in a benign trace, or explicit uncertainty. It does not encode complete host safety.

The deterministic baseline was written before its author received the held-out labels. Observer-role compatibility fixes were made before first scoring without changing truth. A valid comparison must fingerprint the baseline, prompt/gateway and manifest at run time. The structured input deliberately exposes already resolved facts such as an application authorization result; high scores on it establish rule/contract consistency, not discovery of an unknown attack.

`python -m unittest discover -s tests -p test_adversarial.py -v` passed **24 independent tests** on 2026-10-24. These include the 48-case input-manifest check. Fake adapters/providers in these tests are visibly named unit doubles and are never deployed-control or AI efficacy evidence.

| Review finding | Disposition and evidence |
| --- | --- |
| Lab identifier alone did not bind the proposed asset to the actuator | Fixed: proposal and adapter require the registered `lab` / `lab_web` identity. Wrong enrolled asset and changed adapter identity are rejected by independent tests. |
| An unchanged idle scheduler tick could erase provider degradation | Fixed: unavailable-provider health survives deduplication. Independent test confirms zero calls, visible degradation and no unchanged rerun. |
| Opaque label syntax admitted a recognizable credential-shaped value | Fixed for recognized credential patterns: a synthetic `sk-proj-` canary is rejected. This is not a universal detector of secrets or personal data; unsupported real data remains prohibited. |
| A fresh per-case evaluation database reset the global token ceiling | Fixed: evaluation shares a reservation wrapper. Independent test proves a failed 9-token attempt under a 10-token ceiling blocks a second attempt before dispatch; failed calls do not receive free budget. |
| A successful adapter receipt could be mistaken for verification | Independent tests require `pending_independent_observer`; 412 and lost replies never become verified success, and consumed approval cannot replay. |
| Oracle endpoints and fixture mutation were mixed with public/read-only paths | Lab author added a public `/_lab*` denial and separate stimulus script. Actual route isolation remains a deployed-lab test, not a unit-test conclusion. |

The action tests also cover approval/operator mismatch, grant expiry, evidence-version drift, stale/source-gap/clock-skew mutation denial, unaccepted interruption impact, disabled execution, kill switch, audit tampering, case/source/project swaps, atomic input rollback, expired enrollment, missing capability, conflicting duplicates, telemetry-role verification assertions and invalid model evidence/actions. The local OS user remains the authority boundary; these tests do not demonstrate a network authentication layer or a production multi-operator broker. Source IDs and roles in offline files are operator-asserted synthetic provenance, not authenticated source identities: a declared `observer` field alone cannot prove an observation independent. The actual lab uses a trusted controller invoking a separate observation path; an untrusted-source pilot still needs authenticated collection and source compromise tests.

## Review of actual recorded experiments

The reviewer inspected the executed lab's safe `prevention.json`, `response.json` and `recovery.json` records in `artifacts/lab-results`. These are observations from the actual pinned Docker/Caddy/Coraza/restic stack, not unit-double output. A second reviewer reading the records is not a second independent reproduction; the app counter/oracle and separate observation path provide the effect evidence inside the trusted synthetic fixture.

| Claim | Recorded result | Disposition |
| --- | --- | --- |
| Supported request-phase prevention | Three CRS-shaped inputs produced HTTP 403 and zero app/harm increments with WAF On; the same inputs reached the planted operation with Off and DetectionOnly. All nine benign requests across the three modes succeeded. | Narrow functional pass. No real SQLi/XSS/RCE exploit, broad recall or false-positive rate established. |
| Route isolation and source minimization | No app port was published, public `/_lab/state` returned 404, and the seeded query marker was absent from app/proxy logs. | Pass for these checks. No external IPv6/alternate-host bypass or universal secret-sanitization proof. |
| Ingress maintenance | A plain-input planted abuse request reached the app before maintenance; three new requests after maintenance returned 503 with zero extra harm. Old ETag returned 412; management remained reachable. | Narrow controller effect pass; static WAF alone demonstrably does not stop the plain-input business-abuse fixture. |
| Actual runtime to approved actuator | The sustained fixture ran before collection/planning. Baseline investigation produced an evidence-linked proposal, the scripted operator granted its exact digest, ActionService consumed it, real Caddy maintenance took effect, and independent app/management probes observed the intended result. Reopening used a separate exact approval and restored HTTP 200. | Narrow broker bridge pass for new ingress only. The executor receipt correctly remains pending verification; the controller's separate probe supplies the result. No real human or AI response trial. |
| Residual work and retention | Already admitted HTTP/background work completed. Maintenance survived a proxy restart and was separately reopened. | Negative controls preserve the distinction from host/session/egress containment. No WebSocket or full crash-window reconciliation proof. |
| Restore after controlled data loss | Deleted source accounts and a failing HTTP transaction were observed. A pinned snapshot restored into new scratch passed SQLite/business/trust assertions and a real HTTP transaction with balances 600/400. | Narrow isolated application restoration pass, using trusted fixture code and a known planted trust marker. |
| Recovery failures | Missing key, wrong key, corrupt pack, contaminated marker and application-inconsistent database did not produce verified recovery. | Pass for these five known negatives. No unknown-malware/persistence or compromised-backup-administrator guarantee. |
| AI value | The selected CLIProxyAPI endpoint is unavailable; no real-provider inference/comparison was run. | **Unmeasured.** No fake score, refusal score, latency advantage or analyst time saved is credited to AI. |

The actual approved response took 5.532 seconds from the declared source stimulus through independent verification: 0.773 collection, 0.144 ingestion/planning, 0.865 planning-to-scripted-approval, 1.793 approval-to-receipt and 1.958 independent checking. Eleven additional planted effects occurred during that response window. The 0.250-second scripted wait is included; actual human wait is `null`. This demonstrates a nonzero harm window even with a cheap deterministic decision and cannot establish human-inclusive production response latency.

One recorded restore took 3.162 seconds from restore start through isolated app verification; the synthetic checkpoint-to-incident interval was 5.348 seconds with one intervening committed transaction. These are a tiny fixture's observed intervals, not production RTO/RPO promises or reconnection measurements.

The supported Coraza configuration loads request-rule files only. The pinned full CRS response bundle failed compatibility because an embedded data file was unavailable; this is an explicit inspected-surface limitation rather than a completed full-CRS integration.

Target topology validation, proxy-restart retention, data-loss/invalid-application recovery controls and timer-driven freshness were added after review findings. The runtime author's clock-transition/restart test demonstrates one bounded reconsideration when freshness gaps change and deduplication on subsequent unchanged ticks. Its two-connection regression demonstrates duplicate episode admission protection. These are scheduler correctness tests, not evidence of always-available model reasoning or effective detection under load.

Remaining open work includes actual human approval delays, representative workload/overload/fairness, all broker crash/cancellation/fault windows, authenticated source identities, backup/identity trust reconstruction and real-provider usefulness. Keep these explicit until observed results close their exact claim. No specification checkbox is treated as a runtime pass.

The recorded structured replay result is also not AI efficacy: the baseline recognized all 12 supported traces, produced no suspicious decision on 12 benign traces, abstained on 10 of those benign traces, preserved uncertainty on 12 incomplete cases and rejected all 12 hostile inputs. Conservative abstention on a benign trace is acceptable in this contract but is not a decisive correct classification or evidence of analyst work saved. No baseline or prompt was tuned to improve these first scores.

The reviewer registered the fixed replay clock `2026-10-24T00:42:00Z`, one minute after the latest input observation. Both arms use the same clock, and the evaluator reports actual host time and case freshness gaps. Older facts remain historical: this dataset is not fresh mutation authority. The clock controls replay freshness/enrollment/ingestion metadata; model transport and hard deadlines retain real time. No event or truth label changed for this correction.

The first baseline result must not be presented as a completed AI comparison. Even a configured endpoint would not by itself prove AI utility: this structured corpus and same-timeline catalog reads do not measure discovery from ambiguous telemetry or the value of gathering previously unseen evidence. Long-lived case history and source freshness need representative tests beyond this intentionally small contract corpus.

Once this labeled corpus is published, treat it as a frozen regression benchmark. A later efficacy claim after prompt/rule changes needs a new independently reserved held-out set; do not reuse the published answers while calling them unseen.
