# Anti-REA experiment results

Observed 2026-10-24. Scope: owned synthetic public web releases, real loopback HTTP, installed Chrome and OpenHunterAI's bounded REA adapter. This is an experimental implementation, not a production defense acceptance or an AI efficacy claim. [Machine-readable evidence](evidence/anti-rea.json) contains safe counts, enums, fingerprints and sanitized REA summaries only.

## What changed and what was measured

| Boundary | Before | After | Observation |
|---|---|---|---|
| Release contents | Client formula, named synthetic marker and source map with `sourcesContent` | Thin client; formula remains outside the exact static export allowlist | Release policy blocks before, passes after; independent fixture assertions inspect every generated file |
| Direct HTTP authority | UI-only check; direct quote succeeds without identity | Object ownership checked on server before grant and operation | Missing/invalid identity, wrong owner and guessed capability denied |
| Operation authority | No server capability | Opaque grant bound to session, object, exact integer quantity and expiry | Changed quantity/object/session rejected; rejected attempts do not consume a valid grant |
| Reuse | Unlimited fixture requests | Atomic single-use consume and principal query count | Eight concurrent uses of one grant produce one success and seven denials |
| Query oracle | Unlimited fixture requests | Four successful operations per principal, across fresh grants and sessions | Fifth operation denied; another principal keeps its own budget |
| Legitimate behavior | Quote result from the deliberately exposed function | Same authorized result from the server function | HTTP quantities 2/3 match; real Chrome UI returns 166 cents on both releases |
| Public readability | JavaScript, endpoint and map readable | JavaScript and endpoint still readable | REA successfully parses one JS file on both sides; this is expected |
| Algorithm inference | Formula delivered verbatim | Formula bytes absent from delivered release | **Two authorized outputs still reconstruct this linear function and predict a third** |

The HTTP trial has **16/16 passing assertions**, including the expected algorithm-inference counterexample. The Chrome probe has **4/4 passing assertions**: both legitimate UIs work, the protected UI rejects an invalid session, and no page script error occurs. The browser requires an ephemeral test-controller session entered in a labelled password input; no credential is embedded in the release, printed or persisted in public evidence.

`write_artifacts()` and the HTTP static handler share the exact byte exports. A separate integration test compares every generated file with its actual HTTP response. Missing maps, private source paths, encoded traversal and missing-file responses return safe 404 JSON; no filesystem fallback serves the Python engine. These controls are delivered by the lab server, not installed into an unrelated application automatically.

## Actual REA run

Pinned runtime: `rea-agents@6.7.0`, release commit `27dc42d10249f0410904a75c0997842eb03b931c`. The installed launcher's SHA-256 is recorded in the evidence. The adapter reports `integrityVerified: false`; an expected version and launcher hash do not establish a verified upstream build. No floating upstream package was installed or executed for this experiment.

| Sanitized observation | Before | After |
|---|---:|---:|
| Whole release files | 3 | 2 |
| Whole release bytes | 1,906 | 1,134 |
| Parsed JavaScript files | 1 | 1 |
| Parse failures / skipped JavaScript | 0 / 0 | 0 / 0 |
| Visited AST nodes | 94 | 140 |
| Static observation count | 3 | 3 |
| Application coverage reported by upstream | complete | complete |
| Semantic coverage reported by upstream | unknown | unknown |
| Overall adapter result / exit code | partial / 1 | partial / 1 |

The protected client has **more** AST nodes. Smaller AST counts, fewer observations or a parser failure are not our success criterion. Overall `partial` remains an explicit limitation because semantic coverage is unknown and upstream limitations remain. Raw REA graph properties, source literals, reconstructed endpoints and diagnostics were discarded by the Hunter adapter; its counts cannot independently establish private material absence or API authorization. Independent export inspection and real HTTP/browser tests establish the narrower claims above. Target code is not executed by REA; the separate browser trial intentionally executes only our owned fixture.

See [source research](../research/REA_DEFENSE_RESEARCH.md) for exact release/current-source differences and [independent challenge](../research/ANTI_REA_CHALLENGE.md) for falsifiers. The current upstream main was studied but not substituted for the pinned runtime.

## Reproduce

From the Shield repository root, Python 3.11+:

```text
python -m openshield anti-rea-lab --output output/anti-rea-results.json
python -m unittest discover -s tests -p "test_*.py" -v
python -m scripts.check_anti_rea_browser
```

The optional browser probe requires installed Node, Playwright resolvable through standard `NODE_PATH`, and Chrome. It starts and stops its own loopback servers, uses ephemeral in-memory controller sessions, and prevents browser requests to other origins. It installs no package and makes no provider call.

To repeat REA, create a **new** stable fixture directory first:

```text
python -c "from lab.anti_rea import write_artifacts; write_artifacts('output/rea-releases')"
```

Then use the sibling Hunter checkout's [REA skill](https://github.com/LumosLab-Innovation/OpenHunterAI/blob/main/.agents/skills/openhunter-rea/SKILL.md), configure its installed pinned `OPENHUNTER_REA_ROOT`, and run its fixed adapter on both complete `before` and `after` directories:

```text
node tools/cli/openhunter.mjs rea doctor
node tools/cli/openhunter.mjs rea analyze ABSOLUTE_BEFORE_DIRECTORY --authorized
node tools/cli/openhunter.mjs rea analyze ABSOLUTE_AFTER_DIRECTORY --authorized
```

Only the sanitized adapter report may be retained. A partial exit code is a coverage result to inspect, never a successful defense verdict. REA is optional operator software outside Shield's production dependencies; its process wrapper does not enforce OS network isolation.

## Independent review and remaining gates

The local suite completed **105 tests: 101 passed, 4 skipped**. Three skips are opt-in Docker experiments from the first lab; one is Windows denying unprivileged symlink creation. The new slice accounts for 21 release-policy tests, 23 independent adversarial tests and four integration tests. Adversarial review caught and closed HTML/Unicode/SVG/data-URI/archive map carriers, unusable initial client authentication, permissive authority header grammar and a report-output hardlink that could overwrite input bytes. Report writes now atomically replace the output entry; the independent regression verifies input preservation and temporary-file cleanup. Tests and published fixtures are regression evidence, not future hidden evaluation data.

The release policy has explicit gaps for unsupported containers, ambiguous syntax and uninspected carriers. It is not general secret/PII detection, a full JavaScript parser or a guarantee that private functions are absent. Header-checked images/fonts can still carry metadata. Scope it to an immutable copy of the actual complete deploy export; independently inspect precompressed files, runtime headers, CDN copies, service-worker caches and earlier releases. This run does not inspect any real application's deployment.

The quote identities, grants, quotas and lock are in-memory within one lab process. Restart and multiple workers would reset or split state; real authentication, durable shared atomic accounting, TLS, revocation, XSS/stolen authorized sessions, distributed abuse and production availability are unpassed gates. A four-query budget is a test policy, not a calibrated production setting, and already exceeds the two queries needed to infer this simple function. The synthetic formula is also public in this repository: the claimed boundary is browser delivery and server authority, not secrecy from GitHub readers.

AI receives no source or raw sessions from this module. Only an explicitly constructed synthetic `release_exposure` fact can enter the current synthetic runtime, where deterministic policy requests human review without claiming an attack. CLIProxyAPI/Codex remains unconfigured; incremental AI value is **not measured**. Removing a leaked release does not retract already downloaded information.
