# Experimental local runtime

The Python 3.11+ runtime accepts **synthetic lab data only**. It is an S1 implementation with isolated control/recovery experiments, not a production pilot or a supported incident-response deployment. No Python package installation or provider SDK is needed. See [measured results](lab/RESULTS.md), [independent review](lab/EFFICACY_REVIEW.md) and [lab setup](../lab/README.md).

## Run the smallest slice

From the repository root:

```powershell
python -m openshield --help
python -m openshield --state incident-data/demo.sqlite3 init
python -m openshield benchmark --output output/comparison.json
python -m unittest discover -s tests -p 'test_*.py' -v
```

The benchmark freezes source/corpus hashes before scoring. Its 48 cases comprise 36 functional decision cases and 12 boundary-rejection cases; labels, groups and expected outcomes stay outside runtime/model inputs. Both arms use the independently registered replay clock, `2026-10-24T00:42:00Z`, for evidence freshness/enrollment; network deadlines retain real clocks. Historical freshness gaps are reported, not rewritten away. An unconfigured AI arm has `metrics: null`, not a simulated score. A conservative abstention on a benign trace is counted policy-acceptable and separately reported; do not call that decisive classification accuracy. Some input facts already resolve authorization/contamination, so this corpus does not establish AI discovery or operational advantage.

`ingest <file>` imports one case's JSONL or JSON array atomically, limited to 1,000 records/1MB. The exact `lab_event_v1` fact catalog is in [core.py](../openshield/core.py); unknown fields, unsupported data classes, scope/source changes, credential-shaped labels and conflicting duplicate IDs are rejected. This is a narrow allowlist, not a universal secret/PII sanitizer. Original incident material is unsupported.

`tick --mode baseline` performs deterministic investigation. `tick --mode ai` uses the configured gateway or visibly records degradation. `serve --mode ai --duration 60 --interval 10` repeats cheap scheduler ticks; unchanged evidence is deduplicated across restart. Freshness-gap transitions trigger one new bounded review. The process is serial; two is a concurrency ceiling, not a throughput claim. Configured inference jobs remain individually bounded even when service shutdown waits for a running job. The runtime has no public API or dashboard and uses local OS-user authority.

SQLite persists immutable enrollment, accepted evidence, source roles, case watermarks, episode reservations and health. The initial catalog reads only bounded subsets of that same synthetic timeline; it is not a live telemetry collector. Missing visibility and provider failure remain visible. There is no real-world AI coverage claim from a healthy scheduler process.

## CLIProxyAPI / Codex adapter

All reasoning passes through [gateway.py](../openshield/gateway.py). The selected transport is CLIProxyAPI's OpenAI-compatible, non-streaming `POST /v1/chat/completions`; Codex account authentication stays entirely in the operator's separate proxy. Shield does not read Codex OAuth files, launch Codex CLI, provision keys or inherit `OPENAI_API_KEY`.

Reviewed upstream: [CLIProxyAPI commit 8289ec4](https://github.com/router-for-me/CLIProxyAPI/tree/8289ec4c71ad914d0612c2776352b76ba3d355a6), observed 2026-10-24; [MIT license](https://github.com/router-for-me/CLIProxyAPI/blob/8289ec4c71ad914d0612c2776352b76ba3d355a6/LICENSE). No proxy source is vendored or installed by the runtime. [The minimal proxy example](../config/cliproxy.example.yaml) uses its reviewed v8 configuration layout; configure Codex OAuth and model routing using the upstream's own instructions. Bind the proxy to loopback, keep its authentication directory outside source control, select one known Codex route and disable sensitive request logging in the proxy's own deployment.

Once the operator has an authenticated proxy endpoint and a client key in `SHIELD_CLIPROXY_API_KEY`, set these nonsecret route values:

```powershell
$env:SHIELD_LLM_PROVIDER='cliproxyapi'
$env:SHIELD_LLM_BASE_URL='http://127.0.0.1:8317/v1'
$env:SHIELD_LLM_MODEL='your-configured-codex-alias'
$env:SHIELD_LLM_ALLOW_LOOPBACK_HTTP='true'
$env:SHIELD_LLM_API_KEY_ENV='SHIELD_CLIPROXY_API_KEY'
$env:SHIELD_LLM_GLOBAL_TOKEN_LIMIT='64000'
python -m openshield benchmark --with-ai --output output/comparison-with-ai.json
```

These commands do not create or print a key. `.env.example` is a reference and is not automatically loaded. An explicit `--with-ai` enables provider calls for the benchmark; ordinary benchmark runs are offline. The initial 64k global reservation ceiling may stop a larger comparison; raise it only after selecting the operator's acceptable budget. Shared evaluation reservations survive per-case database isolation within a run; they are not an account-wide quota across separate benchmark processes.

Only explicitly configured literal-IP endpoints are supported initially, avoiding unbounded hostname DNS resolution. Plain HTTP additionally requires explicit loopback permission; other addresses require verified HTTPS. Redirects, environment HTTP proxies, tools, arbitrary paths, credential fallback and model-created routes are forbidden. Requests/replies have size, deadline and retry limits; outputs must use known evidence references, hypothesis enums, actions and reads.

Each reasoning episode allows at most eight calls, 64k conservative visible-token reservations, 180 seconds, two read rounds and three reads per round; per-call deadline is 20 seconds and one transient retry. Model-requested evidence cannot reset a budget. Reservations count failed attempts and are **not actual billing**. Proxy-hidden reasoning/account usage and an alias's actual upstream model are not independently established; real-provider budget, usage, model compatibility and retention checks remain open. Unit HTTP contract tests use a visibly named local double, never an efficacy result.

Even after connection, an AI-benefit claim needs harder held-out ambiguous cases, genuinely useful additional observations, an equally capable baseline/operator and measured correctness, harm, time, cost and adverse proposals. Fluent explanations and this structured fixture score are insufficient.

## Exact approved lab actions

Use a **new** state file initialized with `init --enable-lab-actions` when testing actions; enrollment is immutable. Only project `lab`, asset `lab_web` and the fixed dedicated lab deployment are supported. Start the lab using its [instructions](../lab/README.md) first. Import fresh accepted synthetic observations, then review the complete proposal:

```powershell
python -m openshield --state incident-data/action-demo.sqlite3 init --enable-lab-actions
# Ingest fresh lab_event_v1 observations for your case before proposing.
python -m openshield --state incident-data/action-demo.sqlite3 propose CASE_ID --accept-lab-interruption
python -m openshield --state incident-data/action-demo.sqlite3 approve PROPOSAL_ID EXACT_DIGEST
python -m openshield --state incident-data/action-demo.sqlite3 execute PROPOSAL_ID APPROVAL_ID --enable-lab-actions
```

The current OS account maps to an opaque local operator ID. Exact digest, project/asset, immutable enrollment, case version/watermark, expiry, accepted interruption, enrolled observer role and target ETag are rechecked. Source role labels in imported synthetic data are operator assertions, not cryptographic source authentication. A case with old historical evidence is conservatively denied mutation even after a new fact; source-scoped freshness needs further design. The approval is consumed before dispatch. A receipt leaves verification pending; the independent app observer must show the actual effect and service interruption. `reconcile PROPOSAL_ID` only reads uncertain state; it authorizes no retry. `kill` revokes pending dispatches and does not reverse in-flight operations.

Maintenance deliberately returns 503 and stops new ingress. It does not isolate hosts, revoke sessions or stop egress. Reopening uses a separately reviewed `propose ... --mode on` with a current ETag and new approval. The review deadline is not automatic expiry. The privileged lab controller is the experiment owner's infrastructure tool, outside the model/runtime broker; it can intentionally set Off/DetectionOnly for negative controls.

This action profile serializes operator CLI work. Separate SQLite case/action stores are not a distributed transaction; concurrent ingestion/dispatch, multi-operator authentication, off-host audit completeness, production credentials, application dependency discovery, broad cancellation and production isolation remain unpassed gates. Do not attach the fixture to customer systems.
