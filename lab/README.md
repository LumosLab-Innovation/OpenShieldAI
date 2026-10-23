# Isolated first lab

This is an operator-controlled **synthetic experiment**, not a production deployment or a general incident-response adapter. It creates only the Docker Compose project `openshield-lab`, binds ingress to `127.0.0.1:18780`, publishes no origin/admin port and stores disposable synthetic state in ignored `artifacts/lab-state`. Existing containers and other projects are not changed. No Docker daemon socket is mounted in a service.

## Run

Requirements: Docker Linux engine + Compose, Python 3.11+, Go 1.26+. Build downloads only the manually pinned Go graph and the explicit restic image. The native build targets Linux amd64, with CGO disabled and four compile workers. All commands run from the repository root:

```text
python -m lab.control build
python -m lab.control start
python -m lab.control prevention
python -m lab.control response
python -m lab.control recovery
python -m lab.control stop
```

Ordinary unit tests do not start containers. After explicit build/start, PowerShell can execute the actual integration assertions:

```powershell
$env:SHIELD_RUN_LAB_TESTS='1'
python -m unittest discover -s tests -p test_lab.py -v
```

`stop` removes only this named project's containers/network and preserves state/artifacts. No automatic reopening on a timer exists. Maintenance remains until an explicit approved reopening or the experiment owner changes/recreates its proxy.

## Control and observation interfaces

`lab.control.Lab` exposes `config()` (root ETag and config digest), `set_mode(mode, expected_etag)`, `state()`, `request(relative_path)`, `probe()` and the three trial methods. Scope is fixed as `lab_id=openshield-lab`, `project_id=lab`, `asset_id=lab_web`. The Shield runtime must apply its policy/approval/audit services before dispatching **maintenance or reopening to on**. These controller methods by themselves are privileged local experiment tools, not an authentication/approval implementation. `off` and `detection` modes are negative-control setup available only to the experiment owner, never model actions.

The broker service has no network and shares the private Unix admin socket only with Caddy. It reads `/config/` then conditionally replaces the fixed route slot using its **root ETag** and `If-Match`; no `/load` path or generic remote shell is provided. The observer uses a different container/path and reads actual app counters, rather than trusting the executor. Fixture setup/checkpoint/contamination belongs to `stimulus.py`, not the read-only observer script. These internal lab endpoints share a trusted network; this fixture does **not** demonstrate production authentication, least-privilege source identities or an untrusted-app isolation proof.

The proxy rejects `/_lab*` before forwarding. Restic receives only synthetic files and a generated ignored password file. Restore mounts the frozen repository read-only, uses a full snapshot ID and a fresh empty scratch directory; `--no-lock` is permitted only under this single-writer isolated experiment. The restore container drops all Linux capabilities and adds only `CHOWN`/`FOWNER` to restore the fixture file's original owner and timestamps; an actual first run without those capabilities failed and was not counted as recovery. Only the empty isolated destination is writable. The verifier copies the restored database into ephemeral scratch, starts the trusted fixture application, checks SQLite integrity and business/trust invariants, and executes a real local HTTP transaction. It does not execute restored code or reconnect a recovered service to production.

## What the trials prove and do not prove

- Prevention compares WAF Off, DetectionOnly and On for three CRS-shaped inputs plus three legitimate inputs. A planted operation increments a synthetic harm counter if the request reaches the app. Request status **and independent app non-effect** are required. These are not real SQLi/XSS/RCE exploit demonstrations and the corpus cannot support a general attack-blocking or false-positive claim.
- Maintenance checks new requests no longer reach the app, legitimate requests receive 503, admin remains available, stale ETag gets 412, the private persistent autosave retains maintenance across an actual proxy restart, and authorized reopening resumes requests. Previously accepted HTTP/background work is measured separately. There is no host/session/egress actuator, native expiry, WebSocket scenario, or production incident commander in this fixture. Autosave missing/corrupt storage and unacknowledged crash windows are not covered by the restart test. Automated fixture approval has zero simulated human wait and cannot establish human response latency.
- Recovery backs up an application-consistent SQLite copy, records an immutable snapshot, checks all repository data, then deliberately deletes synthetic account rows. The independent observer must see the loss and a transaction must fail before restoring into empty scratch and checking the running app. Missing-key, wrong-key, corrupted-pack, known contaminated-build-marker and application-inconsistent copies must fail. The known marker is not a malware scanner. RPO is checkpoint-to-declared synthetic incident with one intervening committed transaction; RTO is restore start through application verification, not a production reconnection SLO. The experiment owner reseeds the disposable source fixture after the test; that setup step is not credited as recovery.
- Logging excludes connector/error/admin API loggers and disables request access, Coraza audit and debug output. A seeded sensitive-looking query marker is tested against actual app/proxy stdout/stderr. Suppression loses WAF-detail telemetry; fixture observations carry only controlled labels, status, count deltas and timestamps. This does not claim a general sanitizer or production forensic retention design.

## Pins, provenance and third-party licenses

The connector is [e268cf0f44e95d64da81c641aabebd21364be6f1](https://github.com/corazawaf/coraza-caddy/tree/e268cf0f44e95d64da81c641aabebd21364be6f1), resolved as `v2.6.3-0.20261015122811-e268cf0f44e9`; its unchanged module graph selects Caddy 2.11.4, Coraza 3.8.1 and embedded CRS 4.30.0. `go.mod`/`go.sum` pin the graph. No upstream source is vendored and no source patch is applied. Config changes are the explicit logging suppression and bounded lab policy. Caddy/Coraza use Apache-2.0; [CRS](https://github.com/coreruleset/coreruleset/blob/v4.30.0/LICENSE) uses Apache-2.0; [restic](https://github.com/restic/restic/blob/v0.19.1/LICENSE) uses BSD-2-Clause. These upstream licenses are separate from the root project's PolyForm Noncommercial license.

Python/base image digests are pinned in Compose/Dockerfile. Restic 0.19.1 is pinned to `sha256:136600b6ff6843d61d355f7f71f460a166429f35de6fd11b568fece3c9a4d510`; operations use this immutable digest. `artifacts/lab-build/provenance.json` records actual image IDs, binary SHA-256, Go graph, versions and logging policy. Build metadata and real trial outputs belong with an evaluation report; successful build alone demonstrates no efficacy. Full upstream CRS regression, dependency security review and production hardening remain separate unpassed gates.

Actual provisioning rejected the pinned full `@owasp_crs/*.conf` bundle: `RESPONSE-955-WEB-SHELLS.conf` references `web-shells-php.data`, absent from the embedded 4.30.0 module. The selected, explicit first-lab policy therefore loads **`REQUEST-*.conf` only**, including inbound blocking evaluation, with response-body inspection disabled. No response-rule coverage is claimed and no missing file is fabricated or upstream version silently upgraded. This compatibility finding is part of the lab evidence.
