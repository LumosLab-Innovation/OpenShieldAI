# Parallel PM/BA and anti-REA experiments

Observed **2026-10-24**. Capability: **S1 owned synthetic experiments**, using real loopback HTTP and actual protected fixture effects. No provider/model call, production action, authenticated production source or broad efficacy estimate. [Methods and use cases](../PARALLEL_DEFENSE.md), [independent challenge](../research/PARALLEL_DEFENSE_CHALLENGE.md), [machine-readable evidence](evidence/parallel-defense.json).

## What ran and what changed

The combined controller [check_parallel_defense.py](../../scripts/check_parallel_defense.py) ran four arms and passed **83 named assertions/case expectations**. The count includes positive controls, effect observations and acknowledged counterexamples; it is not 83 independent attacks or a prevention percentage.

| Arm | Checks | Actual observation |
|---|---:|---|
| Go downstream authority: PM A1/A2/A3 | 43 | Unsafe control completes one forbidden mark and one outside-recipient delivery; protected forbidden phase produces zero effects. Allowed work retains nine reads, one approved mark and one approved receipt. One of sixteen concurrent consumers succeeds |
| Original anti-REA export/HTTP experiment | 16 | Public export policy blocks the planted leaky release; reduced export passes. Unauthorized/object/session/parameter substitutions fail; legitimate outputs remain equal. Authorized outputs still expose the simple linear formula |
| Durable quote authority | 11 | Three HTTP server instances share state: replay stays denied, outstanding grants survive, principal quota remains spent across fresh sessions/restarts, revocation persists, backward clock returns 503, exact expiry is denied |
| HTTP representation/retirement policy | 13 | Clean identity/gzip pass; map headers, stale gzip, mismatching root and retired exports block; redirects, compressed bombs, invalid/multiple gzip and unsupported coding stay partial |

The delivery cases include a retired map that is absent under identity but present under gzip. Both encodings are now checked. A retired SPA fallback returning 200 is a retirement-policy violation; it does not prove that response contains private source. A source-map header is reported without fetching its target.

The quote authority stores only token digests and uses SQLite write transactions for one-use consumption and successful-query accounting. New sessions cannot reset the principal's four-query budget. Independent process races additionally verify shared state; the separate Go tool authority is still ephemeral and single-process. Neither experiment claims exactly-once external effects after a crash.

## Validation

The local Python suite ran **178 tests: 174 passed, four explicit skips**. Three skips require the separately opted-in Docker lab; Windows did not permit the remaining symlink test. The new tests include thirteen durable-authority tests, seven delivery/CLI tests and twenty-one independent challenges. The latter compile the actual Go package with three additional hostile HTTP tests in an isolated temporary module. Go package tests and `go vet` pass.

Seven delivery/CLI tests also verify output cannot overwrite the release, hardlink destinations preserve the source, invalid output is rejected before HTTP, safe reports omit private bytes, omitted details remain counted and a trickled response is interrupted by the total deadline. Ten additional offline script tests pass: six documentation-checker tests and four aggregate-report gate tests using labelled doubles. Selected experiment source and locally compiled Go binary hashes are retained in the evidence. Source hashing normalizes text line endings; these commitments establish consistency with this captured experiment, not source authenticity or production provenance.

The independent reviewer required and verified three corrections: a successful approved receipt to reject deny-everything behavior; checking the root entry alias; and checking retired assets under gzip as well as identity. The combined controller independently requires the expected unsafe effects, allowed effects, zero protected forbidden effects and single concurrent success before reporting a pass. See [tool details](TOOL_GUARD_RESULTS.md) and [review](../research/PARALLEL_DEFENSE_CHALLENGE.md).

## Reproduce

From the repository root, with Python 3.11+ and the declared Go toolchain:

```powershell
go -C runtime-go build -trimpath -o ../artifacts/runtime-go/shield-correlate.exe ./cmd/shield-correlate
go -C runtime-go build -trimpath -o ../artifacts/runtime-go/shield-tool-lab.exe ./cmd/shield-tool-lab
go -C runtime-go test ./...
go -C runtime-go vet ./...
python -m unittest discover -s tests -p 'test_*.py' -v
python scripts/check_parallel_defense.py
python scripts/check_docs.py
```

On Linux/macOS omit `.exe`. The combined record is written to `output/parallel-defense.json`; the committed record is a curated snapshot, not a live dashboard. No Docker, third-party target, remote model endpoint or upstream research executable is invoked by this combined controller.

## Practical meaning and remaining limits

These controls affect authority and public delivery even if an attacker can fully reconstruct the public client. Delivery inspection is a promotion gate only when the operator wires it into deployment; it does not block currently served bytes, purge a CDN or recall downloads. Its declared path/reference contract cannot prove absence of unknown routes or previous releases. The existing REA analysis is historical evidence: both clients parsed; no new REA efficacy measurement is attributed to this increment.

Scripted forbidden proposals test downstream authority, not whether an LLM follows a prompt injection. Recipient binding is not general DLP. Quotas limit accepted sampling, while two valid outputs can still reveal the fixture formula. Restoring an old valid database can roll back quota/time state; no off-host anchor exists. Local SQLite/controller identity trust, production TLS/storage, availability, multi-host state and real AI-versus-baseline benefit remain unpassed gates.
