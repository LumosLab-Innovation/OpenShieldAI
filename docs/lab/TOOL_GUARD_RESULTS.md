# Tool authority lab: A1, A2 and A3

Measured on **2026-10-24**. Capability stage: **S1 synthetic experiment**, not an installed production broker, authenticated source adapter, AI evaluation or general prompt-injection defense. This increment implements the selected [PM A1/A2/A3 scenarios](../research/SECURITY_PORTFOLIO.md) through the [BA M01/M11 authority boundary](../research/DEFENSE_METHODS_AND_HYPOTHESES.md). The protected effect, rather than a detector verdict, is the test outcome.

## Mechanism and experiment

The standard-library Go fixture starts two ephemeral loopback HTTP servers: the same fixed operation catalog with capability enforcement disabled and enabled. There is no shell, executable path, target URL, arbitrary filesystem access, generic recipient address, model call or production target. The unprotected variant is a deliberately unsafe negative control reachable only for the duration of this local experiment.

A trusted test controller creates opaque random session identities and grants through in-process methods outside the HTTP surface. An HTTP caller cannot mint approval. A grant binds the session/agent/tenant, case, asset, object, operation, normalized parameters, recipient, synthetic data class, scope/policy version, evidence revision and expiry. The server checks all these fields at the actual tool boundary and atomically consumes one grant before its fixed effect. Failed substitutions do not consume the valid grant. Mutation issuance additionally requires an explicit controller approval; a body field or peer instruction cannot provide it.

The fixed operations are `read_record`, `mark_reviewed` and `send_receipt`. A mark changes an in-memory fixture record from pending to reviewed. Reads return its current state. A receipt stores a fixed synthetic message in a recipient-specific in-memory inbox. The independent fixture observer reads record/inbox counters separately from HTTP receipts; it does not trust the executor's completion response. This is separate in-process observation, not an external source trust guarantee.

The A1 stimulus is a scripted forbidden operation representing the request an agent could propose after poisoned tool text. No LLM reads that text or chooses the operation in this experiment. The lab tests whether even that selected forbidden request can cause an effect, not the probability that a prompt injection changes a model's behavior.

## Observed results

`go -C runtime-go run ./cmd/shield-tool-lab` completed **43/43 named checks**. Those checks include effect assertions and positive controls, not 43 distinct attacks.

| Arm / observation | Independent observed result |
|---|---|
| Enforcement disabled, forbidden planted mark | One record mutation completed |
| Enforcement disabled, receipt directed outside the approved recipient | One message reached the `inbox_beta` fixture receiver |
| Enforcement enabled, selected forbidden requests | Zero reads, marks or receipts during the negative-request phase |
| Valid read retained after all attempted substitutions | Returned pending; no failed substitution had consumed its grant |
| Original approved receipt after wrong-recipient substitution | Exactly one message reached `inbox_alpha`; zero reached `inbox_beta` |
| Original read / receipt grants reused | Rejected; independent counts unchanged |
| Sixteen concurrent consumers of one approved mark grant | Exactly one completion and one mark; fifteen requests denied |
| Benign service after attacks and concurrency | Eight further fresh-grant reads returned reviewed |
| Total protected allowed operations | Nine reads, one explicitly approved mark and one explicitly approved receipt |
| Actual model calls / production actions | Zero / zero |

Selected rejections cover read-to-write escalation, case/asset/object/agent/tenant changes, recipient and data-class substitution, scope/policy/evidence drift, parameter substitution, no grant, forged approval token, forged session, cross-agent grant use and actual elapsed expiry. Exact JSON tests reject case aliases, duplicate and escaped-duplicate field names, unknown fields, nested/unknown parameters, bool/float/exponent/null integer substitutions, integer overflow, invalid UTF-8, oversized input, truncation and trailing documents. HTTP tests also reject alternative paths/methods, query-based approval, incorrect media type and duplicate grant headers.

The successful approved receipt matters: a control that denied every delivery would fail the positive-control assertion. The successful read and mark similarly reject a deny-everything implementation. The unsafe control's observed mutation and inbox delivery demonstrate that the selected stimuli were capable of causing the planted effects when authority was absent.

## Bounds and reproduction

From the repository root:

```powershell
go -C runtime-go test ./...
go -C runtime-go run ./cmd/shield-tool-lab
go -C runtime-go test ./toolguard -count=5
```

All Go package tests passed locally; five repeated toolguard test runs also passed. The command returns nonzero on a failed assertion and emits only fixed codes, aggregate counter deltas and limitations. Session/grant values, request bodies, tool text, ephemeral addresses and response bodies are not reported.

The JSON body limit is 2 KiB; string fields are at most 64 bytes and the normalized value at most 32 bytes. Four sessions and 128 outstanding grants cap controller state. Grant lifetime is at most one minute. HTTP read/header/write deadlines and the client request timeout are at most two seconds. The selected replay race has 16 callers; this is not a throughput benchmark. Local Windows `go test -race ./toolguard` could not run because this environment has no configured cgo C compiler. The concurrency assertion ran with the ordinary Go runtime, not the race detector.

## What these results do not establish

- This is complete mediation for three declared synthetic operations, not a claim that arbitrary tools, models, plugins or agent systems are protected. No prompt classifier or instruction filter is used as an authority boundary.
- A2 proves fixed synthetic recipient/data-class binding and actual delivery into an in-memory fixture inbox. It does not inspect arbitrary content, find encoded secrets, provide general DLP or prevent an authorized recipient from redistributing data.
- The controller is the trusted approval authority in this experiment. No real human identity, signing service, TLS deployment or cross-host approval protocol is implemented here. A compromised controller/host is outside the measured boundary.
- Scope, policy and evidence revisions are fixed during a run. Request rebinding is tested; external policy change propagation and dynamic enrollment revocation are not.
- Sessions, grants and fixture state are ephemeral and single-process. A crash between consume and effect can lose an operation; durable unknown-outcome reconciliation, multi-process concurrency and restart guarantees are not claimed.
- An allowed operation can be semantically harmful, and a legitimate principal can intentionally request an approved bad action. Binding cannot determine intent or replace owner review. Real AI benefit, production effectiveness, workload availability and broad security coverage remain unmeasured.

The authority boundary is consistent with the repository's [mandatory guardrails](../SECURITY_GUARDRAILS.md): untrusted evidence may influence a proposal but cannot create execution authority. No upstream implementation or rule set is copied, installed or executed by this lab.
