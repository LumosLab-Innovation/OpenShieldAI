# Fixed application-flow effect lab

Status: **S1 synthetic engineering experiment**, reviewed 2026-10-24. This extends selected [PM cases](../research/SECURITY_PORTFOLIO.md) and [BA methods M01/M02/M11](../research/DEFENSE_METHODS_AND_HYPOTHESES.md) using Go's standard library. It adds no production identity, cloud/network collector, general URL fetcher or response adapter. The existing [parallel-defense boundary](../PARALLEL_DEFENSE.md) remains applicable.

## Mechanism and independently observed effect

The executable starts owned loopback HTTP application, allowed inbox and separate forbidden receiver fixtures, exercises a fixed scenario, reads ledger/receiver state through separate observer functions and closes every server. HTTP responses alone cannot establish the ledger or delivery assertions. The application returns different fixed synthetic object values so that the cross-tenant negative control proves disclosure of another object's bytes as well as an incremented read counter. These values never enter the exported report.

| PM case | Implemented method and unsafe comparison | Protected effect and legitimate control | Remaining boundary |
|---|---|---|---|
| **I1: credential abuse** | Per-principal three-failure, sixty-fixture-second window stops another authenticator check before session issuance. Unsafe comparison accepts the next correct fixture proof and the resulting session reads an object | Correct fixture proof after three failures receives `429` with no further authenticator invocation; another principal can log in; correct proof works after the window | `/login` accepts `proofClass` as a **synthetic authenticator result**, not a real password, MFA or IdP. The denied correct login is a measured lockout cost. A valid stolen proof before failures remains usable; no attack intent is inferred |
| **I2: stolen session** | Both declared resource verifier paths consult current server authority. Unsafe second path retains a warmed session cache after revocation | Revoked session cannot read either protected path. A separate paused request is revoked after its first check and denied at the final pre-effect recheck. A fresh valid session still reads | One ephemeral process, two declared paths. No JWT propagation, refresh-token or external IdP coverage. An already committed effect or dispatched transfer cannot be recalled |
| **W3: cross-tenant object access** | Ownership matrix is checked at each resource path. Unsafe alpha principal reads beta's fixed synthetic value | Both protected paths return no object value and add no read; an alpha session receives its own value | Two fixed objects/principals. No field-level, delegated/shared ownership or production entitlement model |
| **W3: duplicate transaction** | Exact session/object/operation/units/idempotency-key capability; controller approval is outside HTTP. Single serialization point checks authority and records the fixed ledger effect plus idempotency record | Unsafe repeated key creates two rows. Protected one-use replay is denied; a fresh approved capability for the same key reconciles to the existing row; changed payload gets `409`. Sixteen concurrent distinct capabilities for one key produce one ledger commit | In-memory atomicity only. The fixture does not simulate dropping a response packet: the reconciled retry represents the caller not knowing the outcome. No crash-safe database or external-payment guarantee |
| **W4/D4: outbound pivot/data delivery** | Request selects a fixed recipient ID, never a URL. An approved exact export capability reaches one fixed synthetic inbox. Unsafe direct-outside and allowed-recipient `307` redirect both deliver the planted synthetic body to a separate forbidden sink | Protected outside recipient is denied; approved inbox receives one body; replay gives no second body. A `307` from the enrolled recipient is refused: forbidden receiver observes **zero requests and zero data deliveries** | Fixed HTTP receiver mediation, not general SSRF protection or DLP. No DNS resolution/rebinding, metadata-service tests, non-HTTP protocol, alternate process or historical disclosure coverage. External delivery failure spends the capability and requires reconciliation |
| **W3: continued sessions/resource bounds** | Eight reads per principal remain shared across fresh sessions. Fixture admission caps four concurrent requests and eight sessions per principal | Ninth read via a fresh session is denied; eight prior reads succeed. Four paused HTTP requests fill admission; fifth gets `429` before any read; releasing the four preserves their legitimate reads | Lifetime fixture quota, not a business policy recommendation. These controls can deny legitimate bulk work. No load, fairness, slow-client or production denial-of-service result |

The application-side ownership method follows the object-check requirement in [OWASP API1:2023](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/). Per-principal throttling and its lockout trade-off are informed by [OWASP Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#login-throttling). [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009.html#section-2.1) motivates checking actual verifier rejection after revocation instead of accepting a revocation receipt. The endpoint catalog and redirect refusal apply the narrower fixed-destination pattern in [OWASP SSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html); this fixture does not implement that document's full network defense. These are design references, not certification or upstream code adoption.

## Measured result

The fixed trial passed **48/48 named engineering checks**. This counts assertions, not 48 independent attacks or a representative efficacy sample.

| Independent observer / main fixture | Unsafe comparison | Protected |
|---|---:|---:|
| Ledger reads, including warm/legitimate probes | 4 | 2 legitimate; 0 during declared forbidden-request windows |
| Ledger charges | 3: duplicated transaction twice, revoked in-flight request once | 2 approved transactions, including one concurrent idempotency commit; 0 forbidden |
| Charged units | 3 | 2 approved; 0 forbidden |
| Synthetic body deliveries to forbidden HTTP sink | 2 | 0 |
| Requests of any body to forbidden HTTP sink | Positive negative-control delivery requests | 0 |
| Approved synthetic body deliveries to allowed inbox | Not used as a positive assertion | 1 |
| Distinct-capability concurrent idempotent commits | Unsafe duplication is measured separately | 1 from sixteen simultaneous calls |

Separate quota and admission fixtures add eight successful reads before the ninth is denied, and four successful paused/resumed reads after the fifth concurrent request is refused. Their positive reads are not added to the main fixture's two-read total. Concurrency admission may reject some of the sixteen transaction calls with `429`; the invariant is at least one accepted response and exactly one independently observed commit, not sixteen successful requests or measured throughput.

The four `observations` entries in `flow_lab_v1` export only bounded integer facts and fixed identifiers. They describe these known engineering comparisons. The unsafe/protected labels already reveal the test arms; they are unsuitable as hidden labels in a held-out AI detector benchmark. Provider comparison must freeze its own inputs, ground truth and uncertainty scoring and retain exactly the same controls, observations and authority in each arm. This executable makes **zero model calls** and measures no AI benefit.

## Run and reproduce

From the repository root:

```text
go -C runtime-go run ./cmd/shield-flow-lab
go -C runtime-go test ./...
go -C runtime-go vet ./...
python -m unittest discover -s tests -p test_flow_lab.py
```

The command accepts no arguments. Supplying a target or URL exits nonzero before starting a lab. It writes a bounded JSON report and exits nonzero on any failed check or transport/setup failure. A partial failure cannot retain `status: passed`. The Python integration test builds the fixed command into a temporary directory using local Go with dependency download disabled, checks actual effects and verifies the no-target CLI contract.

Source: [flowlab implementation](../../runtime-go/flowlab/flow.go), [trial](../../runtime-go/flowlab/trial.go), [Go tests](../../runtime-go/flowlab/flow_test.go), [fixed command](../../runtime-go/cmd/shield-flow-lab/main.go), [Python integration checks](../../tests/test_flow_lab.py). There are no added dependencies.

## Authority and limits

Sessions, capabilities, throttles, transaction records and revocation are deliberately **ephemeral synthetic state**. The separate Python/SQLite quote authority's durable guarantees do not transfer to this Go experiment. The controller uses random opaque tokens; request content cannot call controller session/revoke/approve methods, choose endpoints or create authority. Report output contains no session/grant values, actual local URLs or raw body values.

Bounds are explicit: 1 KiB request bodies and server header limit, bounded response reads, two-second HTTP client/transport deadlines, one-second fixture pause ceiling, four admitted handlers, sixteen total session records/eight per principal, sixty-four pending grant records, thirty-two idempotency keys, twenty-four admitted login checks and eight reads per principal. Controller fixture time governs sixty-second sessions, thirty-second grants and the login observation window. The global login-check ceiling lasts the whole fixture run; it is a resource ceiling, not a measured global sliding-window policy. Stale records are not automatically reclaimed in this short trial; reaching capacity denies more work.

The observer is separate from HTTP executor receipts but shares the trusted process and host. Local memory corruption, privileged host access, restart, external verification systems and existing egress paths remain outside the claim. No persistence removal, recovery, credential rotation, TLS/identity hardening or real incident containment is established. Client readability and known object/endpoint names are assumed; server mediation remains necessary even when REA reconstructs every client route.
