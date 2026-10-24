# Anti-REA independent efficacy challenge

Status: review criteria for the owner-authorized synthetic web lab, 2026-10-24. This review is deliberately separate from the implementation. A passed fixture assertion is not proof against every reverse-engineering technique or a production release gate.

## Verdict to earn

Protecting an application's private computation and server authority is useful. Making public JavaScript harder to parse is not, by itself, protection. An authorized browser receives the code and outputs necessary to operate the public interface; those remain observable and reproducible. There is no legitimate universal client-side "anti-REA" switch.

The selected experiment should demonstrate this narrower result: the defended release does not distribute its declared private computation or privileged credential, and copying or modifying its public client does not confer server authority. It must preserve the intended legitimate workflow. Lower file, module or AST counts are descriptive only.

The reference tool is [REA 6.7.0 at pinned release commit 27dc42d](https://github.com/morluto/rea/tree/27dc42d10249f0410904a75c0997842eb03b931c). Its [JavaScript reconstruction workflow](https://github.com/morluto/rea/blob/27dc42d10249f0410904a75c0997842eb03b931c/docs/javascript-artifact-reconstruction.md) provides static inspection and explicit coverage limitations. OpenHunter's fixed adapter exposes sanitized aggregate observations, not a secret-absence verdict. OpenShield must not reinterpret a parser timeout, unsupported input, zero observations or reduced AST count as successful defense.

## Claims and falsifiers

| Claim | Independent test | Falsifier / release consequence |
|---|---|---|
| Private material is not shipped | Inventory every actual served release asset, including maps, JSON, manifests, compressed variants and error/static fallback routes; compare against declared forbidden synthetic materials | One matching private export invalidates the claim; inspecting one selected bundle is insufficient |
| Legitimate behavior survives | Execute the same accepted business inputs before and after defense and compare output/side effects | Refusing all requests or silently changing outputs is not protection |
| Client modification does not grant authority | Call the API directly, without UI, with absent/invalid capability, another object and altered bound parameters | UI-only gating, CORS, hidden endpoints and client-side entitlement checks do not count |
| Capability scope is exact | Attempt a valid capability against a different object/operation/input; try unknown extra fields and malformed types | Any request gaining broader authority than its grant is a blocking failure |
| Replay is bounded | Spend an accepted capability twice; test expiry and concurrent use where supported | Reusable action permission or race-dependent duplicate effect invalidates single-use claims |
| Server computation is not a free oracle | Exercise bounded repeated requests using the same authenticated principal, including obtaining fresh capabilities | Per-token limits alone do not establish principal/session/global limits; the scope must be stated |
| Public client remains inspectable | Run the pinned adapter on the exact defended export, retaining partial/unknown states | A defense that works only because analysis failed has not protected information |
| Output and errors remain minimized | Compare permitted response fields, denied error fields and ordinary logs; avoid echoing credentials or private internals | Server migration that returns private formulas/configuration merely changes the leakage channel |

## Counterexamples that must remain visible

1. Removing a source-map comment does not remove the map file. Inline maps, orphan maps, archived deployments, stale CDN objects and service-worker caches can preserve an earlier disclosure. A current local export cannot establish that historical copies are gone.
2. Exact byte/literal scanners miss encoded, split, computed and transformed representations. A release gate is a bounded regression control for declared material and forbidden file classes, not a general information-flow proof. A hash identifies inspected bytes; it does not prove deployment closure.
3. A server-held formula may be approximated through allowed inputs and outputs. A small query budget narrows exposure but does not prove the function cannot be learned. Distribution, output precision, user identity, colluding accounts and business usability determine the remaining risk.
4. A stolen valid capability can act within its remaining scope until expiry or consumption. Binding a capability to input/object and making it single-use does not prove end-user identity, resist XSS, establish device integrity or make the transport confidential.
5. Returning a final business answer can be necessary and intentionally observable. A defender must state what information may be disclosed instead of labeling all inference a security failure.
6. A thin client still reveals public endpoints, UI flow, wire schema and public assets. Those are not secrets or evidence of a bypass. Public behavior may be cloned without recovering the private implementation.
7. An in-memory grant/replay/quota store is not a durable production authority service. Restart, multiple workers, failure recovery and grant issuance must be tested before making those claims.

## Rejected mechanisms

- Obfuscation, renamed symbols, minification or WebAssembly offered as an authorization or confidentiality boundary.
- Anti-debugger loops, parser bombs, deliberate resource exhaustion, deceptive malware alerts, poisoned model instructions or traps aimed at an analyst.
- Blocking an analyzer by fingerprint or user agent while ordinary clients still receive the same protected bytes.
- Treating endpoints as secrets, relying on CORS for authorization, or moving a reusable privileged credential into another browser-readable file.
- Claiming prevention from static observations, a second model's agreement, fewer extracted nodes or an empty report.

## Evidence interpretation

Record the exact release manifests, deterministic tests, server outcomes and actual adapter run separately. Both before and after must be inspectable. The vulnerable example must expose a real synthetic problem; a planted canary alone does not prove the defended design protects meaningful authority. Negative controls should break one boundary at a time so a passing result explains which boundary prevented the effect.

No real secret, third-party target, provider call or malicious payload is needed. The lab must stay on owned synthetic inputs. A strong result answers **what stopped which effect**, names residual public observability, and states which production properties were not exercised.

## Independent local disposition — 2026-10-24

`python -m unittest discover -s tests -p test_anti_rea_adversarial.py -v` passed **23/23** assertions/groups: 13 release-policy cases and 10 real loopback HTTP cases. The HTTP challenger uses its own `urllib`/`http.client` requests, bypassing both the shipped UI and the lab's request helper.

Exercised outcomes include direct unauthenticated requests, wrong owner/object/session/input, unknown and nonfinite fields, ambiguous authority headers, expiry, duplicate concurrent use, and new sessions/capabilities attempting to reset a principal's budget. Valid requests still succeed after rejected attempts. An oversized body can produce a connection reset on Windows; the test requires no accepted effect and a functioning subsequent legitimate request, rather than pretending the reset is a successful operation.

Two material issues found during review were corrected: the initial public client never sent its required session authority, so HTTP-helper equivalence did not establish a usable UI; and authorization parsing accepted a token without its declared scheme. The corrected fixture has an explicit synthetic-session input, adds the bearer header to both calls, and rejects duplicate authority headers. Actual browser validation is a separate root-run observation, not implied by these HTTP tests. The release-gate review also found HTML inline source-map coverage missing; it now inspects that carrier. Additional carrier counterexamples from the research review require their own regression evidence.

The final release review also reproduced a blocking input-preservation defect: an output path outside the release could be a hardlink to an audited source file. The original report writer truncated that source even though the audit correctly rejected the hardlink. Reports now use a new same-directory temporary file and atomic replacement, so they never write through the existing destination inode. The independent regression verifies unchanged source bytes and cleanup of temporary report files. A partial audit remains partial; writing its report cannot alter the inspected artifact.

**A stronger algorithm-confidentiality claim is falsified by the lab itself.** Two permitted output values reveal the synthetic linear formula, and an independently predicted third value matches the actual server answer. Moving the implementation off the client and limiting queries did not make that function unlearnable. The useful result is a smaller shipped disclosure surface and server-enforced operation authority, not immunity to reconstruction.

Accept the narrow experimental claim only. The final review matched the published source fingerprints and both release manifests against the retained REA summaries; successful parsing on both sides and unknown semantic coverage are reported accurately. This reviewer did not run a production deployment, real identity provider, TLS/XSS assessment, durable multiworker quota/replay store, historical-cache purge, or arbitrary algorithm-extraction benchmark. Actual Chrome and pinned REA runs are separately recorded root-run observations; the independent HTTP outcomes do not depend on the analyzer failing.
