# REA-informed defense: remove exposure and retain server authority

Research date: 2026-10-24. This document studies the actual public REA implementation and OpenHunterAI's deliberately narrower adapter. It proposes defenses against unauthorized reconstruction and business-rule abuse; it does not characterize reverse engineering itself as an attack. Implementation and measured outcomes belong in the anti-REA lab results, not in this source review.

## Scope and evidence identity

| Subject | Exact identity | What was inspected |
|---|---|---|
| Installed optional runtime | `rea-agents@6.7.0`, release commit `27dc42d10249f0410904a75c0997842eb03b931c` | Local package metadata and compiled JavaScript, read-only; public source at the release commit |
| Current upstream snapshot | `7958e15892a59d313d90bd678273271593dc10b4`, committed 2026-10-24 02:35:50 UTC | Public source and documentation, read-only |
| OpenHunter boundary | Existing `tools/cli/rea.mjs` and `docs/REA_INTEGRATION.md` in the adjacent owner-controlled checkout | Fixed command, limits, output allowlist and interpretation |

The current snapshot's `package.json` still declares version `6.7.0`, although GitHub's comparison reports 1,530 commits ahead of the selected release. A package-version match alone cannot identify development behavior. The pinned release remains the lab baseline; the current source is a separately identified research snapshot. No upstream code was executed, installed, vendored or modified for this review. No target artifact, source map, provider credential or raw analysis result was published. REA-authored code is MIT; external tools retain their licenses. These are provenance observations, not independent package-integrity attestation. Sources: [release tree](https://github.com/morluto/rea/tree/27dc42d10249f0410904a75c0997842eb03b931c), [current snapshot](https://github.com/morluto/rea/tree/7958e15892a59d313d90bd678273271593dc10b4), [current package metadata](https://github.com/morluto/rea/blob/7958e15892a59d313d90bd678273271593dc10b4/package.json#L1-L12), [upstream license](https://github.com/morluto/rea/blob/27dc42d10249f0410904a75c0997842eb03b931c/LICENSE).

## What REA actually recovers

The important boundary is **which bytes and behavior were delivered to the observer**, rather than whether a particular extractor currently understands every expression.

| Stage | Source-backed behavior | Defensive consequence and limit |
|---|---|---|
| Artifact inventory | Directory/ASAR workflow inventories selected files and classifies package metadata, JSON, JavaScript/TypeScript, HTML, maps and `.node` add-ons. The selected release's relevant-file classifier does not classify `.wasm` as JavaScript. | Inspect the whole public release, including lazy chunks and metadata. A JS-analysis gap says nothing about confidentiality of unexamined bytes. [Classifier](https://github.com/morluto/rea/blob/27dc42d10249f0410904a75c0997842eb03b931c/src/artifacts/javascript/JavaScriptArtifactFiles.ts#L609-L618) |
| Parsing | Babel parses inert text, with separate JS/JSX and TS grammar selection and recovered syntax errors. Bootstrap code is not executed by this workflow. | Minified syntax is still syntax. A parse failure must remain an unknown, never a successful secrecy test. [Parser](https://github.com/morluto/rea/blob/27dc42d10249f0410904a75c0997842eb03b931c/src/domain/javascript/javascriptSourceParser.ts#L84-L129), [analysis boundary](https://github.com/morluto/rea/blob/27dc42d10249f0410904a75c0997842eb03b931c/src/application/javascript/JavaScriptArtifactAnalysis.ts#L342-L435) |
| Module reconstruction | Static/dynamic imports, CommonJS references, workers, HTML scripts, Webpack/Rspack registrations and module factories contribute relationships. A string worker path can remain unresolved because document base/cwd is unknown. | Code splitting and module renaming change packaging, not the right to inspect downloaded code. Require complete inventory before drawing a before/after conclusion. [Workflow](https://github.com/morluto/rea/blob/27dc42d10249f0410904a75c0997842eb03b931c/docs/javascript-artifact-reconstruction.md#L230-L254) |
| Source maps | Real comment tokens identify modern/legacy and block `sourceMappingURL` declarations. Local map processing validates `sources`, `sourceRoot` and `sourcesContent`, retaining original identities and content digests in the graph. This is not a claim that every embedded original is recursively analyzed as executable source. | Excluding `.map` filenames alone is insufficient: declarations, inline maps, map-bearing JSON and deployed response headers also need review. Private error-tracking maps must remain outside public serving paths. [Directive parser](https://github.com/morluto/rea/blob/27dc42d10249f0410904a75c0997842eb03b931c/src/domain/javascript/javascriptStaticAnalysisCalls.ts#L911-L963), [map contents](https://github.com/morluto/rea/blob/27dc42d10249f0410904a75c0997842eb03b931c/src/application/javascript/JavaScriptArtifactAnalysis.ts#L592-L640) |
| Endpoints | Known unchanged `fetch`, `WebSocket`, `EventSource` and `sendBeacon` calls can yield network targets; stable bindings can resolve indirect targets. Method-like calls with unproven receiver identity remain candidates. | Encrypting or splitting an endpoint string is friction, not access control. Every server operation must remain safe when its exact URL and request shape are known. [Calls](https://github.com/morluto/rea/blob/27dc42d10249f0410904a75c0997842eb03b931c/src/domain/javascript/javascriptStaticAnalysisCalls.ts#L432-L616), [candidate limitations](https://github.com/morluto/rea/blob/27dc42d10249f0410904a75c0997842eb03b931c/src/application/javascript/JavaScriptArtifactGraphFindings.ts#L192-L274) |
| Framework/RPC clues | tRPC procedure property paths survive identifier minification. React/TanStack hook and factory spellings, selected tRPC client/link syntax, and named GraphQL operations are recognized. These observations do not recover every server resolver. | Send only operation names, fields and UI behavior that the client actually needs. Do not embed internal policy tables merely because a typed client generator can include them. [RPC implementation](https://github.com/morluto/rea/blob/27dc42d10249f0410904a75c0997842eb03b931c/src/domain/javascript/javascriptRpcEndpoints.ts#L24-L73), [documented scope](https://github.com/morluto/rea/blob/27dc42d10249f0410904a75c0997842eb03b931c/docs/javascript-artifact-reconstruction.md#L262-L301) |
| Semantic analysis | Lexical bindings, references, callable/return relationships, mutation uncertainty, resource acquisitions, configuration/default reads and request/response-consumer candidates feed a bounded semantic graph. This is a conservative static model, not complete program equivalence or exploit validation. | Local business formulas, thresholds and embedded defaults remain valuable reconstruction material. Move private decision authority and required private inputs to the server. [Semantic owner](https://github.com/morluto/rea/blob/27dc42d10249f0410904a75c0997842eb03b931c/src/domain/javascript/javascriptSemanticAnalysis.ts#L1-L103), [configuration/data effects](https://github.com/morluto/rea/blob/27dc42d10249f0410904a75c0997842eb03b931c/src/domain/javascript/javascriptSemanticDataEffects.ts) |
| Cross-version identity | A rename-resistant AST fingerprint includes node kinds, literals and operators. It is not byte identity and not a theorem that two implementations have identical behavior. | Identifier minification is an especially weak response to a tool that intentionally ignores some naming changes. Measure actual disclosure, not cosmetic bundle changes. [Fingerprint](https://github.com/morluto/rea/blob/27dc42d10249f0410904a75c0997842eb03b931c/src/domain/javascript/javascriptAstFingerprint.ts#L23-L32), [tokens](https://github.com/morluto/rea/blob/27dc42d10249f0410904a75c0997842eb03b931c/src/domain/javascript/javascriptAstFingerprint.ts#L77-L100) |
| Electron/native handoff | JS inspection can recover bridge APIs, IPC candidates, preload/window options and `.node` binding relationships. It does not execute or decompile that add-on. A separate native provider can add exact-subject evidence. | Moving browser code to a shipped desktop native add-on changes the analysis route; it does not make delivered logic secret. [Boundary scope](https://github.com/morluto/rea/blob/27dc42d10249f0410904a75c0997842eb03b931c/docs/javascript-artifact-reconstruction.md#L245-L254), [handoff](https://github.com/morluto/rea/blob/27dc42d10249f0410904a75c0997842eb03b931c/src/domain/javascript/javascriptNativeHandoff.ts#L11-L59) |

Every relationship retains an observation/inference distinction. Dynamic expressions, malformed or unavailable files, mutation uncertainty and resource limits remain unknown/partial. AST count, endpoint count, a matching digest and a completed process do not establish exploitability, authorized copying or complete reconstruction. [Upstream authority/unknowns](https://github.com/morluto/rea/blob/27dc42d10249f0410904a75c0997842eb03b931c/docs/javascript-artifact-reconstruction.md#L337-L351).

## Current source goes beyond the selected adapter

The reviewed current snapshot adds a shared route inventory covering literal router calls, nested objects, typed route trees, Next App Router paths and navigation targets. It uses lexical/source context and retains unresolved values. Its complete-application route coverage remains `unknown`; enumerated patterns are not proof of reachability or a denominator for all application routes. This makes hiding UI route names an unsuitable primary control. [Current route contract](https://github.com/morluto/rea/blob/7958e15892a59d313d90bd678273271593dc10b4/docs/javascript-route-inventory.md#L61-L143).

The separate browser workflow can fetch explicitly approved source maps without browser credentials, under response/time budgets. This capability is not enabled by the Hunter local-directory adapter. Likewise the upstream catalog's WASM/WABT, native provider, browser observation and runtime capture are distinct workflows with their own prerequisites and effects. No result from the JS-only adapter closes those coverage gaps. [Browser map implementation](https://github.com/morluto/rea/blob/7958e15892a59d313d90bd678273271593dc10b4/src/browser/WebSourceMapFetcher.ts#L40-L88), [current catalog and static/runtime distinction](https://github.com/morluto/rea/blob/7958e15892a59d313d90bd678273271593dc10b4/README.md).

### What OpenHunter exposes today

The owner's existing adapter calls only `analyze-javascript-application` with a fixed directory input, strict integrity policy, a 256 MiB analysis heap, 20-second per-source analysis timeout and a 45-second launcher deadline. Fixed semantic-node/unknown caps can produce partial output. It neither runs the target nor enables the broader MCP toolset.

Its output allowlist contains opaque artifact IDs/digests, counts, application/semantic coverage and bounded gap indicators. Raw source literals, endpoint strings, map contents, paths and graph properties do not enter Shield or an LLM. Upstream `findings` becomes `staticObservationCount`; it is not a validated security-finding count. Therefore:

1. Use this adapter to establish that a pinned real analyzer ran and to report honest coverage.
2. Use an independent public-artifact inventory and bounded release policy to test forbidden delivery.
3. Use actual server requests and state checks to test denied/allowed authority.
4. Never score fewer REA observations or an analyzer timeout as a defensive win.

The adapter's temporary process home and environment filtering are not an OS network sandbox or independent upstream attestation. See the maintained [Hunter contract](https://github.com/LumosLab-Innovation/OpenHunterAI/blob/main/docs/REA_INTEGRATION.md); its moving `main` link is explanatory, while REA mechanism citations above are immutable.

## Selected defensive design

### 1. Make the public release an explicit information contract

Assign every shipped asset to a public purpose. Keep private policy modules, server configuration, source maps, archives, debug fixtures, source trees, private package metadata and administrative operation catalogs out of the public root. The release gate receives a stable artifact snapshot, rejects links/traversal/unsupported carriers within its declared scope, applies resource bounds and emits only rule IDs, opaque asset IDs and digests. A deny pattern is a useful regression check, not a universal secret detector.

A practical improvement is an **exposure change review**: compare the approved public asset/operation manifest with the next release and require a named reason for newly delivered private-classified material. A signed manifest can bind the reviewed bytes; signing cannot turn exposed bytes into secrets. Test nested/lazy chunks, inline maps, unexpected metadata, compressed copies and stale files. If a carrier is not inspected, fail or disclose it explicitly rather than silently declaring the release clean.

The deployment check is separate: build-root scanning cannot establish CDN/object-storage ACLs, `SourceMap` headers, old hashes, alternate origin paths, prior service-worker caches or historical downloads. Already downloaded code cannot be remotely made unknown.

### 2. Keep proprietary decisions and security authority server-side

The browser submits domain inputs, not an authoritative price, permission flag, tenant ID or policy result. The server authenticates the principal; selects tenant/resource scope from trusted identity; checks entitlement, operation, schema and business preconditions; computes the decision with a private module; and returns only the fields required for that operation. A public endpoint is expected to be discoverable.

If a bounded capability is used, bind it to the exact principal, tenant, operation, input/quote identity, expiry and replay policy. Revalidate resource authority at use. A capability is explicit delegated authority, not an anti-debug trick. Changing an input, spending the same one-use grant twice, using a different principal or presenting it after expiry must fail without an unauthorized state change. Concurrent requests must exercise the same durable authority accounting.

The first lab can use a synthetic private pricing/policy function to compare outcomes for identical legitimate inputs. It must also reject unauthenticated, wrong-tenant and forged-client-result requests. This proves the selected boundary, not secrecy against a compromised server or exact-function extraction by an authorized black-box observer.

### 3. Bound the server as an extraction oracle

Server relocation removes delivered implementation bytes but leaves observable input/output behavior. Apply an operator-set budget to expensive/sensitive operations by durable principal and operation, rather than by a browser session or newly minted token alone. New sessions, fresh capabilities and parallel requests must not reset the same principal's quota. Use output minimization and access entitlement before rate limits. A normal user's required workflow must still complete inside the accepted allowance.

This may raise the cost of bulk sampling; it does not prove resistance to patient sampling, multiple authorized principals, Sybil identities, insiders, inferred formulas or low-complexity functions. The lab must disclose those counterexamples. Do not claim an arbitrary quota is statistically sufficient to prevent model extraction.

### 4. Give continuous Shield supervision a concrete role

Useful events are a changed public release digest, a new exposure rule hit, an unexpected private-class asset, a source-map availability regression, repeated cross-tenant denial, replayed grants or unusual per-principal query consumption. A resident AI may correlate accepted sanitized events, request bounded release/API observations and propose a release block, policy fix or incident investigation. Deterministic serving and authorization continue without the model.

Do not label a user or request as REA merely because it downloads JavaScript or knows an endpoint. No reliable REA-specific network signature was established in this review. Runtime blocking based on developer tools, user-agent names or a model's suspicion would produce an unmeasured service-impact boundary. The normal and no-AI branches should receive the same facts and permissions; compare correct release/authority decisions, analyst work, latency and service impact. Report AI value as unmeasured until a real provider and fair held-out comparison exist.

### 5. Respond honestly after exposure

Preserve the minimal evidence and reviewed artifact identity; identify affected versions and delivery paths; remove unintended public serving; purge owned caches where supported; fix authorization and rotate truly exposed credentials through the approved incident procedure. Credential revocation is not reversible. These steps limit future access; they cannot undo prior disclosure or copying. Do not deploy traps, malicious artifacts, resource bombs or retaliation against analyzers.

## Falsifiable first-lab matrix

| Experiment | Required evidence | Failure that defeats the claim |
|---|---|---|
| Leaky versus minimized release | Same legitimate function/output; fixed public-artifact manifests; independent planted private-material checks; real pinned REA summary for each, including all gaps | Private decision implementation/data still shipped, or reduced REA count caused by skipped/failed analysis |
| Source-map regression | Separate map, inline declaration, nested/lazy asset and unsupported-carrier negatives; result IDs only | Gate passes an in-scope known map/private carrier or silently skips unreadable bytes |
| Server authority | Allowed principal succeeds; unauthenticated/wrong-tenant/forged result cannot mutate protected state | Knowing endpoint or altering client parameters grants authority |
| Capability abuse | Wrong operation/input/principal, expiry, replay and concurrent use rejected under the chosen contract | Another request consumes the same grant or bypasses scope |
| Oracle control | Fresh-token/session and concurrent sampling share durable principal accounting; accepted legitimate throughput preserved | Each token/session resets the allowance, or acceptable users cannot complete their workflow |
| Analyzer outage | Missing runtime, timeout and partial parse remain explicit unknowns | The defender marks the artifact safe because REA failed |
| AI comparison | Same held-out cases, observations, permissions and budgets; actual model identity/latency/errors; raw prompts excluded | Labels leak into input, AI has privileged facts, test doubles count as real AI, or no-provider metrics become zero |

## Rejected primary defenses and residuals

- Identifier minification, junk branches, string encryption, packed bundles, anti-debugging, canvas/VM tricks and browser fingerprinting are not confidentiality or authorization boundaries. Client decryption code/key and clear execution state are available to an authorized client observer.
- WASM or native compilation can change reconstruction cost but retains a delivered implementation; broader REA tools and other analyzers exist. The selected JS adapter cannot measure that cost.
- Renamed/random endpoints and client route deletion do not replace server policy. A UI copy can reproduce public behavior even when every security control works.
- CSP/SRI, TLS and signed assets address other trust problems; none stops an authorized recipient from inspecting delivered content.
- Synthetic markers establish only the planted disclosure cases. Regex checks cannot prove universal absence of unknown secrets or proprietary concepts, and root access to the server defeats this lab's trust boundary.

The credible first deliverable is a release-exposure gate plus a server-authority/oracle lab with stated gaps. No general “REA-proof” product, perfect anti-copying system, production support or measured AI advantage follows from this research.
