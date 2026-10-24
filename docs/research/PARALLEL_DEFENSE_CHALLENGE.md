# Independent challenge: practical controls before breadth claims

Review date: **2026-10-24**. This review addresses the next selected PM/BA slices: downstream AI-tool mediation (A1/A2/A3), deployed release delivery (W2/C2) and durable server authority (I2/W3/W2). It does not establish coverage of the full portfolio. The [PM portfolio](SECURITY_PORTFOLIO.md), [BA hypotheses](DEFENSE_METHODS_AND_HYPOTHESES.md) and [mandatory guardrails](../SECURITY_GUARDRAILS.md) retain their individual acceptance gates.

## Required falsifiers

| Mechanism | A result that blocks its narrow claim |
|---|---|
| Exact downstream tool authority | A direct call, forged grant, cross-case operation, recipient/data-class substitution or concurrent replay creates a forbidden effect. A poisoned-text detector is not the authority boundary. |
| Legitimate-tool preservation | Approved ordinary work fails under the supported policy or only a deny-everything configuration passes the hostile cases. |
| Durable operation grants | Restart, a second process, another session for the same principal or a policy reload resets quota or makes a consumed/revoked grant valid. |
| Time and state failure | Clock rollback extends authority; unavailable/corrupt state silently switches to an empty store or in-memory allowance. |
| Exact deployed-byte checks | A mismatching decoded representation, HTTP source-map header, catch-all response for a retired path, redirect or unbounded response receives a complete pass. |
| Honest deployed coverage | A supplied reference manifest is called proof that no other origin/CDN/old-release path exists. Only the explicitly requested paths and representations are observed. |

The positive controls must independently observe effects with enforcement absent and preserve the same allowed outputs with enforcement present. An alert or a broker denial alone is not the outcome. Public client/API structure remains observable; neither low AST counts nor inability to parse a bundle demonstrates effective defense.

## Interpretation constraints

The useful anti-REA goals are to deliver less unnecessary implementation material, detect unexpected delivery and require server authority for consequential operations even when the client is reconstructed. These mechanisms cannot recall prior downloads, remove third-party caches, stop an authorized recipient from redistributing results or make an arbitrary function unlearnable through allowed output queries. The existing synthetic linear-formula inference counterexample remains relevant.

The selected experiments use owned synthetic data and loopback HTTP. SQLite transactional persistence can close a single-host restart/process race without establishing production identity, multi-host distributed accounting, a tamper-resistant clock or compromise resistance against the host administrator. Restoring a sufficiently old valid database can roll back usage and the clock watermark together; no external anti-rollback anchor exists. Deletion/corruption while running fails closed, while a new absent state path intentionally bootstraps a fresh lab. Ephemeral grants in the separate Go tool lab must not be described as durable production approval.

## Concrete review findings

1. **Missing delivery positive control:** the first tool trial never exercised a valid receipt, so rejecting every receipt could pass its recipient assertions. The implementation now performs the original approved receipt after an attempted recipient change, observes one message in the correct fixture inbox and rejects replay. A mark also changes a real fixture record that later reads observe as reviewed. A2 remains fixed recipient/data-class mediation, not general DLP or sensitive-content classification.
2. **Unverified main entry alias:** checking `/index.html` alone would miss a different response at `/`. The delivery auditor now checks both when the reference contains `index.html`; an independent mismatching-root test rejects unreviewed root bytes.
3. **Retired compressed export bypass:** an independent server returned `404` for the retired map with identity encoding and `200` containing the old map for gzip. The initial auditor returned a complete pass because it probed only the identity representation. The auditor now probes both identity and gzip for every retired path; the retained independent regression detects the compressed exposure and returns blocked.

## Executed independent checks

The reviewer-owned [test module](../../tests/test_parallel_defense_adversarial.py) completed **21/21 Python tests**, including the separately compiled three-test Go challenge below. It exercises actual loopback HTTP and the actual authorization code. Ten durable-authority tests passed: consumed grants and session revocation survive restart; separate processes cannot spend one grant twice or exceed the last shared principal budget using different grants; new sessions do not reset quota; wrong bindings preserve the valid grant; credential values are absent from persisted bytes; backward clock/configuration drift and missing/corrupt state fail closed.

The Go test copies the exact current package sources into an isolated temporary module and adds three independently authored HTTP tests. They cover all three allowed operations, scope/recipient/data-class substitution, preserved legitimate completion, replay, concurrent receipt consumption, direct-call negative control, escaped duplicate fields, numeric type ambiguity and duplicate authority headers. This adds no exported test API or repository dependency.

Ten delivery tests passed: valid identity/gzip positive controls, stale compressed bytes, mismatching root alias, concatenated/truncated/tail gzip, duplicate mixed-case source-map headers, retired-path application fallback, compressed retired paths, no redirect to another receiver, explicit unsupported content encoding and authorization/scope rejection before HTTP. The retired compressed-path regression above is retained as a required falsifier. A `complete` result covers the declared paths/representations only; it is not URL discovery or CDN/cache verification.

No unresolved release blocker was found for these narrow experimental claims after the fixes. This is a source review and selected falsifier pass, not an exhaustive audit or proof that the controls cannot be bypassed in another deployment.

## Final integration checks

The additional [delivery/CLI suite](../../tests/test_delivery.py) passed **7/7 tests**. It runs all 13 owned real-HTTP delivery modes through the actual `delivery-lab` CLI, verifies that forbidden output destinations are rejected before HTTP or remote-reference resolution, preserves reference bytes when an external report is a hardlink, checks failure exit status for observed drift and confirms omitted-detail counts. A continuously trickled real HTTP response was interrupted by the configured half-second total deadline; fresh bytes arriving before the socket timeout did not extend the job indefinitely.

The first combined verifier checked forbidden tool effects but omitted explicit aggregate positive and negative controls. Its gates now require the planted unsafe-control mutation/delivery, wrong-recipient control delivery, preserved allowed reads/mark/receipt and exactly one concurrent acceptance. These checks use ordinary conditional failures, so Python optimization cannot remove them. The [aggregate-gate suite](../../scripts/test_check_parallel_defense.py) passed **4/4 tests** in both normal and `python -O` execution. Labeled process/trial test doubles show that deny-everything/stale-control reports and malformed process results cannot start the Python trials; a valid typed report reaches the mocked trials, and an individual failure cannot become aggregate success. Those four tests validate aggregation logic only; they are not additional real-HTTP or attack-efficacy results.

No real model/provider run, production source authentication, external cloud/CDN deployment, host containment or production mutation is part of this review. Published regression examples are not fresh held-out efficacy data. Passing these selected invariants closes neither the full PM/BA portfolio nor production acceptance.
