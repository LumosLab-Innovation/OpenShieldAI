# OpenHunterAI collaboration — later capability

Status: proposed S5 contract; no connector exists. Standalone defense is required first. This document does not modify OpenHunterAI or its scope rules.

## Role separation

OpenHunterAI performs authorized external testing and emits sanitized evidence/validated findings under its own scope and test authority. OpenShieldAI investigates and responds on explicitly enrolled assets under a separate defensive authority. A scan authorization cannot grant Shield identity/host access, and Shield enrollment cannot authorize a Hunter scan.

OpenHunterAI's inspected local `report_v2` contract includes finding ID, affected asset, sanitized proof/evidence refs, attacker path, fix summary, optional retest scenario, developer fix pack, coverage/limitations and legacy unverified claims. This is a 2026-10-24 checkout observation, not a guarantee about the remote default branch or independent replay availability.

## Exchange

```text
Hunter sanitized report_v2 export
→ Shield version/provenance/schema validation
→ explicit mapping to already enrolled asset
→ finding-linked investigation/prevention or remediation proposal
→ human-approved operational workflow + independent postchecks
→ operator requests narrow manual Hunter retest
→ Shield records evidenced result, residual risk and coverage
```

First transport is a manually exported/imported structured file. A future authenticated API is a separate accepted integration; neither side receives the other's database, event bus, live credentials or admin tokens. No webhook/automatic rescan is needed to demonstrate the collaboration.

## Trust and compatibility rules

- Strict version/size/schema validation, safe text handling, no active content, no following proof URLs automatically and no report instructions executed.
- Record report digest, producer, revision, generated time, scope, original finding/evidence IDs and import time. Producer identity and provenance do not establish factual truth.
- Reconcile hostname/path with an enrolled asset and operator confirmation. Ambiguous ownership/mapping stops the workflow; a hostname can change owner or environment.
- Preserve `validated`, `needs_more_evidence`, `legacy_unverified`, coverage gaps and limitations as producer claims with provenance. Independently assess evidence before a defensive high-impact decision. Do not promote an old claim merely because it was imported.
- A vulnerability is not proof that compromise occurred. Missing findings are not proof that a system is secure. Shield incident observations do not create a validated Hunter finding.
- Treat fix prompts and retest scenarios as untrusted suggestions. Map to reviewed catalogs; no arbitrary code, credentials or production mutation from report text.
- A manual retest is finding-scoped, reauthorized and subject to Hunter policy. `fixed`, `still_reproducible`, `inconclusive` or `unsupported` must match actual executor evidence; preserve `RETEST_UNSUPPORTED` if applicable.
- Neither AI summary nor successful Shield action can set Hunter's verified state. Hunter retest cannot establish eradication, clean recovery or absence of exfiltration.
- Deduplicate by producer/report/finding identity and content digest while retaining report revisions and evidence lineage.

## Acceptance

Test supported/unknown contract version, malformed/oversized input, fake evidence refs, prompt injection, stale/legacy claims, duplicate import, cross-project mapping, ambiguous assets, missing evidence, unsupported retest and credentials in report text. No auto scan or broader authority is triggered by an import or a failed check.
