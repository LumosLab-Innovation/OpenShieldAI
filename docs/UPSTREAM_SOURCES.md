# Research sources and adoption index

Review snapshot: 2026-10-24. Evidence favors bounded, measurable assistance and independently verified effects; no source establishes OpenShieldAI efficacy.

## Repository review

- [15-core-upstream evaluation](research/UPSTREAM_EVALUATION.md): roles, inputs/outputs, licenses, integration boundaries, validation and rejected shortcuts.
- [Machine-readable registry](research/upstreams.json): immutable reviewed commits, license evidence, observed activity, adoption decision, required tests and `not_implemented` status. These research commits are not production release recommendations.
- [AI research and additional IR/recovery references](research/AI_DEFENSE_EVIDENCE.md): measured studies, preprint/benchmark limitations, standards and additional candidates such as AgentDojo, Timesketch and DFIR-IRIS. These supplementary references are not approved runtime dependencies; add a pinned registry entry before adoption.
- [Skeptical review](research/SKEPTICAL_REVIEW.md): admission criteria, feature decisions and concrete S0 review disposition.

## Standards and methodology

| Primary source | Design use | Limit |
|---|---|---|
| [NIST SP 800-61 Rev. 3, April 2025](https://csrc.nist.gov/pubs/sp/800/61/r3/final) | Integrate preparation, detection, response and recovery with risk management | A reference, not certification or our exact workflow |
| [CISA StopRansomware guide](https://www.cisa.gov/stopransomware/ransomware-guide) | Prepared backups, incident coordination, evidence trade-offs and clean recovery | Organization-specific execution and authority still required |
| [MITRE ATT&CK STIX](https://github.com/mitre-attack/attack-stix-data) | Threat/technique vocabulary and scenario traceability | Mapping is not measured detection coverage |
| [MITRE D3FEND resources](https://d3fend.mitre.org/resources/) | Defensive technique/artifact relationships | A listed technique is not a deployed or effective control |
| [OWASP prompt injection guidance](https://genai.owasp.org/glossary/prompt-injection/) | Untrusted-content and agent-tool trust boundary | A classifier/prompt cannot replace runtime authorization |

Research claims must cite a direct primary source and exact paper version when available. Distinguish abstract from full-text results; record inconsistencies, benchmark scope, sample size, ground-truth construction and external-validity limits. Do not reconcile conflicting numbers by guessing. Do not cite source popularity or a GitHub star count as efficacy evidence.

## Adoption ledger rules

`reference`, `evaluate`, `integrate_candidate`, and `reject_as_core` are research decisions. None means integrated, supported, secure, legally compatible or deployed. Selected design is recorded in the PRD/ADR; approved activation needs implementation, pinned artifact, tests and acceptance evidence. Follow the [manual enrichment policy](MANUAL_UPSTREAM_ENRICHMENT_POLICY.md).

No upstream code or rule content was copied into this foundation; the root SVG is an original repository asset. Upstream names identify research subjects, not endorsement or affiliation.
