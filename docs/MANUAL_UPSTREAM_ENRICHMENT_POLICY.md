# Manual upstream enrichment policy

Research is part of the product; activation is a separate controlled change. An owner-requested research pass may update references and proposals. It does not authorize installing tools, running upstream code or granting new capabilities.

## Allowed process

1. Identify a real defensive gap, user, observable input, baseline and desired measurable outcome.
2. Inspect primary source, exact commit/release, artifact/dependency licenses, notices, maintenance and security model. Record unknowns without guessing.
3. Classify as reference, evaluate, integrate candidate, or reject as core; record alternatives and the smallest useful boundary.
4. Add provenance and a normal reviewable patch. For imported code/rules, include source path, digest, author, license/notice, modifications and required tests.
5. Challenge usefulness, safety and feasibility against [evaluation](EVALUATION.md) and [skeptical rubric](research/SKEPTICAL_REVIEW.md).
6. Implement only within an accepted stage and explicit task scope. A new adapter/capability needs owner direction, compatibility tests and acceptance evidence before activation.

## Never automatic

No cron, scheduled sync, bot-generated activation, floating `latest` rule download, runtime repository fetch, submodule, full-repo vendoring, auto-installed plugin or execution of a paper's scripts during research. CI may validate local provenance; it must not pull and activate upstream content.

Manual research can inspect upstream remotely. Runtime security telemetry is a different authorized data flow and must not be confused with upstream code/rule updates.

## Promotion record

| Field | Requirement |
|---|---|
| Need / decision | Capability, user, baseline and stage |
| Source | Canonical repository, immutable ref, source item path and retrieval date |
| Rights | Exact artifact/content/dependency license and preserved author/notices |
| Transformation | Content digest, modifications, normalized mapping and adapter version |
| Safety | Input authority, scope, credentials, egress, resource limits and failure behavior |
| Evidence | Positive/negative/abuse tests, utility result, observer/verification and limitations |
| Operations | Owner, supported versions, update/rollback/reconciliation and retirement path |

Keep third-party licensing distinct from the root PolyForm license. AGPL/GPL/DRL and service terms need artifact-specific review; calling a project source-available or open source does not settle compatibility. Do not include malware samples, real private incident material, secrets or personal data in imported fixtures.

Scope, authority or security-rule changes require the appropriate PRD/ADR/guardrail update; an enrichment entry cannot override them. Defer an integration with unresolved permission, license or safety prerequisites and state exactly what evidence is missing.
