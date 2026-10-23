# Contributing

Start with [AGENTS.md](AGENTS.md), the [PRD](docs/PRD.md) and [security guardrails](docs/SECURITY_GUARDRAILS.md). The repository is a research/specification foundation; please do not submit a broad autonomous SOC implementation or unrequested integration.

## Propose useful work

Open a sanitized feature/research proposal describing the concrete defensive failure, user and asset, available telemetry/permissions, baseline, measurable outcome, action risks, proposed stage and required evidence. Include primary sources and exact upstream refs/licenses. An idea is not accepted merely because a paper or repository exists.

Use GitHub Issues for planned work. Default triage vocabulary: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. Labels describe readiness, not permission to operate a real system. Maintainers decide scope and priority.

## Submit a focused patch

- Follow existing structure and update affected callers, contracts, fixtures and behavior documents.
- Preserve prior content unless the task explicitly changes it; no incidental rewrites or mass formatting.
- Separate facts, hypotheses, planned behavior and validated results. Never add production badges or demo results implying efficacy.
- Add relevant positive/negative/failure tests for nontrivial logic; prioritize security boundaries, approvals, sanitization and recovery safety.
- Use synthetic, clearly labeled fixtures only. Do not upload customer evidence, malware, secrets or personal data.
- Respect [manual upstream enrichment](docs/MANUAL_UPSTREAM_ENRICHMENT_POLICY.md) and [licensing](LICENSING.md). No dependency/adapter activation without accepted scope and tests.

## Local checks

Python 3.11+; no third-party package is required for the current documentation foundation.

```text
python scripts/check_docs.py
python -m unittest discover -s scripts -p "test_*.py"
git diff --check
```

These are documentation/provenance checks, not a security or incident-response benchmark. Future runtime changes must additionally run relevant implementation tests and stage acceptance scenarios. State what was tested, what remains unverified and which capability stage the patch reaches.

Report potential vulnerabilities privately through [SECURITY.md](SECURITY.md). Participate respectfully under the [code of conduct](CODE_OF_CONDUCT.md).
