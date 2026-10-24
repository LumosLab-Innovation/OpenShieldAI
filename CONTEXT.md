# OpenShieldAI context

Owner: HungBil / LumosLab-Innovation. Research snapshot: 2026-10-24 (Asia/Saigon).

## Mission

Help operators prevent, investigate, contain and recover from compromise as attackers increasingly use AI. The thesis is that defense must shorten the evidence-to-safe-action loop while maintaining availability, data integrity and human control. Market leadership and superior efficacy are ambitions to test, not established facts.

## Current state

The repository now includes a Python/SQLite synthetic runtime, bounded resident scheduling, a CLIProxyAPI/Codex transport module, exact fixed-lab approvals and isolated Caddy/Coraza/restic experiments. No real model endpoint is configured and no AI benefit or production support is established. See [runtime](docs/RUNTIME.md) and [measured evidence](docs/lab/RESULTS.md); research snapshots remain historical sources.

## Decisions

The current slice also includes a dependency-free Go access-decision correlator, a bounded Python caller, CLI/catalog integration and independent regression/performance evidence. [PM scenarios](docs/research/SECURITY_PORTFOLIO.md), [BA methods/hypotheses](docs/research/DEFENSE_METHODS_AND_HYPOTHESES.md) and [ADR 0003](docs/adr/0003-bounded-go-analysis-workers.md) guide further experiments. These generic patterns are candidates, not login-takeover findings; source authentication, live effects and AI value remain unverified. See [Go runtime](docs/GO_RUNTIME.md).

- Standalone defense first; OpenHunterAI is one later evidence producer.
- The four core questions now drive an explicit enforcement plane plus resident AI supervision; see ADR 0002 and the operating architecture.
- Evidence/provenance and deterministic policy surround AI reasoning.
- A small modular monolith precedes distributed services; external security tools remain separate systems.
- Original evidence stays with the operator; bounded sanitized evidence enters reasoning.
- Start with offline replay and read-only investigation; earn each action capability with benchmarks and isolated trials.
- Match OpenHunterAI's PolyForm Noncommercial 1.0.0 policy; dependencies keep their own terms.

See [ADR 0001](docs/adr/0001-evidence-first-defense.md), [ADR 0002](docs/adr/0002-continuous-ai-and-enforcement-planes.md), [core questions](docs/CORE_QUESTIONS.md), [operating architecture](docs/OPERATING_ARCHITECTURE.md), [roadmap](docs/ROADMAP.md) and [release gates](docs/PRODUCTION_READINESS.md).

## Open decisions

The first pilot organization, telemetry coverage, identity provider, supported host OS, data classification, deployment constraints and named incident commander are not selected. No production execution design is accepted without these inputs. The selected first lab uses a single Linux web service behind a dedicated Caddy/Coraza/CRS proxy with a private origin, synthetic data, independent effect probes and an isolated restic/application restore target. Its source-minimization, compatibility and efficacy gates remain open; it is not a support promise.
