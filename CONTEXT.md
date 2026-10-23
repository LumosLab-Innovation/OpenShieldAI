# OpenShieldAI context

Owner: HungBil / LumosLab-Innovation. Research snapshot: 2026-10-24 (Asia/Saigon).

## Mission

Help operators prevent, investigate, contain and recover from compromise as attackers increasingly use AI. The thesis is that defense must shorten the evidence-to-safe-action loop while maintaining availability, data integrity and human control. Market leadership and superior efficacy are ambitions to test, not established facts.

## Current state

This is a research and specification foundation. There is no deployable security product, live connector, model integration, recovery executor or published efficacy measurement. Documents distinguish selected design, proposed integration, experimental research and deferred work.

## Decisions

- Standalone defense first; OpenHunterAI is one later evidence producer.
- Evidence/provenance and deterministic policy surround AI reasoning.
- A small modular monolith precedes distributed services; external security tools remain separate systems.
- Original evidence stays with the operator; bounded sanitized evidence enters reasoning.
- Start with offline replay and read-only investigation; earn each action capability with benchmarks and isolated trials.
- Match OpenHunterAI's PolyForm Noncommercial 1.0.0 policy; dependencies keep their own terms.

See [ADR 0001](docs/adr/0001-evidence-first-defense.md), [roadmap](docs/ROADMAP.md), [research](docs/UPSTREAM_SOURCES.md) and [release gates](docs/PRODUCTION_READINESS.md).

## Open decisions

The first pilot organization, telemetry coverage, identity provider, supported host OS, data classification, deployment constraints and named incident commander are not selected. No production execution design is accepted without these inputs. The proposed first lab uses a single Linux web service, synthetic access/auth/file-integrity events and an isolated backup/restore target; it is not a support promise.
