# ADR 0002 — continuous AI supervision and explicit enforcement points

Date: 2026-10-24. Status: selected specification direction, runtime unimplemented. This refines ADR 0001 following the owner's requirement that the architecture explain actual prevention, ongoing response, post-incident recovery and AI's continuous role.

## Problem

The original design had strong guardrails but no selected traffic control point, concrete first actuator, temporal AI lifecycle or measurable attack-to-effect traces. Describing AI as optional also allowed the normal product to become a report workspace with an occasional model call. Neither establishes the intended defense vision.

## Decision

- Separate immediate execution of already approved defensive controls from an event-driven AI supervisory loop. Do not put an LLM/network round trip in the request-enforcement path.
- Use continuous AI investigation/planning as the normal operating mode, with durable entity/evidence state, event/timer triggers, bounded observations, budgets, explicit backlog and degraded health. Idle means waiting for changed evidence, not repeated identical inference.
- Keep a deterministic baseline for ablation and degraded operation; its availability does not make degraded operation equivalent to full AI supervision.
- Select Caddy + Coraza/CRS ingress, source-minimized telemetry and an isolated restic/application recovery drill as the first lab design. Verify the connector's actual dependency tuple and log behavior before building/pinning a supported artifact.
- Select one S3 ingress-maintenance actuator with exact action approval, protected administration, single-writer/state conflict checks and independent effect/management/availability verification. Do not infer host, identity or egress containment from ingress control.
- Preserve S1 offline/S2 read-only authority, every mutation's exact human approval and high-impact human-run restrictions. Existing deployed static policy may enforce requests without new per-request approvals; AI cannot change that policy without a new approved action.
- Require the T1–T6 traces in [operating architecture](../OPERATING_ARCHITECTURE.md). Never claim production efficacy from the existence of this ADR.

## Alternatives and consequences

LLM-per-request blocking creates latency, cost and outage coupling and is not selected. A chatbot consuming arbitrary logs without an actuator is not sufficient. A general root agent would add authority beyond the selected need. More complex stream-learning models remain measured candidates, not compulsory dependencies.

Human approval can delay response while harm continues; measure this delay and rely on preexisting approved fast controls for immediate covered threats. Unknown host/identity/egress paths remain exposed until a relevant actuator and evidence exist. An untested restore or unknown-clean snapshot remains unverified recovery. Architecture and public copy must say so.
