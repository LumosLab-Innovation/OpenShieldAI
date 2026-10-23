# AI defense: evidence, limits, and adoption decisions

Research snapshot: **2026-10-24**. Status: **research and proposed design; no OpenShieldAI runtime or measured product results exist in this document**.

OpenShieldAI should help defenders prevent avoidable incidents, investigate evidence, make safer response decisions, and prove recovery. Its first justification must be useful defense on an organization's own evidence. OpenHunterAI interoperability is a later input path, not the foundation of the product.

## Evidence policy

- Prefer standards publishers, paper authors, and upstream repositories over marketing summaries.
- Record the precise paper revision or standard edition. A mutable website or default branch is a discovery reference, not an implementation pin.
- Separate a published result, our inference, a proposed feature, and an implemented capability.
- A research score does not transfer to OpenShieldAI, a newer model, a different organization, or a different telemetry source.
- Before importing code, datasets, rules, artifacts, or playbooks: pin the commit/release, record content hashes, examine per-item licenses, preserve notices, review privacy and supply-chain risks, and obtain a reproducible local evaluation.
- Benchmarks containing attacker traces or malware artifacts belong in isolated evaluation environments. A repository link is not authorization to download or execute samples.

## 1. Operational foundations

| Source and edition | Verified contribution | Design decision for OpenShieldAI |
| --- | --- | --- |
| [NIST SP 800-61 Rev. 3](https://doi.org/10.6028/NIST.SP.800-61r3), final 2025-04-03 | Connects incident response to CSF 2.0 risk management, including preparation, detection, response, recovery, and improvement. | Keep asset criticality, owners, readiness, incident decisions, and lessons learned together. A chat transcript alone is not incident management. |
| [NIST SP 800-184](https://csrc.nist.gov/pubs/sp/800/184/final), final 2016-12-22 | Recovery planning, realistic exercises, resource prioritization, and recovery metrics. | A recovery plan needs business dependencies, a clean restoration target, recovery objectives, and an actual restore exercise. |
| [CISA #StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide), updated guide published 2023-05; live page consulted 2026-10-24 | Preparation, isolation, volatile evidence preservation, protected backups, and restoration priorities. | Treat containment, forensic preservation, and restoration as coordinated decisions. Record the business and evidence cost of emergency isolation. The direct v3.1 PDF was access-blocked during this research; the HTML guide was readable. |
| [MITRE D3FEND](https://d3fend.mitre.org/) and [ontology changelog](https://d3fend.mitre.org/changelog/), ontology 1.6.0 dated 2026-08-31 | A knowledge graph of defensive countermeasures, artifacts, and their relationships. | Use it as a versioned countermeasure vocabulary. A mapping does not prove that a control is installed or effective. Do not confuse ontology 1.6.0 with UI release 0.26.1. |
| [NIST AI 600-1](https://doi.org/10.6028/NIST.AI.600-1), July 2024 | Describes generative AI risks including information security and the added attack surface of AI systems. | Defend the AI responder itself: untrusted inputs, bounded permissions, protected data, and operational monitoring are product requirements. |
| [OWASP Top 10 for Agentic Applications announcement](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/), 2026 edition announced December 2025 | Agent behavior hijacking, tool misuse, privilege abuse, and other agent-specific risks. | Include compromised agents and poisoned tool/context inputs in incident exercises; this taxonomy is not a certification or an effectiveness benchmark. |

These are methodological inputs. They do not make OpenShieldAI NIST-certified, compliant, or endorsed by the publishers.

## 2. What measured AI studies support

### Human-assisted incident summaries: a credible narrow starting point

[Kramer et al., *Integrating Large Language Models into Security Incident Response*, SOUPS 2025, pp. 133-148](https://www.usenix.org/conference/soups2025/presentation/kramer) studied 18 security analysts and 50 real incidents using Gemini 1.5 Flash. In Table 2's 211 comparisons, analysts identified missing details in 73 comparisons (35%) and factual inaccuracies in 89 (42%). These are comparison-level judgments, not percentages of distinct incidents. Table 7 reports human-plus-AI summaries preferred in 116 of 150 comparisons (77%), compared with 17 (11%) preferring the human-only version. See the [paper, Tables 2 and 7](https://www.usenix.org/system/files/soups2025-kramer.pdf).

**Adopt:** evidence-linked timeline drafts, structured handoffs, and human-reviewed incident reports. **Do not infer:** that attractive summaries are factually correct, or that the study establishes detection, containment, or restoration effectiveness. The population, model, prompt, and study conditions constrain generalization.

### Domain-specific queue prioritization can improve analyst throughput

[Bono, *Randomized Controlled Trials for Phishing Triage Agent*, arXiv:2511.13860v1, 2025-11-17](https://arxiv.org/abs/2511.13860v1) reports 167 professional analysts and curated, privacy-vetted email artifacts. Its [full text, Section 3 and Tables 1-2](https://arxiv.org/html/2511.13860v1) reports 6.53 times as many true positives per analyst minute and a 77% relative F1 improvement under the corpus-ground-truth condition. Both depend on its resolve-benign protocol, which removes agent-benign verdicts from human review; that corpus contained no agent false positives. Counterfactual conditions reduce the gain.

**Adopt as a hypothesis:** rank cases with transparent reasons and preserved queue access. Do not adopt automatic benign closure from this trial. **Limits:** vendor-authored, narrow task, selected corpus, conditional protocol-dependent effects. This is not an OpenShieldAI result or evidence of autonomous enterprise defense.

### Independent challenge is more promising than asking an agent to agree with itself

[Tsegai et al., *From Investigation Failures to Reliable SOC Agents*, arXiv:2610.10608v1, 2026-10-07](https://arxiv.org/abs/2610.10608v1) evaluates 1,247 alerts, including 225 attack-related alerts, replayed from one four-day enterprise scenario. Its AIDA design uses an explicit proposed decision, a challenger in a separate reasoning context, an append-only investigation ledger, and separate adjudication. The [full text, Section VI-A](https://arxiv.org/html/2610.10608v1) reports F1 0.958, false-negative rate 3.1%, and 18.4% of alerts escalated to analysts; comparison approaches missed at least 40.4% of attack alerts.

**Adopt as a design hypothesis:** independently challenge a concrete evidence-backed conclusion; request more evidence instead of interpreting an empty query as safety. **Limits:** a recent preprint; one selected scenario; attack labels concentrate in reconnaissance rules. The result is not a field deployment, cross-tenant result, or guarantee that multiple agents are better. Reproduce a baseline and measure the added cost before adopting the full multi-agent arrangement.

## 3. What current research warns against

### Unbounded threat hunting remains difficult

[Chona, Kozlov, and Kumar, *Cyber Defense Benchmark*, arXiv:2604.19533v3, 2026-04-23](https://arxiv.org/abs/2604.19533v3) builds campaigns from recorded Windows attack procedures and evaluates open-ended log investigation. **Source discrepancy found on 2026-10-24:** the arXiv abstract and [versioned PDF](https://arxiv.org/pdf/2604.19533v3) report different best-model performance and tested-model coverage. The PDF also has an arithmetically inconsistent description of its reported coverage. Exact performance figures are therefore excluded from the evidence adopted here until the authors' artifacts are reconciled.

**Implication:** retain this as a benchmark-discovery lead, not validated quantitative evidence. Independently test bounded investigation against known telemetry and ground truth. An LLM must not be the only detector or declare an organization safe; no abstract percentage is an organizational breach-detection probability.

### Investigating an already compromised host is harder than explaining an alert

[Wang et al., *SecRespond*, arXiv:2607.26791v1, 2026-07-29](https://arxiv.org/abs/2607.26791v1) evaluates 23 models across 10 compromised-cloud-host ranges, spanning five operating systems and 21 ATT&CK techniques. Agents receive a forensic disk snapshot and security-product alerts/checks. No model achieved complete detection and remediation on any range; agents struggled with silent intrusions and comprehensive verified remediation.

**Implication:** track persistence hypotheses, missing evidence, root-cause coverage, and independent recovery checks. A resolved alert must not automatically close an incident. **Limits:** the benchmark requires reports and remediation plans; its result does not prove safe execution of real production remediation. [Author-linked benchmark assets](https://github.com/Alibaba-NLP/qqr/tree/main/data/secrespond) were not readable through the research browser; their license, full artifact availability, and reproducibility remain unverified. Do not vendor them on this evidence alone.

### Cyber knowledge evaluations do not establish incident-response competence

[Deason et al., *CyberSOCEval*, arXiv:2509.20166v2, 2025-11-10](https://arxiv.org/abs/2509.20166v2) evaluates malware analysis and threat-intelligence reasoning. The authors report substantial remaining headroom and find that reasoning-model gains do not mirror those in coding and mathematics. [Upstream data](https://github.com/CrowdStrike/CyberSOCEval_data) explicitly have multiple source-specific licenses.

**Use:** a separate component evaluation after license review. **Do not use:** as an end-to-end safety score. The paper, harness, source reports, malware artifacts, and model weights do not necessarily share one license; "open source benchmark" is not sufficient permission to redistribute every artifact.

### The defender agent is also attackable

[Debenedetti et al., *AgentDojo*, NeurIPS 2024 Datasets and Benchmarks](https://papers.neurips.cc/paper_files/paper/2024/file/97091a5177d8dc64b1da8bf3e1f6fb54-Paper-Datasets_and_Benchmarks_Track.pdf) supplies 97 tasks and 629 security test cases for tool-using agents operating on untrusted data. The [author repository](https://github.com/ethz-spylab/agentdojo) has an [MIT license](https://github.com/ethz-spylab/agentdojo/blob/main/LICENSE).

**Adopt:** adversarial evaluation of malicious content in logs, evidence, retrieved documents, and tool results; measure both attack success and legitimate-task utility. **Limits:** these are simulated application tasks, not a turnkey SOC benchmark or proof that any particular injection detector protects incident response. An apparently correct final report can coexist with a harmful side effect; evaluate tool calls and data flows too.

## 4. Reuse and integration candidates

The following are **evaluated research candidates, not installed dependencies or implemented integrations**. These references were inspected on 2026-10-24. A moving branch is deliberately not represented as a deployment pin.

| Upstream | Verified role and license | Smallest useful adoption path | Boundary |
| --- | --- | --- | --- |
| [Timesketch](https://github.com/google/timesketch); [license](https://github.com/google/timesketch/blob/master/LICENSE) | Collaborative forensic timelines; Apache-2.0. | Study its evidence/timeline model; later import a deliberately supported export or offer an optional API adapter. | Preserve original event identities and source timestamps; normalization is a derived view, not replacement forensic evidence. |
| [Velociraptor](https://github.com/Velocidex/velociraptor); [license](https://github.com/Velocidex/velociraptor/blob/master/LICENSE) | Endpoint investigation/collection; AGPL-3.0 license text. | Initially accept operator-collected artifacts; evaluate a separate, explicitly authorized collection adapter later. | No automatic endpoint rollout or unrestricted VQL. Artifact Exchange/documentation have different licensing, noted in [contribution guidance](https://github.com/Velocidex/velociraptor/blob/master/CONTRIBUTING.md); do not assume all artifacts are AGPL. |
| [DFIR-IRIS](https://github.com/dfir-iris/iris-web) | Collaborative incident case management; upstream declares LGPL-3.0. | Reuse case-management lessons and consider import/export interoperability before duplicating a full SOC platform. | Production hardening and deployment requirements remain the operator's responsibility; API support must be tested against a pinned release. |
| [restic](https://github.com/restic/restic) and its [threat model](https://github.com/restic/restic/blob/master/doc/design.rst) | Encrypted backups; BSD-2-Clause. | Evaluate backup manifest/check output and human-run isolated restore drills. | Encryption is not immutability. Compromised clients can create bogus snapshots or leak repository keys; deletion privileges and retention jobs need separate trust. No autonomous prune/forget. |
| [No More Ransom](https://www.nomoreransom.org/en/decryptiontools.html) | Authoritative discovery portal for variant-specific recovery tools; not a single uniformly licensed repository. | Link an analyst to a verified applicable tool and its publisher's instructions. | No universal decryption promise, automatic downloads, or execution on originals. Each tool has separate terms and applicability. |
| [AgentDojo](https://github.com/ethz-spylab/agentdojo) | MIT-licensed adversarial agent evaluation harness. | Evaluate a small synthetic Shield-specific tool/data boundary suite; use upstream suites as a separate track. | Keep production credentials and customer evidence out of evaluation artifacts. |

## 5. Recommended staged capability path

Use the canonical S0-S5 stages in the [PRD](../PRD.md), [roadmap](../ROADMAP.md), and [acceptance criteria](../ACCEPTANCE_CRITERIA.md). These are proposed delivery stages with independent gates, not claims that capabilities exist. Research cannot relax the [security guardrails](../SECURITY_GUARDRAILS.md).

| Stage | Useful outcome | Explicit limit | Evidence required to advance |
| --- | --- | --- | --- |
| S0: Research foundation — current | Source-backed product/design decisions, strict rules, playbooks, and evaluation design. | No runtime or measured efficacy. | Reviewable docs, explicit uncertainties, provenance and license checks. |
| S1: Offline investigation | Authorized local intake, source-linked timeline, missing-evidence list, bounded hypotheses, response proposal, restore-readiness checklist. | Only accepted synthetic/sanitized replay inputs; no live access, production mutations, or endpoint rollout. | Deterministic baseline and parser/sanitizer tests; held-out cases from the accepted first-lab scope; every material claim supported or marked hypothesis. |
| S2: Read-only pilot | One selected telemetry source, narrow typed queries, correlation, independent challenge, clear escalation. | Enrolled assets and explicit read grants; shadow decisions; no live mutation or unbounded hunting. | Real pinned adapter, operator review, source-quality controls, measured error and escalation burden. |
| S3: Approved response and isolated recovery drill | One narrow reversible action through an existing control plane; execution receipts and separate observations; isolated restore validation. | Exact per-action human approval for every mutation; production restore and high-impact procedures stay human-run with required two-person review. | Lab fault-injection, cancellation/reconciliation, compensation and service checks; actual isolated restore and operator acceptance. |
| S4: Independently proven expansion | Additional incident families, environments, prevention checks, and adapters justified by pilot need. | Every mutation still requires per-action approval; a prior family or adapter pass grants no new authority. | Repeat evidence, efficacy, safety and environment-specific acceptance per capability. |
| S5: Optional Hunter collaboration | Import verified finding evidence and compare remediation with a manually requested narrow retest. | Hunter reports remain untrusted; no inherited response authority or automatic scan authorization. | Versioned interchange, sanitizer/enrollment/provenance checks, replayed examples, and separate integration acceptance. |

S1 must still provide value without an LLM: deterministic evidence indexing, case ownership, a structured response plan, and verification checklists. AI should improve an already useful workflow rather than become its only working component.

**Research-only autonomy question:** standing authorization or automatic mutation is not an allowed stage or capability under the current rules. Exploring it does not enable it. Any future proposal requires a new ADR, an explicitly approved guardrails change, and a new acceptance/evaluation envelope before implementation. Until then, every mutation requires exact per-action human approval, and the high-impact human-run/two-person restrictions remain in force.

## 6. Evaluation requirements derived from the evidence

Use the repository's acceptance and evaluation specifications as the authority for release gates. The research supports the following measurement design:

- Compare deterministic playbooks/rules, one AI investigator, and investigator plus independent challenger on the same held-out cases. Record the difference in safety, recall, analyst effort, latency, and cost.
- Split by organization/campaign/scenario and time, not random rows from a shared attack sequence. Hide labels and post-incident narratives from investigators.
- Report precision, attack recall, false-negative rate, false closure rate, escalation rate, evidence completeness, unsupported-claim rate, and analyst correction effort together. Accuracy alone can reward dismissing almost every alert.
- Measure missing/late logs, empty queries, parser failures, clock skew, contradictory evidence, poisoned tool output, false indicators, budget exhaustion, and connector outages. Missing telemetry must produce a gap or escalation.
- Test scope/tenant boundaries, approval replay, secret leakage, prompt injection, action idempotency, rollback failure, and evidence preservation. Zero observed safety violations on a finite fixture suite is a release check, not proof of zero production risk.
- For recovery, measure verified restore success, application/data integrity, observed recovery time and data-loss window against owner-defined RTO/RPO, reinfection indicators, and operator acceptance. A successful backup job alone is insufficient.
- Publish sample counts, uncertainty intervals where appropriate, model/provider configuration, harness revision, telemetry coverage, repeat runs, budgets, and all material failure cases. Do not substitute an LLM grader for blinded expert review of critical outcomes.

## 7. Claims to reject

- "Prevents every AI attack", "stops hackers autonomously", or "guarantees recovery".
- "No breach" when logs are missing, collection failed, or only an alert bundle was reviewed.
- "Eradicated" because one process was killed, one file deleted, or one alert closed.
- "Safe to restore" because a backup archive passes a hash check, without validating the restore point, application behavior, identity trust, and dependencies.
- "AI-powered" as the success metric; the meaningful result is lower incident harm or lower analyst effort without unacceptable missed attacks and operational damage.
- "NIST/MITRE compliant" merely because techniques or checklist steps were mapped.

## Research limitations

This is a source-backed initial architecture research pass, not a systematic literature review, legal license opinion, upstream code audit, or empirical replication. No upstream code or malware samples were executed. No production incidents were investigated. Recent preprints and vendor trials are labeled because their results need independent, environment-specific validation.
