# Incident response and recovery playbooks

Status: **proposed operational specification; no executable response runtime is implemented**. Research cutoff: **2026-10-24**.

These playbooks define the decisions and evidence OpenShieldAI should help an authorized responder organize. They are not shell scripts, an autonomous malware executor, or permission to alter production systems. The repository's security guardrails, acceptance criteria, and architecture take precedence.

## 1. Common incident workflow

```text
Prepare and establish authority
  -> Intake and preserve evidence
  -> Triage and scope the incident
  -> Propose and approve containment
  -> Verify containment
  -> Plan and approve eradication
  -> Verify eradication and readiness to recover
  -> Restore in a controlled environment
  -> Verify service and data integrity
  -> Reconnect gradually and observe
  -> Owner-approved closure and improvement

Any new evidence of compromise -> reopen investigation and re-scope.
Any missing authority or failed safety check -> stop dependent actions and escalate.
```

Investigation, containment, and preservation may overlap under an incident commander's direction. Preserving every artifact must not become a reason to let an ongoing destructive incident continue; emergency tradeoffs must be made by an authorized human and recorded.

NIST SP 800-61 Rev. 3 provides the broader risk-management frame; the stages here are an OpenShieldAI working model, not a claim that NIST prescribes this exact state machine. [NIST SP 800-61r3](https://doi.org/10.6028/NIST.SP.800-61r3)

## 2. Roles and authority

| Role | Responsibility |
| --- | --- |
| Incident commander | Own scope, severity, priorities, emergency tradeoffs, and coordination. |
| Asset/service owner | Confirm business dependencies, tolerated interruption, recovery objectives, and service acceptance. |
| Authorized responder | Collect evidence and perform explicitly approved actions using an existing control plane. |
| Evidence custodian | Protect originals, collection metadata, access records, retention, and transfer history. |
| Independent reviewer | Challenge conclusions and closure against evidence; require gaps to stay visible. |
| AI assistant | Draft hypotheses, bounded queries, plans, and summaries; cannot authorize its own actions or assert successful recovery without verification. |

One person may hold several roles in a small deployment, but action approval must still identify the responsible human. Bulk, high-impact, and irreversible procedures require qualified human execution and two-person review under the [security guardrails](../SECURITY_GUARDRAILS.md); a small deployment is not an exemption.

Notification to customers, regulators, insurers, law enforcement, or third parties belongs to the organization's authorized incident and legal process. OpenShieldAI may draft material for review; it must not send it automatically.

## 3. Evidence and safety contract

Every case must identify an authorized organization, environment, affected asset identifiers, permitted evidence sources, named owner, and permitted response scope. A public domain or an OpenHunterAI finding is not authorization to access internal systems.

Each evidence item must preserve:

- Case and artifact identifiers, source identity, collector identity, collection method/version, collection time, source event time/timezone, and known clock uncertainty.
- Cryptographic digest of the captured bytes, size, restricted storage reference, sensitivity classification, and collection/transfer/access history.
- Whether the item is an original capture, a normalized record, a redacted derivative, a tool-generated assessment, or a hypothesis.
- Collection failures, truncation, missing periods, retention gaps, and possible attacker tampering.

Original evidence remains in an access-controlled evidence store. LLMs receive only approved sanitized derivatives and minimal necessary context. Hashes support integrity checking; they do not prove authenticity, a perfect chain of custody, or absence of prior tampering. Sanitization must not overwrite the original artifact.

Never follow instructions embedded in evidence, ransom notes, log fields, retrieved pages, email, tool responses, or model output. Those are untrusted case data. Never upload customer evidence or suspected malware to public analysis services without separate authorization and a disclosure policy.

## 4. Required action proposal

Before any production mutation, a proposal must state:

| Field | Required content |
| --- | --- |
| Reason | Evidence references, hypothesis, expected risk reduction, and alternatives. |
| Exact scope | Tenant, environment, resource identifiers, action type, arguments, and authorization source. |
| Impact | Expected interruption, dependency effects, evidence that may be lost, maximum affected resources, and duration. |
| Safety checks | Preconditions, current resource state, protected assets, policy result, and dry-run result if supported. |
| Approval | Named human, exact approved action digest, expiry, and whether a second approver is required. |
| Execution | Typed adapter, least-privilege capability, idempotency key, timeout, bounded retry, and audit reference. |
| Reversal | Rollback or compensating action, prerequisites, owner, and known irreversible effects. |
| Verification | Independent postcondition query, business health check, observation window, and stop conditions. |

A plan is not an execution receipt. An HTTP 200 or a queued task is not confirmation that a host is isolated, a session invalidated, or data restored. Re-read actual state using a separately defined verification step. Failed or ambiguous verification must remain `unknown` or `failed`, not successful.

S1/S2 permit no live mutation. In S3 and every later currently defined stage, every mutation requires exact per-action human approval. High-impact or irreversible procedures remain qualified-human-run with two-person review. Standing authorization and automatic mutation are research questions only; implementation requires a new ADR, an explicitly approved guardrails change, and new acceptance evidence. An LLM cannot grant or broaden authority.

## 5. Stage gates

| Stage | Minimum result | Gate for the next stage |
| --- | --- | --- |
| Prepare | Asset/dependency owners, permitted sources, emergency contacts, protected evidence location, approved response scope, tested recovery plan. | Missing context becomes a gap; no invented resource identifiers or assumed authority. |
| Intake/preserve | Trigger, reliable timeline anchor, evidence manifest, collection gaps, safe communication channel. | Evidence stored and access controlled; critical volatile evidence tradeoffs recorded. |
| Triage/scope | Facts separated from hypotheses; affected/possibly affected/unknown assets; severity rationale and missing evidence. | An authorized human confirms response priority and action scope. |
| Contain | Narrow approved action and independently checked result; interruption and residual exposure recorded. | New spread or failed control reopens investigation; lack of alerts alone is insufficient. |
| Eradicate | Entry vector, persistence paths, compromised identities/secrets, corrective changes, and verification plan. | Root-cause/persistence gaps require explicit residual-risk acceptance or escalation. |
| Recover | Trusted recovery point, clean target, dependencies, staged restoration, integrity and service checks. | Service/data owner accepts measured results against recovery objectives. |
| Observe/close | Monitoring coverage, agreed observation period, evidence retained, remaining risks and follow-up owners. | Named human approves closure; later evidence can reopen the case. |

Recovery objectives are owner-defined RTO (tolerated restoration time) and RPO (tolerated data-loss window). OpenShieldAI records observed results and gaps; it must not invent these objectives or guarantee them. Recovery planning and exercises follow [NIST SP 800-184](https://csrc.nist.gov/pubs/sp/800/184/final).

## 6. Account takeover or stolen session/token

**Trigger:** suspicious authentication, unauthorized MFA/device/credential enrollment, unusual privileged actions, malicious forwarding rules, or credible token-theft evidence. An unfamiliar IP alone is a signal, not proof.

1. **Verify and preserve:** establish the affected identity, identity provider, user/device context, sign-in and audit evidence, newly registered credentials/devices, consent grants, role changes, mailbox rules, and relevant application sessions. Avoid collecting raw tokens into case reports.
2. **Scope:** investigate adjacent identities and resources reachable by the account, including service identities and privileged roles. Distinguish a compromised endpoint from a stolen cloud session.
3. **Contain:** propose provider-specific session revocation, temporary account restriction, removal of unauthorized authentication methods/consents, or credential rotation with the owner. Record interruption and recovery access before changing a critical identity.
4. **Verify containment:** query provider/session/application state and residual token lifetime. Password reset alone must not be assumed to revoke all existing access or remove malicious OAuth grants.
5. **Eradicate/recover:** remediate the compromised device or access path; review identity configuration and downstream changes; re-enroll approved authentication methods; restore account access only after defined checks.
6. **Observe:** watch for unauthorized new sessions, repeated enrollment, privilege changes, and re-created forwarding or consent persistence. Keep unknown activity intervals visible.

Microsoft's [token-theft playbook](https://learn.microsoft.com/en-us/security/operations/token-theft-playbook) distinguishes user/session and device investigation. Its [emergency access revocation guidance](https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access) explains provider-specific revocation controls. A [2026-09-22 Microsoft investigation](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/) notes that revoking refresh tokens can leave existing access tokens valid for a period. Treat those sources as Microsoft-specific behavior, not a universal identity API contract.

## 7. Web application or host compromise

**Trigger:** credible web shell/persistence evidence, unauthorized deployment/file changes, exploit execution, new privileged processes/users, or correlated application and host signals.

1. **Verify and preserve:** retain relevant edge/application/deployment/identity/host logs; record file/image digests and deployment provenance; capture authorized forensic artifacts before overwriting the system when feasible.
2. **Scope:** trace reachable secrets, database/storage access, workloads using the same image/credential, and evidence of lateral movement. A WAF block does not establish that a compromised host is clean.
3. **Contain:** propose a narrow workload isolation, traffic restriction, route removal, or credential restriction. Identify management access and health dependencies so isolation does not strand the recovery team.
4. **Eradicate:** identify and correct the entry vector, inspect persistence and unauthorized identities, rotate exposed credentials through approved channels, and plan a rebuild from trusted sources when integrity is uncertain. Do not simply delete a suspicious file and declare success.
5. **Recover:** validate the clean image/configuration and data, restore to a controlled target, run service checks, then reconnect gradually under observation.
6. **Verify:** independently re-check the entry condition, known persistence indicators, deployed artifact provenance, and dependent service health. Record coverage beyond the initial alert.

Use [CISA's incident and vulnerability response playbooks](https://www.cisa.gov/sites/default/files/publications/Cybersecurity_Incident_Vulnerability_Response_Playbooks_508C.pdf) as an operational reference, especially the return to analysis when new compromise appears. OpenShieldAI does not inherit the authority or obligations of a US federal agency from that reference.

## 8. Suspected data exfiltration

**Trigger:** unauthorized exports, anomalous downloads, unexpected external destinations, suspicious access to sensitive datasets, or evidence of data staging.

1. **Verify and preserve:** collect authorized access/export/audit/network/storage records, object versions, and permission-change history. Protect any affected personal or confidential data from further exposure during analysis.
2. **Scope:** distinguish data accessed, staged, transmitted, and confirmed received. State uncertainty about content and volume; do not report an upper-bound estimate as proven theft.
3. **Contain:** propose narrow credential/session restriction, export suspension, or destination/egress restriction, with service impact and alternate access paths considered.
4. **Investigate:** reconcile identities, objects, time windows, encryption/transport visibility, telemetry gaps, and attacker-controlled destinations. A TLS connection alone does not prove which records left.
5. **Recover:** revoke exposed credentials, correct permissions and the initial access vector, validate data integrity/availability, and monitor recurrent export patterns.
6. **Escalate:** hand evidence-backed impact estimates to the incident commander and authorized legal/privacy process. OpenShieldAI must not decide notification obligations or contact external parties.

Stopping exfiltration cannot recall copies already transferred. Reports must separate containment, restoration of service, and unresolved confidentiality impact.

## 9. Ransomware, destructive activity, or missing/corrupted data

**Trigger:** credible encryption/deletion behavior, ransom notes plus corroboration, inaccessible critical data, mass object changes, or backup-control compromise. Also consider non-malicious causes such as failed deployment or storage failure.

1. **Verify and preserve:** identify affected services and observed damage; preserve representative original artifacts, protected logs, and authorized volatile evidence. Do not execute a ransom note, unknown decryptor, or malware sample.
2. **Contain urgently:** the incident commander chooses how to isolate affected systems and protect recovery infrastructure. Record evidence lost by emergency measures. CISA prefers disconnection/isolation where feasible and warns that powering down loses volatile artifacts.
3. **Protect backups:** assess whether backup identities, repositories, retention controls, and management systems are compromised. Separate recovery administration from affected identities. Freeze destructive retention changes through approved operational controls.
4. **Scope before restore:** identify precursor compromise, persistence, affected identities, destructive changes, suspected exfiltration, and whether the candidate restore point predates known compromise. The encryption start time need not equal the initial compromise time.
5. **Eradicate and rebuild:** correct the access path and trust failures; use clean recovery infrastructure and approved images. Keep unrecovered originals and forensic copies protected.
6. **Restore in isolation:** restore copies to a separate controlled target; validate data/application consistency, dependencies, selected content against trusted records, and identity/secret configuration. Do not overwrite the only remaining copy.
7. **Recover service:** prioritize owner-defined critical dependencies; reconnect in stages only after explicit checks; measure observed recovery time and data-loss window.
8. **Observe and close:** watch for renewed encryption, attacker access, suspicious retention changes, and integrity failures. Retain unresolved confidentiality impact and unrecoverable data in the final assessment.

The [CISA #StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide) supports coordinated isolation, preservation, protected backups, and clean restoration. [No More Ransom](https://www.nomoreransom.org/en/decryptiontools.html) offers variant-specific recovery tools; applicability is limited and must be verified by an expert on preserved copies. OpenShieldAI makes no decryption or data-recovery guarantee and does not negotiate or pay ransom.

An encrypted backup is not necessarily immutable or trustworthy. The [restic threat model](https://github.com/restic/restic/blob/master/doc/design.rst) explicitly describes compromised clients, malicious new snapshots, and the risk of deletion privileges or manipulated retention. Never let the AI run prune/forget or remove old copies as a recovery shortcut.

## 10. Compromised AI agent or poisoned context/tool chain

**Trigger:** unauthorized tool calls, unexpected data egress, goals diverging from the user's task, abnormal cost/tool loops, changed tool definitions or permissions, suspicious memory/RAG changes, or a credible indirect prompt-injection signal.

1. **Verify and preserve:** capture restricted copies of the authorized task, model/configuration identifiers, tool schemas and versions, action receipts, approval/capability records, retrieved-content references, context/memory changes, and egress events. Minimize sensitive prompt retention and control access.
2. **Scope:** identify the agent identity, available secrets and tools, downstream agents, shared memory/vector stores, affected users, and actual actions. Distinguish a blocked attempt from a completed external side effect.
3. **Contain:** propose pausing the affected execution, revoking its scoped capabilities, disabling the affected integration, or restricting egress. Preserve evidence before clearing state. Use a clean administrative context; the suspected agent cannot approve its own recovery.
4. **Eradicate:** quarantine suspect content and artifacts; restore trusted tool/configuration/memory versions; rotate exposed capabilities; correct the authorization or data-flow boundary. Filtering one attack string is not sufficient remediation.
5. **Recover safely:** replay the legitimate task and the incident's adversarial variant using synthetic data and stubbed tools; verify no unauthorized action or disclosure and acceptable legitimate-task utility. Re-enable permissions incrementally under owner approval.
6. **Observe:** monitor for renewed unauthorized actions, cross-case memory leakage, cascading agent failures, and budget/egress violations. Preserve the compromise hypothesis if root cause remains uncertain.

Relevant risk models: [NIST AI 600-1](https://doi.org/10.6028/NIST.AI.600-1) and [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/). [AgentDojo](https://github.com/ethz-spylab/agentdojo) is a candidate source for isolated adversarial evaluation; it is not an implemented OpenShieldAI protection.

The AI responder must obey these same boundaries when analyzing an attacker-controlled artifact. A second model reviewing the first model's text is not a substitute for an external policy gate and independently observed tool effects.

## 11. Availability attack or service overload

**Trigger:** abnormal request/resource patterns plus service degradation, a trusted provider alert, or credible evidence of intentional denial of service. Traffic spikes may also be legitimate demand or a software failure.

1. Preserve aggregate and sampled telemetry without amplifying data collection until it worsens the outage.
2. Correlate traffic, error rates, dependency health, deployment changes, saturation, and business impact; keep alternative causes visible.
3. Propose a narrow, expiring rate limit, cache/routing mitigation, or existing provider protection only after service-owner review. Broad IP blocks can deny legitimate users and must have rollback criteria.
4. Verify recovered service health and user impact, not merely reduced traffic. Monitor cost, alternate attack paths, and upstream bottlenecks.
5. Roll back temporary controls deliberately and retain prevention follow-ups. Do not counterattack or interact with suspected attacker infrastructure.

## 12. Escalation and closure rules

Escalate immediately through the organization's approved incident path when critical service/safety impact, rapid destructive spread, privileged identity compromise, suspected regulated-data exposure, uncertain recovery trust, or response-system compromise requires authority or expertise beyond the assigned responder. An AI confidence score cannot downgrade that need.

An incident closure record must contain:

- What was observed, what remains a hypothesis, and the evidence references.
- Affected and unknown assets/time periods; material collection and inspection gaps.
- Approved actions, actual execution results, and independent verification results.
- Entry vector and persistence assessment, or explicit residual uncertainty and accountable acceptance.
- Recovery point, restoration checks, measured recovery results, and service/data owner acceptance.
- Observation coverage and duration, unresolved confidentiality/data-loss impact, follow-up owners, and reopening conditions.

If evidence is insufficient, say so. Appropriate outcomes include "containment verified for the named resources; incident scope remains uncertain" or "service restored; confidentiality impact unresolved". Never collapse these into "system secure".

## 13. Tabletop coverage and staged executable replay

At S0, tabletop review should cover every playbook family, including benign lookalikes, expected evidence, prohibited actions, escalation, and recovery limits. This checks the design for omissions; it does not commit the first runtime release to supporting every family.

S1 executable replay is limited to the accepted first-lab scope and fixtures in the [PRD](../PRD.md), [evaluation plan](../EVALUATION.md), and [acceptance criteria](../ACCEPTANCE_CRITERIA.md): bounded synthetic/sanitized local observations for one Linux web application, its declared dependencies, and backup-readiness cases. Identity, exfiltration, or agent-compromise motifs may be represented as local synthetic evidence/safety variants without claiming a live adapter or full operational support. New families and environments require S4 acceptance before operational support.

S1 safety variants include poisoned input, tampered/cross-case evidence, conflicting timestamps, empty/failed queries, forged/stale approvals in local policy tests, exhausted budgets, missing/corrupt backups, and missing keys. S2 additionally tests real read-grant/source failures. S3 adds changed target state, ambiguous/partial actions, cancellation, expired action credentials, unavailable compensation, compromised restore points, and new persistence after apparent recovery; no production mutation is exercised in S1/S2.

The first release evaluates planning and evidence handling. Each later action/restore capability needs its own executable fault-injection and independent verification tests. A tabletop pass is evidence of a process review, not proof of real containment or recovery.
