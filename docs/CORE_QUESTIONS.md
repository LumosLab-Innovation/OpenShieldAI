# The four questions OpenShieldAI must answer

Status: engineering questions and selected design. A synthetic runtime and isolated first-lab experiments now exercise a subset; [measured results](lab/RESULTS.md) distinguish actual observations from unpassed production and AI-benefit claims. The website and documents themselves provide no protection.

Every capability needs a falsifiable chain: **threat → observations → decision → actual control point → independently observed effect → service impact → residual risk**. A response without an actuator is advice. An actuator without verification is an unproven action.

## 1. Can it actually prevent an attack? How?

1. Which attack and which protected invariant? Distinguish malicious HTTP input, stolen identity, broken object authorization, host execution, data disclosure and availability.
2. Where must the attack pass? Which reverse proxy, application authorization check, identity/session verifier, network control or backup boundary can stop it?
3. Can an attacker bypass that point through the origin, another hostname/path/protocol, an existing session or a different network path?
4. What is inspected before damage occurs? Which request fields/limits, identity context, object ownership or process event is observable, and what is encrypted/invisible?
5. Which deployed rule/control blocks the operation? Is it actually in blocking mode, correctly ordered and enforcing the supported request phases?
6. What did AI contribute: identify a gap, prioritize a hypothesis, select a reviewed control, propose a narrower exclusion or discover a missing invariant? What works without it?
7. How are legitimate operations preserved? Test uploads, encoded inputs, business transactions and authorized changes, not just attack examples.
8. How is prevention proved? Observe the request and application-side non-effect with an independent oracle; a WAF alert/403 alone is insufficient.
9. Which attacks remain outside this control's reach, and how is that gap exposed to the operator?

**First selected prevention experiment:** an operator-deployed Caddy + Coraza/CRS ingress in an isolated lab, with the origin unreachable through any unmediated route. The last approved blocking policy acts immediately; AI supervises evidence and proposes reviewed changes outside the request path. This does not establish protection against valid-session IDOR, root compromise or upstream volumetric DDoS.

## 2. Can it handle an attack that is already happening? How?

1. How is an active incident distinguished from an isolated blocked request, normal deployment, failed login or compromised telemetry source?
2. Which entity is followed across time: request, account/session, service/container, process, file, database object or outbound destination?
3. How much time passes from source event to collection, decision, human approval, execution and verified effect? How much harm can accumulate during that interval?
4. Is the proposed action on the attacker's current path? Blocking new HTTP traffic does not end an existing shell, token, database connection or outbound transfer.
5. Which exact actuator is available, reachable and authorized now? If none exists, does the product say `response_unavailable` instead of pretending to contain the incident?
6. Can it preserve the management path and critical service dependencies while containing a narrow asset?
7. What does AI do next when evidence is missing? Which bounded read queries can it request, and when must it abstain or escalate?
8. What happens if the attacker floods alerts, the collector drops events, the model times out, approval is delayed or the response receipt is lost?
9. Which independent observation shows the attack path stopped, and what legitimate-service probes show the defense did not become the outage?

**First selected response experiment:** within an explicitly accepted low-impact site envelope, place its ingress into a reviewed maintenance policy after exact approval; preserve management access and measure new blocked requests and deliberate user-visible downtime. Existing in-flight requests/streams may continue. Higher-impact maintenance is R3/human-run. Host/identity/egress compromise needs separate actuators and is not declared contained by this experiment.

## 3. Can it handle the aftermath? How?

1. Which initial access, persistence, identity and data-exposure hypotheses remain open after the alert stops?
2. Where is the clean trust anchor: an independent control plane, known-good build manifest, isolated recovery identity and an uncompromised evidence/backup store?
3. Which artifacts must be preserved before cleanup, and who decides the trade-off if waiting permits ongoing damage?
4. Which secrets/sessions/keys may be compromised? How are reissued identities protected, and what access can survive nominal revocation?
5. Is there a usable recovery source with keys, retention and application-consistent data? A snapshot timestamp or successful backup job is not sufficient.
6. How is a restore tested without overwriting production or reconnecting persistence? What file, database and business invariants must hold?
7. What actual data-loss interval and time-to-usable-service were measured? Report RPO/RTO against the owner's objectives, including failed drills.
8. Who authorizes reconnection, which post-recovery observations continue, and what evidence reopens the incident?
9. What cannot be undone: disclosure, permanently lost keys/data, destroyed evidence or unknown persistence?

**First selected recovery experiment:** restore a pinned restic snapshot and an application-consistent database export into an isolated scratch service, verify planted ground-truth invariants and exercise missing-key/corrupt/contaminated snapshot controls. Production restore and broad eradication stay qualified-human procedures.

## 4. Is AI continuously present? Where and how?

1. Is AI an active service in the normal operating mode, or merely a button that summarizes a report?
2. Which events, timers, changed facts, control drift and failed verification wake it? What keeps it from repeatedly reasoning over unchanged data?
3. What durable case/entity state survives a restart? How are facts, hypotheses, source trust, confidence basis and unanswered questions represented outside the prompt?
4. Which bounded reads can an investigator request through policy, and what is the evidence/cost/time budget for that loop?
5. What are its separate jobs before, during and after an incident, and what typed output does each job produce?
6. Which decisions remain deterministic and immediate? No LLM/network call may be required to run an already deployed request-blocking policy.
7. How are poisoned logs, self-confirming hypotheses, benign drift and compromised baselines challenged without pretending a second model is ground truth?
8. What is the visible AI health state, last evidence watermark, backlog age and last successful analysis? Does a model outage explicitly degrade the product?
9. Which measured result improves when AI is enabled, compared with the same tools, permissions, inputs and operator workflow without it?

**Selected definition:** AI is a resident, event-driven supervisor with durable evidence state and recurring preparedness/recovery jobs. It does not consume a token for every request or reason forever when nothing changes. Model failure produces **degraded defense**, while previously approved deterministic controls continue. AI may propose bounded observations and actions; it cannot grant itself execution authority.

## Engineering answer, not a slogan

See [operating architecture](OPERATING_ARCHITECTURE.md) for deployment/control points, state, job triggers, actuator protocol, scenario traces, timing and proof obligations; [AI roles](LLM_PROVIDER_SPEC.md) for use cases; and [the adversarial review](research/ARCHITECTURE_CHALLENGE.md) for unresolved mechanisms and acceptance gates.
