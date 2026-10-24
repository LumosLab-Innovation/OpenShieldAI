"""Bounded synthetic evidence, durable state and read-only investigation."""

import hashlib
import json
import re
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

_DATETIME_TYPE = datetime

KINDS = {
    "waf_decision": {"decision": {"allow", "deny"}, "category": {"crs", "lab_rule", "unknown"}},
    "app_operation": {"authorized": bool, "count": int},
    "auth_decision": {"decision": {"allow", "deny"}, "subjectLabel": str, "objectLabel": str},
    "deployment": {"revision": str, "authorized": bool},
    "control_state": {"mode": {"enforce", "observe", "maintenance"}, "revision": str},
    "release_exposure": {"status": {"pass", "blocked", "partial"}, "observationCount": int, "gapCount": int},
    "source_health": {"available": bool, "dropped": int},
    "backup_state": {"snapshotId": str, "keyAvailable": bool, "integrity": {"pass", "fail", "unknown"},
                     "applicationConsistent": bool, "contaminated": bool},
    "verification": {"objective": {"new_ingress_stopped", "application_restored"},
                     "result": {"verified", "not_verified", "inconclusive"}, "independent": bool},
}
ACTIONS = {"set_site_ingress_mode", "restore_isolated"}
HYPOTHESES = {"http_input_attack", "business_abuse", "suspicious_access", "unauthorized_change",
              "false_positive", "authorized_activity", "control_gap", "recovery_gap", "unknown"}
READS = {"recent_waf_events", "recent_app_events", "control_posture", "backup_readiness", "access_patterns"}
LIMITATIONS = {"synthetic_lab_only", "visibility_gap", "stale_evidence", "unverified_effect",
               "no_supported_actuator", "no_independent_observer", "model_unavailable",
               "budget_exhausted", "incomplete_evidence", "unknown_model_version",
               "source_clock_skew", "bounded_window", "usage_unavailable"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def timestamp(value):
    if not isinstance(value, str) or len(value) > 40 or not value.endswith("Z"):
        raise ValueError("UTC timestamp required")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise ValueError("Invalid timestamp") from None
    return parsed


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", value):
        raise ValueError("Invalid opaque identifier")
    if re.match(r"(?i)(sk-|gh[pousr]_|github_pat_|AIza|Bearer)", value):
        raise ValueError("Recognizable credential-shaped identifier is forbidden")
    return value


def exact_fields(value, required, optional=()):
    if not isinstance(value, dict) or set(value) - set(required) - set(optional) or set(required) - set(value):
        raise ValueError("Invalid fields")


def validate_event(event):
    exact_fields(event, {"schemaVersion", "id", "projectId", "caseId", "assetId", "sourceId",
                         "observedAt", "kind", "facts", "dataClass"}, {"receivedAt"})
    if len(canonical(event).encode()) > 4096:
        raise ValueError("Event exceeds size limit")
    if event["schemaVersion"] != "lab_event_v1" or event["dataClass"] != "synthetic":
        raise ValueError("Only synthetic lab_event_v1 data is supported")
    for key in ("id", "projectId", "caseId", "assetId", "sourceId"):
        identifier(event[key])
    timestamp(event["observedAt"])
    if "receivedAt" in event:
        timestamp(event["receivedAt"])
    kind = event["kind"]
    if not isinstance(kind, str) or kind not in KINDS:
        raise ValueError("Unsupported event kind")
    facts = event["facts"]
    exact_fields(facts, KINDS[kind])
    for name, rule in KINDS[kind].items():
        value = facts[name]
        if isinstance(rule, set):
            if not isinstance(value, str) or value not in rule:
                raise ValueError("Unsupported fact enum")
        elif rule is str:
            identifier(value)
        elif type(value) is not rule or (rule is int and not 0 <= value <= 1_000_000):
            raise ValueError("Invalid fact type or bound")
    return event


class Store:
    """Local OS-user authority; never accepts an untrusted database path from evidence."""

    def __init__(self, path, clock=None):
        self.clock = clock
        self._now()
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, timeout=5)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS shield_enrollments(
                project_id TEXT, asset_id TEXT, record TEXT NOT NULL,
                PRIMARY KEY(project_id,asset_id));
            CREATE TABLE IF NOT EXISTS shield_events(
                seq INTEGER PRIMARY KEY, project_id TEXT, case_id TEXT, asset_id TEXT,
                event_id TEXT, record TEXT NOT NULL, received_at TEXT NOT NULL,
                UNIQUE(project_id,event_id));
            CREATE INDEX IF NOT EXISTS shield_case_events ON shield_events(project_id,case_id,seq);
            CREATE TABLE IF NOT EXISTS shield_episodes(
                dedup TEXT PRIMARY KEY, project_id TEXT, case_id TEXT, watermark TEXT,
                mode TEXT, route TEXT, status TEXT, started_at TEXT, deadline_at TEXT,
                calls INTEGER NOT NULL DEFAULT 0, tokens INTEGER NOT NULL DEFAULT 0,
                result TEXT);
            CREATE TABLE IF NOT EXISTS shield_health(
                name TEXT PRIMARY KEY, record TEXT NOT NULL);
        """)
        self.db.commit()

    def _now(self):
        value = self.clock() if self.clock is not None else datetime.now(timezone.utc)
        if not isinstance(value, _DATETIME_TYPE) or value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("Store clock must return an aware UTC datetime")
        return value

    def _utc_now(self):
        return self._now().isoformat().replace("+00:00", "Z")

    def close(self):
        self.db.close()

    def enroll(self, project_id, asset_id, owner, *, expires_at=None, source_ids=("lab",),
               allowed_actions=(), synthetic_only=True, source_roles=None):
        for item in (project_id, asset_id, owner):
            identifier(item)
        if synthetic_only is not True:
            raise ValueError("Runtime accepts synthetic lab data only")
        if not source_ids or len(source_ids) > 16 or len(set(source_ids)) != len(source_ids):
            raise ValueError("Enrollment needs one to sixteen distinct sources")
        for source in source_ids:
            identifier(source)
        if not set(allowed_actions) <= ACTIONS:
            raise ValueError("Unsupported action capability")
        roles = source_roles or {source: "telemetry" for source in source_ids}
        if set(roles) != set(source_ids) or any(role not in {"telemetry", "observer"} for role in roles.values()):
            raise ValueError("Source roles must match the enrolled sources")
        existing = self.db.execute("SELECT record FROM shield_enrollments WHERE project_id=? AND asset_id=?",
                                   (project_id, asset_id)).fetchone()
        if expires_at is None:
            expires_at = (json.loads(existing[0])["expiresAt"] if existing else
                          (self._now() + timedelta(days=1)).isoformat().replace("+00:00", "Z"))
        timestamp(expires_at)
        record = {"projectId": project_id, "assetId": asset_id, "owner": owner, "expiresAt": expires_at,
                  "sourceIds": sorted(source_ids), "sourceRoles": roles,
                  "allowedActions": sorted(set(allowed_actions)), "dataClass": "synthetic"}
        record["scopeVersion"] = digest(record)
        if existing and existing[0] != canonical(record):
            raise ValueError("Enrollment is immutable; create a new asset enrollment")
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO shield_enrollments VALUES(?,?,?)",
                            (project_id, asset_id, canonical(record)))
        return record

    def enrollment(self, project_id, asset_id):
        row = self.db.execute("SELECT record FROM shield_enrollments WHERE project_id=? AND asset_id=?",
                              (project_id, asset_id)).fetchone()
        if not row:
            raise ValueError("Asset is not enrolled in this project")
        record = json.loads(row[0])
        if timestamp(record["expiresAt"]) <= self._now():
            raise ValueError("Enrollment expired")
        return record

    def ingest(self, event):
        return self.ingest_batch([event])[0]

    def ingest_batch(self, events):
        """One bounded case import: any invalid record rolls back the entire batch."""
        if (not isinstance(events, list) or not 1 <= len(events) <= 1000 or
                len(canonical(events).encode()) > 1_048_576):
            raise ValueError("Invalid batch or batch size limit")
        for event in events:
            validate_event(event)
        if len({(e["projectId"], e["caseId"], e["assetId"]) for e in events}) != 1:
            raise ValueError("A batch must bind one project/case/asset")
        try:
            with self.db:
                self.db.execute("BEGIN IMMEDIATE")
                return [self._ingest(event) for event in events]
        except ValueError as error:
            if str(error) == "Case intake cap reached; visibility is incomplete":
                self._health("intake", {"state": "degraded_visibility", "reason": "case_intake_cap"})
            raise

    def _ingest(self, event):
        event = validate_event(event)
        scope = self.enrollment(event["projectId"], event["assetId"])
        if event["sourceId"] not in scope["sourceIds"]:
            raise ValueError("Source is not enrolled")
        if event["kind"] == "verification" and event["facts"]["result"] == "verified":
            if (scope["sourceRoles"][event["sourceId"]] != "observer" or
                    event["facts"]["independent"] is not True):
                raise ValueError("Verification requires an enrolled observer")
        old = self.db.execute("SELECT record FROM shield_events WHERE project_id=? AND event_id=?",
                              (event["projectId"], event["id"])).fetchone()
        if old:
            if old[0] != canonical(event):
                raise ValueError("Conflicting duplicate event")
            return False
        asset = self.db.execute("SELECT asset_id FROM shield_events WHERE project_id=? AND case_id=? LIMIT 1",
                                (event["projectId"], event["caseId"])).fetchone()
        if asset and asset[0] != event["assetId"]:
            raise ValueError("This lab case is bound to one enrolled asset")
        count = self.db.execute("SELECT COUNT(*) FROM shield_events WHERE project_id=? AND case_id=?",
                                (event["projectId"], event["caseId"])).fetchone()[0]
        if count >= 1000:
            raise ValueError("Case intake cap reached; visibility is incomplete")
        self.db.execute("INSERT INTO shield_events(project_id,case_id,asset_id,event_id,record,received_at) "
                        "VALUES(?,?,?,?,?,?)", (event["projectId"], event["caseId"], event["assetId"],
                                               event["id"], canonical(event), self._utc_now()))
        return True

    def _health(self, name, record):
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO shield_health VALUES(?,?)", (name, canonical(record)))

    def health(self):
        return {row[0]: json.loads(row[1]) for row in self.db.execute("SELECT name,record FROM shield_health")}

    def case(self, project_id, case_id):
        identifier(project_id)
        identifier(case_id)
        rows = self.db.execute("SELECT record,received_at FROM shield_events WHERE project_id=? AND case_id=? "
                               "ORDER BY seq", (project_id, case_id)).fetchall()
        if not rows:
            raise ValueError("Unknown case")
        events = [json.loads(row[0]) for row in rows]
        scope = self.enrollment(project_id, events[0]["assetId"])
        now = self._now()
        gaps = []
        if any((now - timestamp(e["observedAt"])).total_seconds() > 300 for e in events):
            gaps.append("stale_evidence")
        if any((timestamp(e["observedAt"]) - timestamp(rows[i][1])).total_seconds() > 30
               for i, e in enumerate(events)):
            gaps.append("source_clock_skew")
        if any(e["kind"] == "source_health" and
               (not e["facts"]["available"] or e["facts"]["dropped"] > 0) for e in events):
            gaps.append("visibility_gap")
        if not any(role == "observer" for role in scope["sourceRoles"].values()):
            gaps.append("no_independent_observer")
        return {"schemaVersion": "case_snapshot_v1", "projectId": project_id, "caseId": case_id,
                "assetId": scope["assetId"], "version": len(events), "watermark": digest(events),
                "evidenceIds": [e["id"] for e in events], "dataClass": "synthetic",
                "timeline": [{**event, "ingestedAt": rows[i][1],
                              "sourceTrust": "operator_enrolled_synthetic_source",
                              "sourceRole": scope["sourceRoles"][event["sourceId"]]}
                             for i, event in enumerate(events)],
                "allowedActions": scope["allowedActions"], "gaps": sorted(set(gaps)),
                "coverage": {"sourcesObserved": sorted({e["sourceId"] for e in events}),
                             "sourcesEnrolled": scope["sourceIds"],
                             "windowStart": min(e["observedAt"] for e in events),
                             "windowEnd": max(e["observedAt"] for e in events),
                             "complete": False}}

    def cases(self, project_id=None):
        query = "SELECT project_id,case_id FROM shield_events"
        args = ()
        if project_id is not None:
            identifier(project_id)
            query += " WHERE project_id=?"
            args = (project_id,)
        return [self.case(row[0], row[1]) for row in self.db.execute(
            query + " GROUP BY project_id,case_id ORDER BY MIN(seq)", args).fetchall()]


def baseline(case):
    """Frozen baseline v1: documented literal rules, no label-dependent tuning."""
    events = case["timeline"]
    hypotheses = []
    action = "observe"
    assessment = "insufficient_evidence"
    harm = [e["id"] for e in events if e["kind"] == "app_operation" and
            not e["facts"]["authorized"] and e["facts"]["count"] > 0]
    changes = [e["id"] for e in events if e["kind"] == "deployment" and not e["facts"]["authorized"]]
    denies = [e["id"] for e in events if e["kind"] == "waf_decision" and e["facts"]["decision"] == "deny"]
    # A blocked burst is a candidate investigation, never an automatic isolation verdict.
    if len(denies) >= 5:
        hypotheses.append({"code": "http_input_attack", "evidenceIds": denies})
        assessment = "suspicious"
    if harm:
        hypotheses.append({"code": "business_abuse", "evidenceIds": harm})
        assessment = "suspicious"
        action = "set_site_ingress_mode" if "set_site_ingress_mode" in case["allowedActions"] else "needs_human"
    if changes:
        hypotheses.append({"code": "unauthorized_change", "evidenceIds": changes})
        assessment, action = "suspicious", "needs_human"
    bad_backups = [e["id"] for e in events if e["kind"] == "backup_state" and
                   (not e["facts"]["keyAvailable"] or e["facts"]["integrity"] != "pass" or
                    not e["facts"]["applicationConsistent"] or e["facts"]["contaminated"])]
    if bad_backups:
        hypotheses.append({"code": "recovery_gap", "evidenceIds": bad_backups})
    exposed = [e["id"] for e in events if e["kind"] == "release_exposure" and
               (e["facts"]["status"] != "pass" or e["facts"]["observationCount"] or e["facts"]["gapCount"])]
    if exposed:
        hypotheses.append({"code": "control_gap", "evidenceIds": exposed})
        if action == "observe":
            action = "needs_human"
    if not hypotheses and events and all(e["kind"] == "app_operation" and e["facts"]["authorized"] for e in events):
        hypotheses.append({"code": "authorized_activity", "evidenceIds": case["evidenceIds"]})
        assessment = "benign"
    return {"assessment": assessment, "hypotheses": hypotheses, "nextAction": action,
            "evidenceIds": case["evidenceIds"], "readRequests": [],
            "limitations": sorted(set(case["gaps"] + ["synthetic_lab_only", "bounded_window", "unverified_effect"]))}


def validate_analysis(value, case):
    exact_fields(value, {"schemaVersion", "assessment", "hypotheses", "nextAction", "evidenceIds",
                         "readRequests", "limitations"})
    if value["schemaVersion"] != "analysis_v1" or value["assessment"] not in {
            "suspicious", "benign", "insufficient_evidence"}:
        raise ValueError("Invalid analysis schema or assessment")
    if value["nextAction"] not in {"observe", "needs_human"} | (ACTIONS & set(case["allowedActions"])):
        raise ValueError("Unsupported or unauthorized model action")
    known = set(case["evidenceIds"])

    def refs(items):
        if not isinstance(items, list) or len(items) > 1000 or any(not isinstance(item, str) for item in items):
            raise ValueError("Invalid evidence references")
        if not set(items) <= known or len(items) != len(set(items)):
            raise ValueError("Unknown, cross-case or repeated evidence reference")

    refs(value["evidenceIds"])
    if not isinstance(value["hypotheses"], list) or len(value["hypotheses"]) > 8:
        raise ValueError("Invalid hypotheses")
    for hypothesis in value["hypotheses"]:
        exact_fields(hypothesis, {"code", "evidenceIds"})
        if hypothesis["code"] not in HYPOTHESES:
            raise ValueError("Unsupported hypothesis")
        refs(hypothesis["evidenceIds"])
        if not hypothesis["evidenceIds"]:
            raise ValueError("Hypothesis needs evidence")
    if value["nextAction"] not in {"observe", "needs_human"} and not value["evidenceIds"]:
        raise ValueError("Action proposal needs evidence")
    if not isinstance(value["readRequests"], list) or len(value["readRequests"]) > 3:
        raise ValueError("Read request cap exceeded")
    for request in value["readRequests"]:
        exact_fields(request, {"catalogId", "limit"})
        if request["catalogId"] not in READS or type(request["limit"]) is not int or not 1 <= request["limit"] <= 100:
            raise ValueError("Invalid catalog read")
    if (not isinstance(value["limitations"], list) or len(value["limitations"]) > 16 or
            any(not isinstance(item, str) or item not in LIMITATIONS for item in value["limitations"])):
        raise ValueError("Invalid limitations")
    return value


class Supervisor:
    def __init__(self, store, gateway=None, *, mode="ai"):
        if mode not in {"baseline", "ai"}:
            raise ValueError("Mode must be baseline or ai")
        self.store, self.gateway, self.mode = store, gateway, mode

    def tick(self, project_id=None):
        """One cheap resident-service tick. Unchanged evidence never restarts inference."""
        results = []
        previous = self.store.health().get("supervisor", {"state": "healthy_idle"})
        self.store._health("supervisor", {**previous, "lastTickAt": utc_now(), "mode": self.mode})
        for case in self.store.cases(project_id):
            self.store._health("source_" + case["assetId"], {
                "state": "degraded_visibility" if case["gaps"] else "observed_synthetic_window",
                "gaps": case["gaps"], "watermark": case["watermark"], "checkedAt": utc_now()})
            route = self.gateway.route_hash if self.gateway else "unconfigured"
            # A deadline-driven visibility transition is material; unchanged stale ticks are not.
            key = digest([case["projectId"], case["caseId"], case["watermark"], case["gaps"], self.mode, route])
            if self.store.db.execute("SELECT 1 FROM shield_episodes WHERE dedup=?", (key,)).fetchone():
                continue
            result = self._investigate(case, key, route)
            if result is not None:
                results.append(result)
        return results

    def _investigate(self, case, key, route):
        base = baseline(case)
        started = utc_now()
        deadline = (datetime.now(timezone.utc) + timedelta(seconds=180)).isoformat().replace("+00:00", "Z")
        with self.store.db:
            self.store.db.execute("BEGIN IMMEDIATE")
            if self.store.db.execute("SELECT 1 FROM shield_episodes WHERE dedup=?", (key,)).fetchone():
                return None
            active = self.store.db.execute("SELECT project_id,case_id FROM shield_episodes "
                                          "WHERE status='running' AND deadline_at>?", (started,)).fetchall()
            if len(active) >= 2 or any(row[0] == case["projectId"] and row[1] == case["caseId"] for row in active):
                self.store._health("supervisor", {"state": "backlogged", "oldestUnexaminedAt": case["timeline"][0]["ingestedAt"]})
                return {"status": "backlogged", "projectId": case["projectId"], "caseId": case["caseId"]}
            # Persist intent before any provider call; a crashed episode is never silently replayed.
            self.store.db.execute("INSERT INTO shield_episodes(dedup,project_id,case_id,watermark,mode,route,status,"
                                  "started_at,deadline_at) VALUES(?,?,?,?,?,?,'running',?,?)",
                                  (key, case["projectId"], case["caseId"], case["watermark"], self.mode,
                                   route, started, deadline))
        analysis, status, failure_code = base, "not_requested", None
        started_mono = time.monotonic()
        if self.mode == "ai" and self.gateway is None:
            status = "degraded_unconfigured"
        elif self.mode == "ai":
            try:
                context = dict(case)
                for round_number in range(3):
                    context["readRoundsRemaining"] = 2 - round_number
                    analysis = self.gateway.analyze(context, before_attempt=lambda tokens: self._reserve(key, tokens),
                                                    deadline=time.monotonic() + max(0, 180 - (time.monotonic() - started_mono)))
                    validate_analysis(analysis, case)
                    if not analysis["readRequests"]:
                        break
                    if round_number == 2:
                        from .gateway import GatewayError
                        raise GatewayError("READ_ROUND_LIMIT")
                    context["catalogObservations"] = self._reads(case, analysis["readRequests"])
                status = "succeeded"
            except Exception as error:
                # Provider exceptions are untrusted and can echo credentials/content. Persist only safe codes.
                from .gateway import GatewayError
                from .correlation import CorrelationError
                status = ("degraded_tool" if isinstance(error, CorrelationError) else
                          "degraded_budget" if isinstance(error, GatewayError) and error.code == "BUDGET_EXHAUSTED" else "degraded_model")
                safe_codes = {"BUDGET_EXHAUSTED", "READ_ROUND_LIMIT", "CREDENTIAL_UNAVAILABLE", "CROSS_CASE_INPUT",
                              "DATA_CLASS_DENIED", "DEADLINE_EXCEEDED", "INPUT_LIMIT", "INVALID_CASE_CONTEXT",
                              "INVALID_PROVIDER_OUTPUT", "INVALID_READ_CONTEXT", "OUTPUT_LIMIT", "PROVIDER_CONTENT_TYPE",
                              "PROVIDER_HTTP_FAILURE", "PROVIDER_UNAVAILABLE", "TRANSIENT_PROVIDER_FAILURE", "USAGE_UNAVAILABLE"}
                failure_code = (error.code if isinstance(error, GatewayError) and error.code in safe_codes
                                else "TOOL_CONTRACT_REJECTED" if isinstance(error, CorrelationError)
                                else "ANALYSIS_OR_TOOL_CONTRACT_REJECTED")
                analysis = base
        totals = self.store.db.execute("SELECT calls,tokens FROM shield_episodes WHERE dedup=?", (key,)).fetchone()
        limitations = set(analysis["limitations"]) | set(base["limitations"])
        if status.startswith("degraded"):
            limitations.add("incomplete_evidence" if status == "degraded_tool" else
                            "budget_exhausted" if status == "degraded_budget" else "model_unavailable")
        result = {**analysis, "schemaVersion": "investigation_v1", "projectId": case["projectId"],
                  "caseId": case["caseId"], "assetId": case["assetId"], "caseVersion": case["version"],
                  "evidenceWatermark": case["watermark"], "mode": self.mode, "aiStatus": status,
                  "aiFailureCode": failure_code,
                  "limitations": sorted(limitations), "calls": totals[0], "tokens": totals[1],
                  "tokenAccounting": "conservative_reserved_upper_bound", "startedAt": started,
                  "completedAt": utc_now(), "elapsedSeconds": round(time.monotonic() - started_mono, 6),
                  "routeHash": route,
                  "modelProvenance": getattr(self.gateway, "last_metadata", None) if status == "succeeded" else None,
                  "verificationAuthority": "independent_observer_only"}
        with self.store.db:
            self.store.db.execute("UPDATE shield_episodes SET status='completed',result=? WHERE dedup=?",
                                  (canonical(result), key))
        self.store._health("supervisor", {"state": "degraded_observation" if status == "degraded_tool" else
                                           "degraded_model" if status.startswith("degraded") else "healthy_idle",
                                           "lastAnalysisAt": result["completedAt"], "lastWatermark": case["watermark"],
                                           "aiStatus": status})
        return result

    def _reserve(self, key, tokens):
        from .gateway import GatewayError
        with self.store.db:
            self.store.db.execute("BEGIN IMMEDIATE")
            row = self.store.db.execute("SELECT calls,tokens,deadline_at FROM shield_episodes WHERE dedup=?", (key,)).fetchone()
            total = self.store.db.execute("SELECT COALESCE(SUM(tokens),0) FROM shield_episodes WHERE mode='ai'").fetchone()[0]
            if (row[0] >= 8 or row[1] + tokens > 64000 or timestamp(row[2]) <= datetime.now(timezone.utc) or
                    total + tokens > self.gateway.config.global_token_limit):
                raise GatewayError("BUDGET_EXHAUSTED")
            self.store.db.execute("UPDATE shield_episodes SET calls=calls+1,tokens=tokens+? WHERE dedup=?", (tokens, key))

    def _reads(self, case, requests):
        mapping = {"recent_waf_events": {"waf_decision"}, "recent_app_events": {"app_operation", "auth_decision"},
                   "control_posture": {"control_state", "deployment", "source_health"}, "backup_readiness": {"backup_state"}}
        scope = self.store.enrollment(case["projectId"], case["assetId"])
        observations = []
        for request in requests:
            if request["catalogId"] == "access_patterns":
                from .correlation import CorrelationError, request_for, run
                try:
                    result = run(request_for(case, scope, self.store._utc_now()))
                except CorrelationError as error:
                    self.store._health("correlation", {"state": "unavailable", "code": error.code})
                    raise
                self.store._health("correlation", {"state": result["status"], "gaps": result["coverage"]["gaps"]})
                candidates = result["candidates"][:request["limit"]]
                observations.append({"catalogId": "access_patterns", "status": result["status"],
                                     "candidates": candidates, "omittedCandidates": len(result["candidates"])-len(candidates),
                                     "coverage": result["coverage"], "limitations": result["limitations"],
                                     "ruleVersion": result["ruleVersion"], "isFinding": False,
                                     "origin": "same_episode_synthetic_store"})
            else:
                observations.append({"catalogId": request["catalogId"], "events": [e for e in case["timeline"]
                                     if e["kind"] in mapping[request["catalogId"]]][-request["limit"]:],
                                     "origin": "same_episode_synthetic_store"})
        return observations
