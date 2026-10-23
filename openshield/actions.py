"""Exact approvals for the isolated lab; no production execution adapter."""

import hashlib
import hmac
import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps


class ActionDenied(ValueError):
    pass


def audit_denials(method):
    @wraps(method)
    def call(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except ActionDenied as exc:
            with self._transaction():
                self._audit("policy_denial", operation=method.__name__, code=str(exc))
            raise
    return call


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def instant(value):
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.utcoffset() is None:
            raise ValueError()
        return result.timestamp()
    except (TypeError, AttributeError, ValueError) as exc:
        raise ActionDenied("INVALID_DEADLINE") from exc


def now():
    return datetime.now(timezone.utc).timestamp()


class ActionService:
    """Single local operator, synthetic lab only; OS account is the trust boundary."""

    def __init__(self, path, store, *, operator, allow_lab_mutations=False):
        if not operator or len(operator) > 128:
            raise ActionDenied("INVALID_OPERATOR")
        self.store = store
        self.operator = operator
        self.enabled = allow_lab_mutations
        self.db = sqlite3.connect(path, timeout=5)
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS action_proposals
              (id TEXT PRIMARY KEY, body TEXT NOT NULL, digest TEXT NOT NULL, state TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS action_approvals
              (id TEXT PRIMARY KEY, proposal_id TEXT UNIQUE, digest TEXT, actor TEXT,
               expires REAL, state TEXT);
            CREATE TABLE IF NOT EXISTS action_audit
              (seq INTEGER PRIMARY KEY, event TEXT NOT NULL, previous TEXT NOT NULL, digest TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS action_settings (name TEXT PRIMARY KEY, value TEXT);
            INSERT OR IGNORE INTO action_settings VALUES ('killed', '0');
        """)
        self.db.commit()

    def close(self):
        self.db.close()

    def verify_audit(self):
        previous = "0" * 64
        for seq, event, prior, digest in self.db.execute("SELECT * FROM action_audit ORDER BY seq"):
            expected = hashlib.sha256(f"{seq}:{prior}:{event}".encode()).hexdigest()
            if prior != previous or not hmac.compare_digest(digest, expected):
                raise ActionDenied("AUDIT_INTEGRITY_FAILURE")
            previous = digest

    def _audit(self, event, **fields):
        last = self.db.execute("SELECT seq,digest FROM action_audit ORDER BY seq DESC LIMIT 1").fetchone()
        seq, prior = (last[0] + 1, last[1]) if last else (1, "0" * 64)
        value = canonical({"event": event, "at": now(), **fields})
        digest = hashlib.sha256(f"{seq}:{prior}:{value}".encode()).hexdigest()
        self.db.execute("INSERT INTO action_audit VALUES (?,?,?,?)", (seq, value, prior, digest))

    @contextmanager
    def _transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self.verify_audit()
            yield
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

    def _available(self):
        if not self.enabled:
            raise ActionDenied("LAB_EXECUTION_DISABLED")
        if self.db.execute("SELECT value FROM action_settings WHERE name='killed'").fetchone()[0] != "0":
            raise ActionDenied("KILL_SWITCH")

    def _current(self, proposal):
        self._available()
        enrollment = self.store.enrollment(proposal["projectId"], proposal["assetId"])
        if "set_site_ingress_mode" not in enrollment["allowedActions"]:
            raise ActionDenied("ACTION_NOT_ENROLLED")
        if enrollment["owner"] != self.operator:
            raise ActionDenied("OPERATOR_NOT_OWNER")
        if enrollment["scopeVersion"] != proposal["scopeVersion"]:
            raise ActionDenied("ENROLLMENT_CHANGED")
        if enrollment.get("expiresAt") and instant(enrollment["expiresAt"]) <= now():
            raise ActionDenied("ENROLLMENT_EXPIRED")
        case = self.store.case(proposal["projectId"], proposal["caseId"])
        if case["assetId"] != proposal["assetId"]:
            raise ActionDenied("ASSET_SCOPE_MISMATCH")
        if case["version"] != proposal["caseVersion"] or case["watermark"] != proposal["evidenceWatermark"]:
            raise ActionDenied("CASE_CHANGED")
        if set(case["gaps"]) & {"stale_evidence", "source_clock_skew", "visibility_gap", "no_independent_observer"}:
            raise ActionDenied("OBSERVATION_PRECONDITION_FAILED")
        if instant(proposal["expiresAt"]) <= now():
            raise ActionDenied("APPROVAL_EXPIRED")
        if enrollment.get("dataClass") != "synthetic":
            raise ActionDenied("ONLY_SYNTHETIC_LAB_SUPPORTED")

    def _proposal(self, proposal_id):
        row = self.db.execute("SELECT body,digest,state FROM action_proposals WHERE id=?", (proposal_id,)).fetchone()
        if row is None:
            raise ActionDenied("UNKNOWN_PROPOSAL")
        proposal = json.loads(row[0])
        digest = hashlib.sha256(canonical(proposal).encode()).hexdigest()
        if not hmac.compare_digest(digest, row[1]):
            raise ActionDenied("PROPOSAL_TAMPERED")
        return proposal, digest, row[2]

    @audit_denials
    def propose(self, project_id, case_id, asset_id, expected_etag, *, review_due_at,
                expires_at, mode="maintenance", accepted_low_impact=False):
        if project_id != "lab" or asset_id != "lab_web":
            raise ActionDenied("UNREGISTERED_LAB_ASSET")
        if mode not in ("maintenance", "on") or accepted_low_impact is not True:
            raise ActionDenied("UNSUPPORTED_IMPACT_OR_MODE")
        if not isinstance(expected_etag, str) or len(expected_etag) > 256 or not expected_etag.startswith('"') or not expected_etag.endswith('"'):
            raise ActionDenied("INVALID_TARGET_ETAG")
        if instant(review_due_at) <= now() or instant(expires_at) - now() > 300:
            raise ActionDenied("INVALID_APPROVAL_WINDOW")
        case = self.store.case(project_id, case_id)
        enrollment = self.store.enrollment(project_id, asset_id)
        proposal = {
            "schemaVersion": "lab_action_proposal_v1", "id": uuid.uuid4().hex,
            "projectId": project_id, "caseId": case_id, "assetId": asset_id,
            "actionType": "set_site_ingress_mode", "mode": mode,
            "caseVersion": case["version"], "evidenceWatermark": case["watermark"],
            "scopeVersion": enrollment["scopeVersion"],
            "evidenceIds": case["evidenceIds"], "targetEtag": expected_etag,
            "policyVersion": "isolated-lab-v1", "reviewDueAt": review_due_at,
            "expiresAt": expires_at, "risk": "R2", "acceptedLowImpact": True,
            "impact": "New ingress is interrupted; reload may close streams. Host/identity/egress remain uncontained.",
            "compensation": "Separate exact approval for fixed on template with current ETag",
        }
        digest = hashlib.sha256(canonical(proposal).encode()).hexdigest()
        with self._transaction():
            self._current(proposal)
            self.db.execute("INSERT INTO action_proposals VALUES (?,?,?,?)", (proposal["id"], canonical(proposal), digest, "awaiting_approval"))
            self._audit("proposal", proposalId=proposal["id"], digest=digest)
        return {**proposal, "digest": digest}

    @audit_denials
    def approve(self, proposal_id, digest, *, operator):
        if operator != self.operator:
            raise ActionDenied("WRONG_OPERATOR")
        with self._transaction():
            proposal, expected, state = self._proposal(proposal_id)
            self._current(proposal)
            if state != "awaiting_approval" or not hmac.compare_digest(str(digest), expected):
                raise ActionDenied("DIGEST_OR_STATE_MISMATCH")
            approval = {"id": uuid.uuid4().hex, "proposalId": proposal_id, "digest": expected,
                        "operator": operator, "expiresAt": proposal["expiresAt"], "state": "granted"}
            self.db.execute("INSERT INTO action_approvals VALUES (?,?,?,?,?,?)", (approval["id"], proposal_id, expected, operator, instant(proposal["expiresAt"]), "granted"))
            self.db.execute("UPDATE action_proposals SET state='approved' WHERE id=?", (proposal_id,))
            self._audit("approval", proposalId=proposal_id, approvalId=approval["id"], actor=operator, digest=expected)
        return approval

    @audit_denials
    def execute(self, proposal_id, approval_id, lab):
        if (getattr(lab, "lab_id", None), getattr(lab, "project_id", None), getattr(lab, "asset_id", None)) != ("openshield-lab", "lab", "lab_web"):
            raise ActionDenied("UNREGISTERED_LAB")
        with self._transaction():
            proposal, digest, state = self._proposal(proposal_id)
            self._current(proposal)
            row = self.db.execute("SELECT proposal_id,digest,actor,expires,state FROM action_approvals WHERE id=?", (approval_id,)).fetchone()
            if not row or row != (proposal_id, digest, self.operator, instant(proposal["expiresAt"]), "granted") or state != "approved":
                raise ActionDenied("INVALID_OR_CONSUMED_APPROVAL")
            self.db.execute("UPDATE action_approvals SET state='consumed' WHERE id=?", (approval_id,))
            self.db.execute("UPDATE action_proposals SET state='dispatching' WHERE id=?", (proposal_id,))
            self._audit("dispatch_intent", proposalId=proposal_id, approvalId=approval_id)
        started = now()
        try:
            self._available()
            result = lab.set_mode(proposal["mode"], expected_etag=proposal["targetEtag"])
            status = "succeeded" if result["status"] in (200, 201, 204) else "failed" if result["status"] == 412 else "unknown_outcome"
            error = None if status == "succeeded" else "TARGET_STATE_CHANGED" if result["status"] == 412 else "RECONCILIATION_REQUIRED"
        except Exception:
            status, error = "unknown_outcome", "RECONCILIATION_REQUIRED"
        receipt = {"schemaVersion": "lab_action_receipt_v1", "proposalId": proposal_id,
                   "approvalId": approval_id, "status": status, "errorCode": error,
                   "startedAt": started, "endedAt": now(), "verification": "pending_independent_observer"}
        with self._transaction():
            self.db.execute("UPDATE action_proposals SET state=? WHERE id=?", (status, proposal_id))
            self._audit("receipt", **receipt)
        return receipt

    def reconcile(self, proposal_id, lab):
        if (getattr(lab, "lab_id", None), getattr(lab, "project_id", None), getattr(lab, "asset_id", None)) != ("openshield-lab", "lab", "lab_web"):
            raise ActionDenied("UNREGISTERED_LAB")
        proposal, _, state = self._proposal(proposal_id)
        observed = lab.config()
        with self._transaction():
            self._audit("reconciliation", proposalId=proposal_id, priorState=state,
                        observedEtag=observed["etag"])
        return {"proposalId": proposal_id, "priorState": state, "config": observed,
                "verification": "pending_independent_observer", "retryAuthorized": False}

    def kill(self):
        with self._transaction():
            self.db.execute("UPDATE action_settings SET value='1' WHERE name='killed'")
            self.db.execute("UPDATE action_approvals SET state='revoked' WHERE state='granted'")
            self._audit("kill_switch", actor=self.operator)
