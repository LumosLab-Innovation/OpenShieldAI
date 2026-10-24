import hashlib
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

from lab.anti_rea import AntiReaLab
from openshield.authority import Authority, AuthorityError


class DurableAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "authority.sqlite3"
        self.now = [100.0]
        self.authority = self.open()
        self.session = self.authority.issue_session()

    def open(self, **kwargs):
        return Authority(self.path, clock=lambda: self.now[0], **kwargs)

    def grant(self, authority=None, session=None, quantity=1):
        status, body = (authority or self.authority).operate("/api/grants", session or self.session, "", "quote-a", quantity)
        self.assertEqual(status, 201)
        return body["capability"]

    def quote(self, cap, authority=None, session=None, quantity=1):
        return (authority or self.authority).operate("/api/quote", session or self.session, cap, "quote-a", quantity)

    def test_reopen_preserves_grant_replay_and_principal_budget(self):
        cap = self.grant()
        reopened = self.open()
        self.assertEqual(self.quote(cap, reopened), (200, {"totalCents": 166}))
        self.assertEqual(self.quote(cap, self.open())[0], 403)
        for _ in range(3):
            reopened = self.open()
            session = reopened.issue_session()
            self.assertEqual(self.quote(self.grant(reopened, session), reopened, session)[0], 200)
        reopened = self.open()
        self.assertEqual(reopened.operate("/api/grants", reopened.issue_session(), "", "quote-a", 1)[0], 429)
        self.assertEqual(reopened.audit["accepted"], 4)

    def test_actual_fresh_process_retains_spend_and_rejects_replay(self):
        cap = self.grant()
        code = """import json,sys
from openshield.authority import Authority
data=json.load(sys.stdin)
authority=Authority(data['path'],clock=lambda:100.0)
print(json.dumps([authority.operate('/api/quote',data['session'],data['cap'],'quote-a',1)[0],authority.audit['accepted']]))
"""
        def child():
            result = subprocess.run([sys.executable, "-c", code],
                                    input=json.dumps({"path": str(self.path), "session": self.session, "cap": cap}),
                                    text=True, capture_output=True, timeout=10,
                                    cwd=Path(__file__).resolve().parents[1])
            self.assertEqual(result.returncode, 0)
            self.assertNotIn(self.session, result.stdout + result.stderr)
            self.assertNotIn(cap, result.stdout + result.stderr)
            return json.loads(result.stdout)
        self.assertEqual(child(), [200, 1])
        self.assertEqual(child(), [403, 1])
        self.assertEqual(self.open().audit["accepted"], 1)

    def test_independent_instances_consume_once_and_share_last_quota_slot(self):
        first, second = self.open(), self.open()
        cap = self.grant()
        with ThreadPoolExecutor(max_workers=8) as pool:
            statuses = list(pool.map(lambda i: self.quote(cap, first if i % 2 else second)[0], range(8)))
        self.assertEqual(statuses.count(200), 1)
        self.assertEqual(statuses.count(403), 7)
        for _ in range(2):
            self.assertEqual(self.quote(self.grant())[0], 200)
        caps = [self.grant(first), self.grant(second)]
        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = list(pool.map(lambda item: self.quote(item[1], item[0])[0], zip((first, second), caps)))
        self.assertEqual(sorted(statuses), [200, 429])
        self.assertEqual(self.open().audit["accepted"], 4)

    def test_parameter_and_session_tamper_does_not_consume_capability(self):
        cap = self.grant(quantity=2)
        other = self.authority.issue_session()
        self.assertEqual(self.quote(cap, quantity=1)[0], 403)
        self.assertEqual(self.quote(cap, session=other, quantity=2)[0], 403)
        self.assertEqual(self.authority.operate("/api/quote", self.session, cap, "quote-b", 2)[0], 403)
        self.assertEqual(self.quote(cap, quantity=2), (200, {"totalCents": 303}))
        self.assertEqual(self.authority.audit["accepted"], 1)

    def test_expiry_boundary_and_durable_clock_rollback_fail_closed(self):
        cap = self.grant()
        self.now[0] = 130
        self.assertEqual(self.quote(cap)[0], 403)
        self.now[0] = 129
        with self.assertRaises(AuthorityError):
            self.quote(cap)
        with self.assertRaises(AuthorityError):
            self.open()
        self.now[0] = 130
        self.assertEqual(self.quote(cap)[0], 403)
        self.assertEqual(self.open().audit["accepted"], 0)

    def test_revocation_invalidates_outstanding_grant_after_restart(self):
        cap = self.grant()
        self.assertTrue(self.open().revoke_session(self.session))
        self.assertFalse(self.authority.revoke_session(self.session))
        self.assertEqual(self.quote(cap, self.open())[0], 403)
        self.assertEqual(self.open().operate("/api/grants", self.session, "", "quote-a", 1)[0], 403)
        self.assertEqual(self.authority.audit["accepted"], 0)

    def test_no_plaintext_credentials_in_database_or_journal(self):
        cap = self.grant()
        self.assertEqual(self.quote(cap)[0], 200)
        raw = b"".join(path.read_bytes() for path in Path(self.temp.name).iterdir())
        for token in (self.session, cap):
            self.assertNotIn(token.encode(), raw)
        self.assertIn(hashlib.sha256(self.session.encode()).hexdigest().encode(), raw)

    def test_policy_configuration_cannot_reset_or_change_existing_budget(self):
        self.assertEqual(self.quote(self.grant())[0], 200)
        for settings in ({"quota": 5}, {"grant_ttl": 31}):
            with self.subTest(settings=settings), self.assertRaises(AuthorityError):
                self.open(**settings)
        self.assertEqual(self.open().audit["accepted"], 1)

    def test_row_limits_and_expired_grant_cleanup_are_bounded(self):
        for _ in range(63):
            self.authority.issue_session()
        with self.assertRaises(ValueError):
            self.authority.issue_session()
        for _ in range(64):
            self.grant()
        self.assertEqual(self.authority.operate("/api/grants", self.session, "", "quote-a", 1)[0], 429)
        self.now[0] += 30
        self.grant()
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM grants").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT count(*) FROM sessions").fetchone()[0], 64)

    def test_unavailable_deleted_empty_and_corrupt_state_never_reinitializes(self):
        self.path.unlink()
        with self.assertRaises(AuthorityError):
            self.grant()
        self.assertFalse(self.path.exists())
        for raw in (b"", b"SYNTHETIC CORRUPT DATABASE"):
            self.path.write_bytes(raw)
            with self.subTest(raw=bool(raw)), self.assertRaises(AuthorityError):
                self.open()

    def test_database_lock_fails_closed_without_grant_or_spend(self):
        cap = self.grant()
        with closing(sqlite3.connect(self.path, isolation_level=None)) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                with self.assertRaises(AuthorityError):
                    self.quote(cap)
            finally:
                db.rollback()
        self.assertEqual(self.quote(cap)[0], 200)

    def test_nonfinite_clock_and_boolean_config_rejected(self):
        for value in (True, float("nan"), float("inf"), -1, "100"):
            with self.subTest(clock=repr(value)), self.assertRaises(AuthorityError):
                Authority(self.path, clock=lambda: value)
        for value in (True, float("nan"), float("inf"), 0, 61):
            with self.subTest(ttl=repr(value)), self.assertRaises(ValueError):
                self.open(grant_ttl=value)

    def test_http_restart_revocation_and_state_failure_are_actual_denials(self):
        self.now[0] = 100
        with AntiReaLab(state_path=self.path, clock=lambda: self.now[0]) as first:
            session = first.issue_session()
            operation = {"object": "quote-a", "quantity": 1}
            status, grant = first.request("POST", "/api/grants", operation, session)
            self.assertEqual(status, 201)
        with AntiReaLab(state_path=self.path, clock=lambda: self.now[0]) as second:
            self.assertTrue(second.revoke_session(session))
            self.assertEqual(second.request("POST", "/api/quote", operation, session, grant["capability"])[0], 403)
            self.assertEqual(second.request("POST", "/api/revoke", operation, session)[0], 404)
            fresh = second.issue_session()
            self.path.write_bytes(b"SYNTHETIC CORRUPT DATABASE")
            self.assertEqual(second.request("POST", "/api/grants", operation, fresh),
                             (503, {"error": "authority_unavailable"}))


if __name__ == "__main__":
    unittest.main()
