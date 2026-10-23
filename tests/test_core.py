import copy
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from openshield.core import Store, Supervisor, baseline, utc_now, validate_analysis
from openshield.gateway import GatewayError


def event(event_id="event_1", kind="app_operation", facts=None, **changes):
    value = {"schemaVersion": "lab_event_v1", "id": event_id, "projectId": "project_lab",
             "caseId": "case_lab", "assetId": "asset_lab", "sourceId": "lab", "observedAt": utc_now(),
             "kind": kind, "facts": facts if facts is not None else {"authorized": True, "count": 1},
             "dataClass": "synthetic"}
    value.update(changes)
    return value


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "state.sqlite"
        self.store = Store(self.path)
        self.store.enroll("project_lab", "asset_lab", "operator_lab", allowed_actions=("set_site_ingress_mode",))

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def test_durable_exact_duplicate_and_conflicting_replay(self):
        item = event()
        self.assertTrue(self.store.ingest(item))
        self.assertFalse(self.store.ingest(item))
        changed = copy.deepcopy(item)
        changed["facts"]["count"] = 2
        with self.assertRaises(ValueError):
            self.store.ingest(changed)
        before = self.store.case("project_lab", "case_lab")
        self.store.close()
        self.store = Store(self.path)
        self.assertEqual(self.store.case("project_lab", "case_lab"), before)
        self.assertEqual(before["version"], 1)

    def test_atomic_batch_rejects_late_invalid_source_and_mixed_case(self):
        with self.assertRaises(ValueError):
            self.store.ingest_batch([event(), event("event_2", sourceId="not_enrolled")])
        self.assertEqual(self.store.cases(), [])
        with self.assertRaises(ValueError):
            self.store.ingest_batch([event(), event("event_2", caseId="other_case")])
        self.assertEqual(self.store.cases(), [])

    def test_expired_cross_project_and_immutable_scope(self):
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat().replace("+00:00", "Z")
        self.store.enroll("expired_project", "expired_asset", "operator_lab", expires_at=yesterday)
        with self.assertRaises(ValueError):
            self.store.ingest(event(projectId="expired_project", assetId="expired_asset"))
        with self.assertRaises(ValueError):
            self.store.ingest(event(projectId="other_project"))
        with self.assertRaises(ValueError):
            self.store.enroll("project_lab", "asset_lab", "other_operator")

    def test_strict_schema_types_secret_shapes_and_data_class(self):
        variants = [event(extra="ignore safety"), event(dataClass="restricted"),
                    event(facts={"authorized": True, "count": True}),
                    event(facts={"authorized": True, "count": -1}),
                    event(observedAt="2026-10-24T00:00:00"),
                    event(kind="shell", facts={"command": "ignored"}),
                    event("sk-proj-SYNTHETIC_REVIEW_CANARY"),
                    event(kind="auth_decision", facts={"decision": "allow", "subjectLabel": "ghp_SYNTHETIC_CANARY",
                                                     "objectLabel": "object_lab"})]
        for item in variants:
            with self.subTest(kind=item["kind"]), self.assertRaises(ValueError):
                self.store.ingest(item)
        self.assertEqual(self.store.cases(), [])

    def test_verified_effect_requires_enrolled_observer(self):
        facts = {"objective": "new_ingress_stopped", "result": "verified", "independent": True}
        with self.assertRaises(ValueError):
            self.store.ingest(event(kind="verification", facts=facts))
        self.store.enroll("observer_project", "observer_asset", "operator_lab", source_ids=("observer",),
                          source_roles={"observer": "observer"})
        self.assertTrue(self.store.ingest(event(kind="verification", facts=facts, projectId="observer_project",
                                               assetId="observer_asset", sourceId="observer")))

    def test_useful_rule_and_explicit_unknown_coverage(self):
        self.store.ingest(event(facts={"authorized": False, "count": 2}))
        snapshot = self.store.case("project_lab", "case_lab")
        result = baseline(snapshot)
        self.assertEqual(result["assessment"], "suspicious")
        self.assertEqual(result["nextAction"], "set_site_ingress_mode")
        self.assertFalse(snapshot["coverage"]["complete"])
        self.assertIn("unverified_effect", result["limitations"])

    def test_burst_never_grants_containment_and_unknown_input_is_unknown(self):
        for index in range(5):
            self.store.ingest(event(f"event_{index}", "waf_decision", {"decision": "deny", "category": "crs"}))
        result = baseline(self.store.case("project_lab", "case_lab"))
        self.assertEqual((result["assessment"], result["nextAction"]), ("suspicious", "observe"))

    def test_watermark_dedup_restart_and_visible_degraded_status(self):
        self.store.ingest(event())
        supervisor = Supervisor(self.store)
        result = supervisor.tick()[0]
        self.assertEqual(result["aiStatus"], "degraded_unconfigured")
        self.assertEqual(result["calls"], 0)
        self.assertEqual(supervisor.tick(), [])
        self.assertEqual(self.store.health()["supervisor"]["state"], "degraded_model")
        self.store.close()
        self.store = Store(self.path)
        self.assertEqual(Supervisor(self.store).tick(), [])
        self.store.ingest(event("event_2"))
        self.assertEqual(len(Supervisor(self.store).tick()), 1)
        self.assertEqual(Supervisor(self.store, mode="baseline").tick()[0]["aiStatus"], "not_requested")

    def test_model_failure_cannot_discard_case_or_fake_ai_success(self):
        class FailedGateway:
            route_hash = "test_gateway_failure"
            config = SimpleNamespace(global_token_limit=64000)

            def analyze(self, case, *, before_attempt, deadline):
                before_attempt(100)
                raise GatewayError("PROVIDER_UNAVAILABLE")

        self.store.ingest(event(facts={"authorized": False, "count": 1}))
        result = Supervisor(self.store, FailedGateway()).tick()[0]
        self.assertEqual(result["aiStatus"], "degraded_model")
        self.assertEqual(result["assessment"], "suspicious")
        self.assertEqual(result["calls"], 1)
        self.assertIn("model_unavailable", result["limitations"])
        self.assertEqual(self.store.case("project_lab", "case_lab")["version"], 1)

    def test_timer_freshness_transition_reviews_once_and_survives_restart(self):
        observed = datetime.now(timezone.utc)
        self.store.ingest(event(observedAt=observed.isoformat().replace("+00:00", "Z")))
        first = Supervisor(self.store, mode="baseline").tick()[0]
        self.assertNotIn("stale_evidence", first["limitations"])
        with patch("openshield.core.datetime", wraps=datetime) as clock:
            clock.now.return_value = observed + timedelta(seconds=301)
            second = Supervisor(self.store, mode="baseline").tick()[0]
            self.assertEqual(second["evidenceWatermark"], first["evidenceWatermark"])
            self.assertIn("stale_evidence", second["limitations"])
            self.assertEqual(Supervisor(self.store, mode="baseline").tick(), [])
            self.store.close()
            self.store = Store(self.path)
            self.assertEqual(Supervisor(self.store, mode="baseline").tick(), [])
            self.assertIn("stale_evidence", self.store.health()["source_asset_lab"]["gaps"])

    def test_replay_clock_keeps_enrollment_intake_and_freshness_reproducible(self):
        fixed = datetime(2026, 10, 24, 0, 1, tzinfo=timezone.utc)
        self.store.close()
        self.path = Path(self.temp.name) / "replay.sqlite"
        self.store = Store(self.path, clock=lambda: fixed)
        enrollment = self.store.enroll("project_lab", "asset_lab", "operator_lab")
        self.assertEqual(enrollment["expiresAt"], "2026-10-25T00:01:00Z")
        self.store.ingest(event(observedAt="2026-10-24T00:00:00Z"))
        first = self.store.case("project_lab", "case_lab")
        self.assertNotIn("stale_evidence", first["gaps"])
        self.assertNotIn("source_clock_skew", first["gaps"])
        self.assertEqual(first["timeline"][0]["ingestedAt"], "2026-10-24T00:01:00Z")
        self.store.close()
        with patch("openshield.core.datetime", wraps=datetime) as host_clock:
            host_clock.now.return_value = fixed + timedelta(days=365)
            self.store = Store(self.path, clock=lambda: fixed)
            self.assertEqual(self.store.case("project_lab", "case_lab"), first)

    def test_replay_clock_requires_aware_utc(self):
        for invalid in (datetime(2026, 10, 24), "2026-10-24T00:00:00Z",
                        datetime(2026, 10, 24, tzinfo=timezone(timedelta(hours=7)))):
            with self.subTest(clock=invalid), self.assertRaises(ValueError):
                Store(":memory:", clock=lambda: invalid)

    def test_two_cli_connections_racing_same_episode_call_provider_once(self):
        self.store.ingest(event())
        barrier = threading.Barrier(2)
        lock = threading.Lock()
        calls, results, errors = [], [], []

        class TestGateway:
            route_hash = "test_gateway_concurrent"
            config = SimpleNamespace(global_token_limit=64000)

            def analyze(self, case, *, before_attempt, deadline):
                before_attempt(100)
                with lock:
                    calls.append(1)
                return {"schemaVersion": "analysis_v1", "assessment": "insufficient_evidence", "hypotheses": [],
                        "nextAction": "observe", "evidenceIds": case["evidenceIds"],
                        "readRequests": [], "limitations": []}

        class RacingSupervisor(Supervisor):
            def _investigate(self, case, key, route):
                barrier.wait(timeout=5)
                return super()._investigate(case, key, route)

        def run():
            connection = Store(self.path)
            try:
                result = RacingSupervisor(connection, TestGateway()).tick()
                with lock:
                    results.extend(result)
            except Exception as error:
                errors.append(type(error).__name__)
            finally:
                connection.close()

        threads = [threading.Thread(target=run) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 1)
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM shield_episodes").fetchone()[0], 1)

    def test_global_budget_and_read_rounds_are_not_reset(self):
        class TestGateway:
            route_hash = "test_gateway_budget"
            config = SimpleNamespace(global_token_limit=199)

            def analyze(self, case, *, before_attempt, deadline):
                before_attempt(100)
                return {"schemaVersion": "analysis_v1", "assessment": "insufficient_evidence", "hypotheses": [],
                        "nextAction": "observe", "evidenceIds": case["evidenceIds"],
                        "readRequests": [{"catalogId": "recent_app_events", "limit": 1}], "limitations": []}

        self.store.ingest(event())
        result = Supervisor(self.store, TestGateway()).tick()[0]
        self.assertEqual(result["aiStatus"], "degraded_budget")
        self.assertEqual((result["calls"], result["tokens"]), (1, 100))
        self.assertEqual(Supervisor(self.store, TestGateway()).tick(), [])

    def test_output_unknown_references_actions_and_verdict_fields_rejected(self):
        self.store.ingest(event())
        case = self.store.case("project_lab", "case_lab")
        good = {"schemaVersion": "analysis_v1", "assessment": "insufficient_evidence", "hypotheses": [],
                "nextAction": "observe", "evidenceIds": ["event_1"], "readRequests": [], "limitations": []}
        for patch in ({"evidenceIds": ["other_case_event"]}, {"nextAction": "host_isolate"},
                      {"containment_verified": True},
                      {"readRequests": [{"catalogId": "arbitrary_url", "limit": 1}]},
                      {"hypotheses": [{"code": "unknown", "evidenceIds": []}]}):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                validate_analysis({**good, **patch}, case)


if __name__ == "__main__":
    unittest.main()
