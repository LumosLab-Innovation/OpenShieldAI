import contextlib
import io
import json
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from openshield import correlation
from openshield.cli import main
from openshield.core import Store, Supervisor


class CorrelationIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "state.sqlite", clock=lambda: datetime(2026, 10, 24, 3, 1, tzinfo=timezone.utc))
        self.store.enroll("project_a", "asset_a", "operator_a", source_ids=("source_a",))
        for index in range(5):
            self.store.ingest({"schemaVersion": "lab_event_v1", "id": f"event_{index}", "projectId": "project_a",
                               "caseId": "case_a", "assetId": "asset_a", "sourceId": "source_a", "kind": "auth_decision",
                               "observedAt": "2026-10-24T03:00:30Z", "dataClass": "synthetic",
                               "facts": {"decision": "deny", "subjectLabel": "subject_a", "objectLabel": "object_a"}})

    def tearDown(self):
        self.store.close(); self.temp.cleanup()

    def test_actual_worker_replay_and_store_restart(self):
        result = correlation.correlate(self.store, "project_a", "case_a")
        self.assertEqual(result["candidates"][0]["code"], "repeated_access_denials")
        self.assertIn("upstream_no_independent_observer", result["coverage"]["gaps"])
        self.assertFalse(result["isFinding"])
        path = self.store.db.execute("PRAGMA database_list").fetchone()[2]
        clock = self.store.clock
        self.store.close(); self.store = Store(path, clock=clock)
        self.assertEqual(correlation.correlate(self.store, "project_a", "case_a"), result)

    def test_catalog_uses_original_snapshot_and_respects_result_limit(self):
        snapshot = self.store.case("project_a", "case_a")
        event = {key: value for key, value in snapshot["timeline"][0].items() if key not in {"ingestedAt", "sourceTrust", "sourceRole"}}
        self.store.ingest({**event, "id": "later", "observedAt": "2026-10-24T03:00:59Z", "facts": {**event["facts"], "decision": "allow"}})
        read = Supervisor(self.store)._reads(snapshot, [{"catalogId": "access_patterns", "limit": 1}])[0]
        self.assertEqual([item["code"] for item in read["candidates"]], ["repeated_access_denials"])
        self.assertNotIn("later", json.dumps(read))

    def test_gateway_catalog_roundtrip_and_missing_worker_is_degraded_tool(self):
        class CatalogDouble:
            route_hash = "synthetic_catalog_test_double"
            config = SimpleNamespace(global_token_limit=64000)
            contexts = []

            def analyze(self, case, *, before_attempt, deadline):
                before_attempt(100)
                self.contexts.append(case)
                return {"schemaVersion": "analysis_v1", "assessment": "insufficient_evidence", "hypotheses": [],
                        "evidenceIds": case["evidenceIds"], "nextAction": "needs_human", "limitations": [],
                        "readRequests": [] if "catalogObservations" in case else [{"catalogId": "access_patterns", "limit": 1}]}

        gateway = CatalogDouble()
        first = Supervisor(self.store, gateway).tick()[0]
        self.assertEqual(first["aiStatus"], "succeeded")
        self.assertEqual(first["calls"], 2)
        self.assertFalse(gateway.contexts[-1]["catalogObservations"][0]["isFinding"])
        gateway.route_hash = "synthetic_missing_worker_test_double"
        with patch.object(correlation, "BINARY", Path(self.temp.name) / "missing"):
            second = Supervisor(self.store, gateway).tick()[0]
        self.assertEqual(second["aiStatus"], "degraded_tool")
        self.assertIn("incomplete_evidence", second["limitations"])
        self.assertEqual(self.store.health()["supervisor"]["state"], "degraded_observation")

    def test_parent_deadline_and_output_limit_use_real_hostile_child(self):
        original = subprocess.Popen
        for script in ("import time; time.sleep(10)", "import os; os.write(1,b'X'*70000)"):
            def child(*_args, **kwargs):
                return original([sys.executable, "-c", script], **kwargs)
            request = correlation.request_for(self.store.case("project_a", "case_a"), self.store.enrollment("project_a", "asset_a"), self.store._utc_now())
            started = time.monotonic()
            with patch.object(correlation.subprocess, "Popen", side_effect=child):
                with self.assertRaises(correlation.CorrelationError):
                    correlation.run(request)
            self.assertLess(time.monotonic() - started, 3)

    def test_registered_corpus_rule_consistency_is_not_attack_accuracy(self):
        corpus = json.loads(Path("tests/fixtures/access_correlation_cases.json").read_text(encoding="utf-8"))
        for case in corpus["cases"]:
            result = correlation.run(case["input"])
            truth = case["truth"]
            self.assertEqual(sorted({item["code"] for item in result["candidates"]}), sorted(truth["expectedCandidateCodes"]), case["id"])
            self.assertTrue(set(truth["expectedGaps"]) <= set(result["coverage"]["gaps"]), case["id"])

    def test_cli_reads_case_without_writes_or_new_authority(self):
        path = self.store.db.execute("PRAGMA database_list").fetchone()[2]
        before = self.store.case("project_a", "case_a")["version"]
        with contextlib.redirect_stdout(io.StringIO()) as capture:
            self.assertEqual(main(["--state", path, "correlate", "case_a", "--project", "project_a"]), 0)
        self.assertFalse(json.loads(capture.getvalue())["isFinding"])
        self.assertEqual(self.store.case("project_a", "case_a")["version"], before)
        for suffix in ("", "-wal", ".actions"):
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                main(["--state", path, "correlate", "case_a", "--project", "project_a", "--output", path + suffix])
        self.assertEqual(self.store.case("project_a", "case_a")["version"], before)


if __name__ == "__main__":
    unittest.main()
