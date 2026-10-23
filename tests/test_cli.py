"""Exercise the local CLI through real SQLite; no model or Docker required."""

import contextlib
import io
import json
import tempfile
import unittest
import copy
from pathlib import Path

from openshield.cli import main, read_events
from openshield.core import utc_now
from openshield.lab_trial import check_report
from openshield.evaluation import fingerprint


class CLIIntegration(unittest.TestCase):
    def test_evaluation_source_hash_is_stable_across_windows_and_linux(self):
        with tempfile.TemporaryDirectory() as directory:
            first, second = Path(directory) / "lf.py", Path(directory) / "crlf.py"
            first.write_bytes(b"line1\nline2\n")
            second.write_bytes(b"line1\r\nline2\r\n")
            self.assertEqual(fingerprint(first), fingerprint(second))

    def test_enroll_import_and_restart_dedup_via_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.db"
            fixture = Path(directory) / "input.jsonl"
            fixture.write_text(json.dumps({"schemaVersion": "lab_event_v1", "id": "e1",
                "projectId": "lab", "caseId": "case1", "assetId": "lab_web", "sourceId": "lab",
                "observedAt": utc_now(), "kind": "app_operation", "dataClass": "synthetic",
                "facts": {"authorized": False, "count": 1}}), encoding="utf-8")

            def invoke(*args):
                stream = io.StringIO()
                with contextlib.redirect_stdout(stream):
                    self.assertEqual(main(["--state", str(state), *args]), 0)
                return json.loads(stream.getvalue())

            enrolled = invoke("init", "--enable-lab-actions")
            self.assertEqual(enrolled["allowedActions"], ["set_site_ingress_mode"])
            self.assertEqual(invoke("ingest", str(fixture))["accepted"], [True])
            result = invoke("tick", "--mode", "baseline")["results"][0]
            self.assertEqual((result["assessment"], result["calls"]), ("suspicious", 0))
            self.assertEqual(invoke("tick", "--mode", "baseline")["results"], [])
            self.assertEqual(len(invoke("status")["cases"]), 1)

    def test_duplicate_json_fields_rejected_before_schema_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "input.jsonl"
            fixture.write_text('{"projectId":"outside","projectId":"lab"}', encoding="utf-8")
            with self.assertRaises(ValueError):
                read_events(fixture)

    def test_record_grader_rejects_harm_even_when_proxy_says_403(self):
        evidence = Path(__file__).resolve().parents[1] / "docs/lab/evidence"
        report = {"prevention": json.loads((evidence / "prevention.json").read_text()),
                  "activeResponse": json.loads((evidence / "response.json").read_text()),
                  "recovery": json.loads((evidence / "recovery.json").read_text()),
                  "approvedRuntimeResponse": json.loads((evidence / "approved-runtime-response.json").read_text())}
        self.assertTrue(all(check_report(report).values()))
        changed = copy.deepcopy(report)
        row = next(row for row in changed["prevention"]["rows"] if row["mode"] == "on" and row["synthetic_harm"])
        row["harm_delta"] = 1
        self.assertFalse(check_report(changed)["planted_prevention_and_legitimate_requests"])
