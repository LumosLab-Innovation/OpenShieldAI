import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lab.anti_rea import AntiReaLab, verify, write_artifacts
from openshield.cli import main
from openshield.core import Store, Supervisor, utc_now, validate_event


class AntiReaIntegrationTests(unittest.TestCase):
    def test_real_http_trial_includes_honest_oracle_counterexample(self):
        result = verify()
        self.assertEqual(result["status"], "pass", result["checks"])
        self.assertEqual(len(result["checks"]), 16)
        self.assertTrue(result["checks"]["authorized_outputs_still_reveal_linear_formula"])
        self.assertEqual(result["aiBenefit"]["status"], "not_measured")

    def test_whole_static_release_is_exact_served_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = write_artifacts(Path(directory) / "releases")
            for protected, path in zip((False, True), paths):
                with AntiReaLab(protected=protected) as lab:
                    for file in path.iterdir():
                        status, body = lab.request("GET", "/" + file.name)
                        self.assertEqual(status, 200)
                        self.assertEqual(body, file.read_bytes())
            with self.assertRaises(FileExistsError):
                write_artifacts(Path(directory) / "releases")

    def test_cli_audit_exit_status_and_output_cannot_change_the_release(self):
        with tempfile.TemporaryDirectory() as directory:
            before, after = write_artifacts(Path(directory) / "releases")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["release-audit", str(before), "--authorized"]), 1)
                self.assertEqual(main(["release-audit", str(after), "--authorized"]), 0)
            with self.assertRaises(ValueError):
                main(["release-audit", str(after), "--authorized", "--output", str(after / "report.json")])
            self.assertFalse((after / "report.json").exists())
            with patch.object(Path, "resolve", side_effect=AssertionError("Remote operand resolved")):
                with self.assertRaises(ValueError):
                    main(["release-audit", "//not-local/share", "--authorized", "--output", str(Path(directory) / "report.json")])

    def test_minimized_exposure_fact_survives_runtime_without_claiming_attack(self):
        record = {"schemaVersion": "lab_event_v1", "id": "release_1", "projectId": "lab",
                  "caseId": "release_case", "assetId": "lab_web", "sourceId": "lab",
                  "observedAt": utc_now(), "kind": "release_exposure", "dataClass": "synthetic",
                  "facts": {"status": "blocked", "observationCount": 2, "gapCount": 0}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.sqlite3"
            store = Store(path)
            store.enroll("lab", "lab_web", "operator")
            store.ingest(record)
            result = Supervisor(store, mode="baseline").tick()[0]
            self.assertIn("control_gap", json.dumps(result))
            self.assertIn("needs_human", json.dumps(result))
            self.assertIn("insufficient_evidence", json.dumps(result))
            store.close()
            reopened = Store(path)
            self.assertEqual(reopened.case("lab", "release_case")["timeline"][0]["facts"], record["facts"])
            reopened.close()
        record["facts"]["rawSource"] = "not permitted"
        with self.assertRaises(ValueError):
            validate_event(record)


if __name__ == "__main__":
    unittest.main()
