"""Delivery integration contracts: real fixtures, safe CLI output and total deadline."""

import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from lab.anti_rea import _exports, write_artifacts
from lab.delivery import DeliveryLab
from openshield.cli import main
from openshield.delivery import delivery_audit


class DeliveryIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        _, self.reference = write_artifacts(self.root / "releases")

    def tearDown(self):
        self.directory.cleanup()

    def arguments(self, url, *extra):
        return ["delivery-audit", str(self.reference), "--base-url", url, "--authorized",
                "--retired-path", "/retired/app.js.map", *extra]

    def test_delivery_lab_cli_executes_all_thirteen_real_http_modes(self):
        destination = self.root / "delivery-trial.json"
        captured = io.StringIO()
        with patch("openshield.cli.Store") as store, contextlib.redirect_stdout(captured):
            status = main(["delivery-lab", "--output", str(destination)])
        self.assertEqual(status, 0)
        store.assert_not_called()
        result = json.loads(destination.read_text(encoding="utf-8"))
        summary = json.loads(captured.getvalue())
        self.assertEqual(summary["cases"], 13)
        self.assertEqual(result["schemaVersion"], "delivery_lab_v1")
        self.assertTrue(result["synthetic"])
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["aiBenefit"]["status"], "not_measured")
        expected = {"clean": "pass", "gzip": "pass", "map_header": "blocked", "stale_gzip": "blocked",
                    "retired_map": "blocked", "retired_gzip": "blocked", "retired_fallback": "blocked",
                    "root_mismatch": "blocked", "redirect": "partial", "gzip_bomb": "partial",
                    "truncated_gzip": "partial", "multi_gzip": "partial", "brotli": "partial"}
        self.assertEqual({case["case"]: case["result"]["status"] for case in result["cases"]}, expected)
        self.assertTrue(all(case["passed"] for case in result["cases"]))
        commitments = {case["result"]["referenceSha256"] for case in result["cases"]}
        self.assertEqual(len(commitments), 1)
        self.assertNotIn(None, commitments)
        for case in result["cases"]:
            report = case["result"]
            self.assertTrue(report["networkRequestsMade"])
            self.assertFalse(report["targetCodeExecuted"])
            self.assertFalse(report["isFinding"])
            if report["status"] == "pass":
                self.assertTrue(report["complete"])
                self.assertEqual(report["counts"]["retiredProbes"], 2)
            if report["status"] == "partial":
                self.assertFalse(report["complete"])
                self.assertGreater(report["counts"]["gaps"], 0)
        serialized = json.dumps(result)
        self.assertNotIn("SYNTHETIC_PRIVATE_RULE_V1", serialized)
        self.assertNotIn("http://127.0.0.1:", serialized)

    def test_cli_rejects_output_inside_reference_before_http(self):
        destination = self.reference / "report.json"
        before = {path.name: path.read_bytes() for path in self.reference.iterdir()}
        with patch("openshield.delivery.delivery_audit", side_effect=AssertionError("HTTP audit started")):
            with self.assertRaises(ValueError):
                main(self.arguments("http://127.0.0.1:1", "--output", str(destination)))
        self.assertFalse(destination.exists())
        self.assertEqual({path.name: path.read_bytes() for path in self.reference.iterdir()}, before)

    def test_cli_rejects_remote_reference_before_path_resolution(self):
        with patch.object(Path, "resolve", side_effect=AssertionError("Remote reference resolved")):
            with self.assertRaises(ValueError):
                main(["delivery-audit", "//unowned.invalid/share", "--base-url", "http://127.0.0.1:1",
                      "--authorized", "--output", str(self.root / "report.json")])

    def test_cli_writes_external_json_and_returns_failure_on_observed_drift(self):
        destination = self.root / "reports" / "audit.json"
        with DeliveryLab("root_mismatch") as lab, contextlib.redirect_stdout(io.StringIO()):
            status = main(self.arguments(lab.url, "--output", str(destination)))
        result = json.loads(destination.read_text(encoding="utf-8"))
        self.assertEqual(status, 1)
        self.assertEqual(result["status"], "blocked")
        self.assertGreater(result["counts"]["observations"], 0)
        self.assertEqual(list(destination.parent.glob(".shield-report-*")), [])

    def test_external_hardlinked_report_cannot_overwrite_reference_bytes(self):
        source, destination = self.reference / "app.js", self.root / "report.json"
        original = source.read_bytes()
        os.link(source, destination)
        with contextlib.redirect_stdout(io.StringIO()):
            status = main(self.arguments("http://127.0.0.1:1", "--output", str(destination)))
        self.assertEqual(status, 1)
        self.assertEqual(source.read_bytes(), original)
        report = json.loads(destination.read_text(encoding="utf-8"))
        self.assertNotEqual(report["status"], "pass")
        self.assertFalse(report["networkRequestsMade"])
        self.assertEqual(source.stat().st_nlink, 1)

    def test_bounded_details_preserve_real_observation_counts(self):
        with DeliveryLab("map_header") as lab:
            result = delivery_audit(self.reference, lab.url, authorized=True, limits={"observations": 1})
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(len(result["observations"]), 1)
        self.assertEqual(result["counts"]["observations"], 2)
        self.assertEqual(result["counts"]["observationDetailsOmitted"], 1)

    def test_total_deadline_interrupts_a_continuously_trickled_response(self):
        stop, received = threading.Event(), threading.Event()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                received.set()
                body = _exports(True)["/"]
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    for byte in body:
                        if stop.wait(.04):
                            break
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                except (OSError, ConnectionError):
                    pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            started = time.monotonic()
            result = delivery_audit(self.reference, f"http://127.0.0.1:{server.server_port}",
                                    authorized=True, limits={"seconds": .5})
            duration = time.monotonic() - started
            self.assertTrue(received.is_set(), result)
            self.assertLess(duration, 2, f"Configured half-second deadline took {duration:.3f}s")
            self.assertEqual(result["status"], "partial", result)
            self.assertFalse(result["complete"])
            self.assertGreater(result["counts"]["gaps"], 0)
            self.assertEqual(result["counts"]["requested"], 1)
        finally:
            stop.set()
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
