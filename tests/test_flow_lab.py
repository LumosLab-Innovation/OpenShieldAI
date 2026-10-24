"""Exercise the fixed Go HTTP effects binary, without a provider or target arguments."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("go"), "Go compiler is unavailable")
class FlowLabIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.temp.name) / ("shield-flow-lab.exe" if os.name == "nt" else "shield-flow-lab")
        env = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off")
        result = subprocess.run(["go", "build", "-trimpath", "-o", str(cls.binary), "./cmd/shield-flow-lab"],
                                cwd=ROOT / "runtime-go", env=env, capture_output=True, timeout=60)
        if result.returncode:
            cls.temp.cleanup()
            raise AssertionError("Fixed flow lab did not compile")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_actual_unsafe_protected_and_benign_effects(self):
        run = subprocess.run([str(self.binary)], capture_output=True, timeout=20)
        self.assertEqual(run.returncode, 0)
        self.assertFalse(run.stderr)
        self.assertLess(len(run.stdout), 64 * 1024)
        report = json.loads(run.stdout)
        self.assertEqual(report["schemaVersion"], "flow_lab_v1")
        self.assertEqual(report["status"], "passed")
        self.assertEqual(len(report["checks"]), 48)
        self.assertTrue(all(item["passed"] for item in report["checks"]))
        self.assertEqual(report["negativeControlEffects"], {"reads": 4, "charges": 3, "chargedUnits": 3})
        self.assertEqual(report["protectedForbiddenEffects"], {"reads": 0, "charges": 0, "chargedUnits": 0})
        self.assertEqual(report["protectedAllowedEffects"], {"reads": 2, "charges": 2, "chargedUnits": 2})
        self.assertEqual(report["negativeControlOutsideDeliveries"], 2)
        self.assertEqual(report["protectedOutsideRequests"], 0)
        self.assertEqual(report["protectedAllowedDeliveries"], 1)
        self.assertEqual(report["idempotentConcurrentCommits"], 1)
        self.assertEqual(report["modelCalls"], 0)
        self.assertFalse(report["productionActions"])
        self.assertEqual({item["caseId"] for item in report["observations"]}, {"I1", "I2", "W3", "W4_D4"})
        for value in (b"127.0.0.1", b"X-Flow-", b"http://", b"synthetic_alpha", b"synthetic_beta"):
            self.assertNotIn(value, run.stdout)

    def test_arbitrary_target_argument_fails_before_lab(self):
        run = subprocess.run([str(self.binary), "--target", "http://127.0.0.1:1"], capture_output=True, timeout=5)
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(json.loads(run.stdout), {"schemaVersion": "flow_lab_v1", "status": "failed", "errorCode": "INVALID_ARGUMENTS"})
        self.assertFalse(run.stderr)
