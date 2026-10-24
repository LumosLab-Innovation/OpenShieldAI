"""Aggregate-report gates with labeled test doubles; no fixture server is started."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


SPEC = importlib.util.spec_from_file_location("parallel_defense_gate_under_test", Path(__file__).with_name("check_parallel_defense.py"))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def tool_report():
    return {"schemaVersion": "tool_guard_trial_v1", "status": "passed", "modelCalls": 0,
            "productionActions": False, "checks": [{"code": "synthetic_test_double", "passed": True}],
            "negativeControlEffects": {"reads": 0, "marks": 1, "deliveries": 1},
            "negativeControlOutsideRecipientDeliveries": 1,
            "protectedForbiddenEffects": {"reads": 0, "marks": 0, "deliveries": 0},
            "protectedAllowedEffects": {"reads": 9, "marks": 1, "deliveries": 1},
            "concurrentAccepted": 1}


class ParallelReportGateTests(unittest.TestCase):
    def setUp(self):
        self.anti = Mock(return_value={"status": "pass", "checks": {"test_double": True}})
        self.durable = Mock(return_value={"status": "pass", "checks": {"test_double": True}})
        self.delivery = Mock(return_value={"status": "pass", "cases": [{"passed": True}]})
        self.trial_patch = patch.multiple(MODULE, anti_rea_trial=self.anti,
                                          durable_trial=self.durable, delivery_trial=self.delivery)
        self.trial_patch.start()
        self.addCleanup(self.trial_patch.stop)

    def invoke(self, report=None, **process):
        result = SimpleNamespace(returncode=0, stderr=b"", stdout=json.dumps(tool_report() if report is None else report).encode())
        for key, value in process.items():
            setattr(result, key, value)
        with patch.object(MODULE.subprocess, "run", return_value=result), patch.object(Path, "read_bytes", return_value=b"synthetic_binary_test_double"):
            return MODULE.verify()

    def no_trials(self):
        self.anti.assert_not_called()
        self.durable.assert_not_called()
        self.delivery.assert_not_called()

    def test_denied_everything_and_stale_controls_cannot_start_other_trials(self):
        mutations = {
            "schemaVersion": "old_tool_schema",
            "status": "failed",
            "modelCalls": 1,
            "productionActions": True,
            "checks": [{"code": "synthetic_test_double", "passed": False}],
            "negativeControlEffects": {"reads": 0, "marks": 0, "deliveries": 0},
            "negativeControlOutsideRecipientDeliveries": 0,
            "protectedForbiddenEffects": {"reads": 0, "marks": 1, "deliveries": 0},
            "protectedAllowedEffects": {"reads": 0, "marks": 0, "deliveries": 0},
            "concurrentAccepted": 2,
        }
        for field, value in mutations.items():
            report = copy.deepcopy(tool_report())
            report[field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                self.invoke(report)
            self.no_trials()

    def test_invalid_process_output_cannot_start_other_trials(self):
        for process in ({"returncode": 1}, {"stderr": b"SYNTHETIC_PROCESS_ERROR"},
                        {"stdout": b"x" * 65537}, {"stdout": b"{"}):
            with self.subTest(fields=tuple(process)), self.assertRaises((RuntimeError, ValueError)):
                self.invoke(**process)
            self.no_trials()

    def test_accepted_typed_test_double_runs_all_trials_and_records_hashes(self):
        result = self.invoke()
        self.assertEqual(result["status"], "pass")
        self.anti.assert_called_once_with()
        self.durable.assert_called_once_with()
        self.delivery.assert_called_once_with()
        self.assertEqual(result["goBinarySha256"], hashlib.sha256(b"synthetic_binary_test_double").hexdigest())
        self.assertEqual(len(result["sourceTreeSha256"]), 64)
        self.assertEqual(result["aiBenefit"]["status"], "not_measured")

    def test_an_individual_trial_failure_cannot_be_promoted_to_aggregate_success(self):
        self.delivery.return_value = {"status": "pass", "cases": [{"passed": False}]}
        self.assertEqual(self.invoke()["status"], "failed")


if __name__ == "__main__":
    unittest.main()
