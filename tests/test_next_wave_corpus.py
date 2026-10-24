"""Public corpus conversion uses actual lab effects; labels never reach input.events."""

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from lab.next_wave_corpus import build_corpus
from lab.promotion import verify as promotion_trial
from lab.recovery_readiness import verify as recovery_trial
from openshield.core import validate_event
from openshield.evaluation import compare


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("go"), "Go compiler required for actual source effect report")
class NextWaveCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / ("flow.exe" if os.name == "nt" else "flow")
            env = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off")
            build = subprocess.run(["go", "build", "-trimpath", "-o", str(binary), "./cmd/shield-flow-lab"],
                                   cwd=ROOT / "runtime-go", env=env, capture_output=True, timeout=60)
            if build.returncode:
                raise AssertionError("Fixed effect lab did not compile")
            run = subprocess.run([str(binary)], capture_output=True, timeout=20)
            if run.returncode or len(run.stdout) > 65536:
                raise AssertionError("Actual fixed effect lab failed")
            cls.flow = json.loads(run.stdout)
        cls.promotion = promotion_trial()
        cls.recovery = recovery_trial()
        cls.corpus = build_corpus(cls.flow, cls.promotion, cls.recovery)

    def test_deterministic_shuffled_unique_and_validated_inputs(self):
        self.assertEqual(self.corpus, build_corpus(self.flow, self.promotion, self.recovery))
        registration = self.corpus["registration"]
        self.assertEqual(registration["evaluationClass"], "public_engineering_regression_not_heldout")
        self.assertEqual(registration["allowedActions"], [])
        self.assertEqual(registration["replayClockUTC"], "2026-10-24T00:42:00Z")
        self.assertEqual(len(self.corpus["cases"]), 16)
        ids, event_ids = set(), set()
        for case in self.corpus["cases"]:
            self.assertNotIn(case["id"], ids)
            ids.add(case["id"])
            self.assertRegex(case["id"], r"^c_[0-9a-f]{24}$")
            self.assertEqual(set(case["input"]), {"events"})
            for event in case["input"]["events"]:
                self.assertEqual(validate_event(event), event)
                self.assertEqual(event["caseId"], case["id"])
                self.assertEqual((event["projectId"], event["assetId"]), ("p_eval", "a_eval"))
                self.assertNotIn(event["id"], event_ids)
                event_ids.add(event["id"])
            serialized = json.dumps(case["input"])
            for marker in (case["scenario"], case["group"], "truth", "supported", "provenance", "unsafe", "stolen"):
                self.assertNotIn(marker, serialized)
        self.assertNotEqual([case["id"] for case in self.corpus["cases"]], sorted(ids))
        self.assertLess(len(json.dumps(self.corpus)), 100_000)

    def test_effect_counts_are_report_observations_not_baseline_labels(self):
        by_name = {case["scenario"]: case for case in self.corpus["cases"]}
        observations = {item["id"]: item["facts"] for item in self.flow["observations"]}
        expected = {
            "Cross-tenant synthetic object bytes observed": observations["fact_object_transaction"]["unsafeCrossTenantReads"],
            "Excess duplicate transaction commit": observations["fact_object_transaction"]["unsafeDuplicateCharges"] - 1,
            "Revoked session allowed by cached verifier": observations["fact_session_verifiers"]["unsafeCachedPathReadsAfterRevocation"],
            "Synthetic body arrived at forbidden receiver": self.flow["negativeControlOutsideDeliveries"],
        }
        for name, count in expected.items():
            case = by_name[name]
            self.assertEqual(case["truth"]["incident"], "supported")
            self.assertEqual(case["input"]["events"][0]["facts"], {"authorized": False, "count": count})
        stale = by_name["Origin updated while the declared edge still delivers private canaries"]
        self.assertEqual([event["facts"]["status"] for event in stale["input"]["events"]], ["pass", "blocked"])
        self.assertEqual(stale["input"]["events"][1]["facts"]["observationCount"],
                         self.promotion["phases"]["edge_without_explicit_purge"]["privateCanaryDeliveries"])
        self.assertEqual(stale["truth"]["requiredHypotheses"], ["control_gap"])

    def test_holder_pair_is_observably_identical_and_both_unknown(self):
        pair = [case for case in self.corpus["cases"] if case["group"] == "identifiability_pair"]
        self.assertEqual(len(pair), 2)
        self.assertEqual({case["truth"]["incident"] for case in pair}, {"unknown"})
        inputs = [[{key: value for key, value in event.items() if key not in {"id", "caseId"}}
                   for event in case["input"]["events"]] for case in pair]
        self.assertEqual(inputs[0], inputs[1])
        self.assertNotEqual(pair[0]["provenance"]["withheldHypothesis"], pair[1]["provenance"]["withheldHypothesis"])
        self.assertTrue(all("withheldHypothesis" not in json.dumps(case["input"]) for case in pair))

    def test_no_invented_key_or_independent_backup_observation(self):
        self.assertNotIn("keyAvailable", json.dumps([case["input"] for case in self.corpus["cases"]]))
        restore_cases = [case for case in self.corpus["cases"] if case["group"] == "recovery_gap"]
        self.assertEqual(len(restore_cases), 3)
        for case in restore_cases:
            event = case["input"]["events"][0]
            self.assertEqual(event["kind"], "verification")
            self.assertEqual(event["facts"]["result"], "not_verified")
            self.assertEqual(case["truth"]["requiredHypotheses"], ["recovery_gap"])
            if case["scenario"].endswith("no_backup"):
                self.assertFalse(event["facts"]["independent"])
                self.assertEqual(event["sourceId"], "lab")
            else:
                self.assertTrue(event["facts"]["independent"])
                self.assertEqual(event["sourceId"], "observer")

    def test_failed_unchecked_or_inconsistent_source_report_is_rejected(self):
        for position in range(3):
            for field, value in (("status", "failed"), ("dataClass", "restricted"),
                                 ("productionActions", True), ("modelCalls", 1), ("modelCalls", False)):
                reports = copy.deepcopy([self.flow, self.promotion, self.recovery])
                reports[position][field] = value
                with self.assertRaises(ValueError):
                    build_corpus(*reports)
            reports = copy.deepcopy([self.flow, self.promotion, self.recovery])
            reports[position]["checks"][0]["passed"] = False
            with self.assertRaises(ValueError):
                build_corpus(*reports)
        flow = copy.deepcopy(self.flow)
        flow["negativeControlOutsideDeliveries"] += 1
        with self.assertRaises(ValueError):
            build_corpus(flow, self.promotion, self.recovery)
        recovery = copy.deepcopy(self.recovery)
        next(case for case in recovery["cases"] if case["caseId"] == "business_inconsistent")["outcomeCode"] = "APPLICATION_INVARIANTS_PASSED"
        with self.assertRaises(ValueError):
            build_corpus(self.flow, self.promotion, recovery)

    def test_evaluator_receives_only_minimized_inputs_and_zero_action_authority(self):
        class BoundaryDouble:
            config = SimpleNamespace(global_token_limit=64000, provider="test_double", model="test_double")
            route_hash = "synthetic_boundary_test_only"
            last_metadata = None

            def __init__(self):
                self.contexts = []

            def analyze(self, case, *, before_attempt, deadline):
                before_attempt(10)
                self.contexts.append(copy.deepcopy(case))
                return {"schemaVersion": "analysis_v1", "assessment": "insufficient_evidence", "hypotheses": [],
                        "nextAction": "observe", "evidenceIds": case["evidenceIds"], "readRequests": [],
                        "limitations": ["synthetic_lab_only"]}

        gateway = BoundaryDouble()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "public-regression.json"
            path.write_text(json.dumps(self.corpus), encoding="utf-8")
            result = compare(path, gateway)
        self.assertEqual(result["manifest"]["evaluationClass"], "public_engineering_regression_not_heldout")
        self.assertEqual(result["manifest"]["allowedActions"], [])
        self.assertEqual(len(gateway.contexts), 16)
        for context in gateway.contexts:
            self.assertEqual(context["allowedActions"], [])
            for marker in ("scenario", "truth", "provenance", "withheldHypothesis", "sourceFactRefs"):
                self.assertNotIn(marker, json.dumps(context))
        metrics = result["arms"]["baseline"]["metrics"]
        self.assertEqual((metrics["cases"], metrics["supportedCases"], metrics["negativeCases"], metrics["unknownCases"]), (16, 4, 4, 8))
