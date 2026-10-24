"""Independent aggregate/evaluator contracts; completion doubles never measure AI skill."""

import copy
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from lab import next_wave
from openshield.cli import main
from openshield.core import Store
from openshield.evaluation import compare, fingerprint
from openshield.gateway import GatewayError


def corpus():
    return {"schemaVersion": "heldout_corpus_v1", "synthetic": True,
            "registration": {"replayClockUTC": "2026-10-24T00:42:00Z", "allowedActions": [],
                             "evaluationClass": "unit_boundary_test_double"},
            "cases": [{"id": "opaque_q1", "group": "evaluator_only", "input": {"events": [
                {"schemaVersion": "lab_event_v1", "id": "opaque_x9", "projectId": "p_eval",
                 "caseId": "opaque_q1", "assetId": "a_eval", "sourceId": "lab",
                 "observedAt": "2026-10-24T00:41:00Z", "dataClass": "synthetic",
                 "kind": "app_operation", "facts": {"authorized": False, "count": 1}}]},
                "truth": {"ingest": "accept", "incident": "supported",
                          "acceptableNextActions": ["needs_human"], "requiredHypotheses": ["business_abuse"]}}]}


class CompletionDouble:
    """Schema-compatible unit fixture, without a provider or inference claim."""
    config = SimpleNamespace(global_token_limit=64000, provider="test_double", model="test_double")
    route_hash = "synthetic_integration_test_only"
    last_metadata = None

    def __init__(self, callback=None, degraded=False):
        self.contexts, self.callback, self.degraded = [], callback, degraded

    def analyze(self, case, *, before_attempt, deadline):
        before_attempt(10)
        self.contexts.append(copy.deepcopy(case))
        if self.callback:
            self.callback()
        if self.degraded:
            raise GatewayError("INVALID_PROVIDER_OUTPUT")
        return {"schemaVersion": "analysis_v1", "assessment": "suspicious",
                "hypotheses": [{"code": "business_abuse", "evidenceIds": case["evidenceIds"]}],
                "nextAction": "needs_human", "evidenceIds": case["evidenceIds"],
                "readRequests": [], "limitations": []}


def effect_double(schema="promotion_lab_v1"):
    return {"schemaVersion": schema, "status": "passed", "dataClass": "synthetic",
            "checks": [{"code": "UNIT_FIXTURE_ONLY", "passed": True}], "modelCalls": 0, "productionActions": False}


def flow_double():
    return {**effect_double("flow_lab_v1"),
            "negativeControlEffects": {"reads": 4, "charges": 3, "chargedUnits": 3},
            "protectedForbiddenEffects": {"reads": 0, "charges": 0, "chargedUnits": 0},
            "protectedAllowedEffects": {"reads": 2, "charges": 2, "chargedUnits": 2},
            "negativeControlOutsideDeliveries": 2, "protectedOutsideRequests": 0,
            "protectedOutsideDeliveries": 0, "protectedAllowedDeliveries": 1, "idempotentConcurrentCommits": 1}


class EvaluationIntegrationChallenge(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "registered-corpus.json"
        self.corpus = corpus()
        self.path.write_text(json.dumps(self.corpus), encoding="utf-8")

    def tearDown(self):
        self.directory.cleanup()

    def test_empty_registered_action_authority_reaches_both_arms_and_optional_scoring(self):
        gateway = CompletionDouble()
        report = compare(self.path, gateway)
        self.assertEqual(report["manifest"]["allowedActions"], [])
        self.assertEqual(gateway.contexts[0]["allowedActions"], [])
        for arm in report["arms"].values():
            self.assertEqual(arm["cases"][0]["nextAction"], "needs_human")
            self.assertEqual(arm["metrics"]["acceptableProposals"], 1)
            self.assertEqual(arm["metrics"]["requiredHypothesisMatches"], 1)
        self.assertNotIn("acceptableNextActions", json.dumps(gateway.contexts))
        self.assertNotIn("requiredHypotheses", json.dumps(gateway.contexts))

    def test_rejected_and_degraded_rows_cannot_earn_proposal_or_hypothesis_credit(self):
        failed = compare(self.path, CompletionDouble(degraded=True))["arms"]["ai"]
        row = failed["cases"][0]
        self.assertEqual(row["aiStatus"], "degraded_model")
        self.assertFalse(row["proposalAcceptable"])
        self.assertFalse(row["requiredHypothesesPresent"])
        self.assertEqual(failed["metrics"]["acceptableProposals"], 0)
        self.assertEqual(failed["metrics"]["requiredHypothesisMatches"], 0)
        self.corpus["cases"][0]["input"]["events"][0]["sourceId"] = "unenrolled_source"
        self.corpus["cases"][0]["truth"]["ingest"] = "reject"
        self.path.write_text(json.dumps(self.corpus), encoding="utf-8")
        gateway = CompletionDouble()
        result = compare(self.path, gateway)
        self.assertEqual(gateway.contexts, [])
        for arm in result["arms"].values():
            self.assertTrue(arm["cases"][0]["rejected"])
            self.assertFalse(arm["cases"][0]["proposalAcceptable"])
            self.assertFalse(arm["cases"][0]["requiredHypothesesPresent"])
            self.assertEqual(arm["metrics"]["acceptableProposals"], 0)
            self.assertEqual(arm["metrics"]["requiredHypothesisMatches"], 0)

    def test_changed_registered_corpus_during_comparison_is_rejected(self):
        def mutate():
            changed = copy.deepcopy(self.corpus)
            changed["description"] = "SYNTHETIC_CHANGED_DURING_COMPARISON"
            self.path.write_text(json.dumps(changed), encoding="utf-8")
        with self.assertRaises((ValueError, RuntimeError)):
            compare(self.path, CompletionDouble(callback=mutate))

    def test_manifest_cannot_hash_different_bytes_than_the_loaded_corpus(self):
        original_read = Path.read_text
        reads = [0]

        def swap_after_first_read(path, *args, **kwargs):
            text = original_read(path, *args, **kwargs)
            if path == self.path:
                reads[0] += 1
                if reads[0] == 1:
                    changed = copy.deepcopy(self.corpus)
                    changed["description"] = "SYNTHETIC_SWAP_AFTER_LOAD_BEFORE_MANIFEST"
                    self.path.write_text(json.dumps(changed), encoding="utf-8")
            return text

        with patch.object(Path, "read_text", swap_after_first_read):
            with self.assertRaises((ValueError, RuntimeError)):
                compare(self.path)

    def test_progress_callback_exports_only_safe_counts_and_status(self):
        progress = []
        compare(self.path, CompletionDouble(), progress=progress.append)
        self.assertEqual(len(progress), 2)
        self.assertEqual([item["arm"] for item in progress], ["baseline", "ai"])
        for item in progress:
            self.assertEqual(set(item), {"arm", "caseIndex", "totalCases", "aiStatus", "calls"})
            self.assertEqual((item["caseIndex"], item["totalCases"]), (1, 1))
            self.assertNotIn(str(self.path), json.dumps(item))

    def test_case_database_closes_even_when_tick_raises_preserving_original_error(self):
        instances = []

        class TrackingStore(Store):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.closed = False
                instances.append(self)

            def close(self):
                self.closed = True
                super().close()

        with patch("openshield.evaluation.Store", TrackingStore):
            with patch("openshield.evaluation.Supervisor.tick", side_effect=RuntimeError("synthetic-case-failure")):
                with self.assertRaisesRegex(RuntimeError, "synthetic-case-failure"):
                    compare(self.path)
        self.assertTrue(instances)
        self.assertTrue(all(store.closed for store in instances))

    def test_benchmark_report_cannot_replace_registered_corpus_before_evaluation(self):
        original = self.path.read_bytes()
        with patch("openshield.evaluation.compare", side_effect=AssertionError("Evaluation started before path guard")):
            with self.assertRaises(ValueError):
                main(["benchmark", "--corpus", str(self.path), "--output", str(self.path)])
        self.assertEqual(self.path.read_bytes(), original)


class NextWaveAggregateChallenge(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def test_bad_unsafe_positive_or_forbidden_effect_counters_fail_even_when_checks_say_passed(self):
        binary = self.root / "artifacts/runtime-go" / ("shield-flow-lab.exe" if next_wave.os.name == "nt" else "shield-flow-lab")
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"UNIT_FIXTURE_NOT_AN_EXECUTABLE")
        bad_reports = []
        for field, value in (("negativeControlOutsideDeliveries", 0), ("protectedAllowedDeliveries", 0),
                             ("protectedOutsideRequests", 1), ("idempotentConcurrentCommits", 2)):
            report = flow_double()
            report[field] = value
            bad_reports.append(report)
        for field in ("negativeControlEffects", "protectedAllowedEffects", "protectedForbiddenEffects"):
            report = flow_double()
            report[field]["charges"] += 1
            bad_reports.append(report)
        for report in bad_reports:
            process = subprocess.CompletedProcess([str(binary)], 0, json.dumps(report).encode(), b"")
            with patch.object(next_wave, "ROOT", self.root), patch("lab.next_wave.subprocess.run", return_value=process):
                with self.assertRaises(RuntimeError):
                    next_wave._flow()

    def test_exact_corpus_exists_before_gateway_and_comparison_receive_it(self):
        expected = corpus()
        registered = self.root / "output/next-wave-corpus.json"
        gateway = CompletionDouble()
        chronology = []

        def configured():
            self.assertEqual(json.loads(registered.read_text(encoding="utf-8")), expected)
            chronology.append("gateway_after_registration")
            return gateway

        def comparison(path, received_gateway, *, progress=None):
            self.assertEqual(path, registered)
            self.assertIs(received_gateway, gateway)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), expected)
            chronology.append("comparison_after_registration")
            return {"arms": {"ai": {"metrics": {"providerUnavailableCases": 0}}}}

        actual_fingerprint = fingerprint

        def hashes(path):
            return actual_fingerprint(path) if Path(path) == registered else "a" * 64

        with patch.object(next_wave, "ROOT", self.root), patch.object(next_wave, "_flow", return_value=(flow_double(), "b" * 64)):
            with patch("lab.promotion.verify", return_value=effect_double()), patch("lab.recovery_readiness.verify", return_value=effect_double("recovery_readiness_lab_v1")):
                with patch("lab.next_wave_corpus.build_corpus", return_value=expected), patch.object(next_wave.Gateway, "from_env", side_effect=configured):
                    with patch.object(next_wave, "compare", side_effect=comparison), patch.object(next_wave, "fingerprint", side_effect=hashes):
                        result = next_wave.verify(with_ai=True)
        self.assertEqual(chronology, ["gateway_after_registration", "comparison_after_registration"])
        self.assertEqual(result["registeredCorpusSha256"], fingerprint(registered))
        self.assertTrue(result["realAICompletedAllCases"])

    def test_failed_promotion_or_recovery_assertion_blocks_before_provider(self):
        for failed_index in (0, 1):
            reports = [effect_double(), effect_double("recovery_readiness_lab_v1")]
            reports[failed_index]["checks"][0]["passed"] = False
            with patch.object(next_wave, "_flow", return_value=(flow_double(), "b" * 64)):
                with patch("lab.promotion.verify", return_value=reports[0]), patch("lab.recovery_readiness.verify", return_value=reports[1]):
                    with patch.object(next_wave.Gateway, "from_env", side_effect=AssertionError("Inference started after effect failure")):
                        with self.assertRaises(RuntimeError):
                            next_wave.verify(with_ai=True)

    def test_next_wave_report_cannot_replace_fixed_registered_corpus(self):
        registered = Path(next_wave.ROOT) / "output/next-wave-corpus.json"
        with patch("lab.next_wave.verify", side_effect=AssertionError("Lab started before output guard")):
            with self.assertRaises(ValueError):
                main(["next-wave-lab", "--output", str(registered)])


if __name__ == "__main__":
    unittest.main()
