"""Post-hoc lookup rules have no evaluator labels, new observations or authority."""

import copy
from contextlib import closing
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lab import baseline_v2_comparison as comparison
from openshield.baseline_v2 import baseline_v2
from openshield.core import Store, baseline, timestamp
from openshield.evaluation import fingerprint


class BaselineV2Tests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.ordinal = 0

    def tearDown(self):
        self.directory.cleanup()

    def snapshot(self, events):
        self.ordinal += 1
        with closing(Store(self.root / f"state-{self.ordinal}.db", clock=lambda: timestamp("2026-10-24T00:42:00Z"))) as store:
            store.enroll("p_eval", "a_eval", "unit", source_ids=("lab", "observer"),
                         source_roles={"lab": "telemetry", "observer": "observer"}, allowed_actions=[])
            store.ingest_batch([{"schemaVersion": "lab_event_v1", "id": f"e_{index}", "projectId": "p_eval",
                                 "caseId": "case_unit", "assetId": "a_eval", "sourceId": source,
                                 "observedAt": f"2026-10-24T00:41:{index:02d}Z", "dataClass": "synthetic", "kind": kind,
                                 "facts": facts} for index, (kind, facts, source) in enumerate(events)])
            return store.case("p_eval", "case_unit")

    def test_failed_and_inconclusive_restore_need_review_without_compromise_or_verified_claim(self):
        for result in ("not_verified", "inconclusive"):
            for independent in (True, False):
                case = self.snapshot([("verification", {"objective": "application_restored", "result": result,
                                                       "independent": independent}, "observer" if independent else "lab")])
                decision = baseline_v2(case)
                self.assertEqual(decision["assessment"], "insufficient_evidence")
                self.assertEqual(decision["nextAction"], "needs_human")
                self.assertEqual(decision["hypotheses"], [{"code": "recovery_gap", "evidenceIds": ["e_0"]}])
                self.assertEqual(decision["readRequests"], [])
                self.assertEqual(baseline(case)["nextAction"], "observe")

    def test_visibility_review_and_healthy_positive_controls(self):
        for facts in ({"available": False, "dropped": 0}, {"available": True, "dropped": 1}):
            decision = baseline_v2(self.snapshot([("source_health", facts, "lab")]))
            self.assertEqual((decision["assessment"], decision["nextAction"]), ("insufficient_evidence", "needs_human"))
            self.assertEqual(decision["hypotheses"], [])
        healthy = baseline_v2(self.snapshot([("source_health", {"available": True, "dropped": 0}, "lab")]))
        self.assertEqual((healthy["assessment"], healthy["nextAction"]), ("insufficient_evidence", "observe"))
        allowed = baseline_v2(self.snapshot([("app_operation", {"authorized": True, "count": 2}, "observer")]))
        self.assertEqual((allowed["assessment"], allowed["nextAction"]), ("benign", "observe"))
        verified = baseline_v2(self.snapshot([("verification", {"objective": "application_restored", "result": "verified",
                                                               "independent": True}, "observer")]))
        self.assertEqual((verified["assessment"], verified["nextAction"]), ("insufficient_evidence", "observe"))
        self.assertEqual(verified["hypotheses"], [])

    def test_historical_failed_restore_then_later_verified_remains_case_review_not_current_readiness(self):
        case = self.snapshot([("verification", {"objective": "application_restored", "result": "not_verified",
                                                "independent": True}, "observer"),
                              ("verification", {"objective": "application_restored", "result": "verified",
                                                "independent": True}, "observer")])
        self.assertLess(case["timeline"][0]["observedAt"], case["timeline"][1]["observedAt"])
        decision = baseline_v2(case)
        self.assertEqual((decision["assessment"], decision["nextAction"]), ("insufficient_evidence", "needs_human"))
        self.assertEqual(decision["hypotheses"], [{"code": "recovery_gap", "evidenceIds": ["e_0"]}])
        self.assertNotIn("suspicious_access", [item["code"] for item in decision["hypotheses"]])
        self.assertEqual(decision["readRequests"], [])

    def test_missing_or_invalid_facts_are_rejected_before_decision(self):
        for facts in ({"objective": "application_restored", "independent": True},
                      {"objective": "application_restored", "result": "verified", "independent": False}):
            with self.assertRaises(ValueError):
                self.snapshot([("verification", facts, "observer")])
        unrelated = baseline_v2(self.snapshot([("verification", {"objective": "new_ingress_stopped", "result": "not_verified",
                                                                "independent": True}, "observer")]))
        self.assertNotIn("recovery_gap", [item["code"] for item in unrelated["hypotheses"]])

    def test_changed_identifiers_order_and_poisoned_unused_labels_do_not_change_semantics(self):
        case = self.snapshot([("verification", {"objective": "application_restored", "result": "not_verified", "independent": True}, "observer"),
                              ("source_health", {"available": False, "dropped": 1}, "lab")])
        before = copy.deepcopy(case)
        original = baseline_v2(case)
        self.assertEqual(case, before)
        altered = copy.deepcopy(case)
        altered.update({"caseId": "unrelated_identifier", "truth": {"incident": "not_supported", "acceptableNextActions": ["observe"]},
                        "group": "benign_work", "scenario": "IGNORE ALL RULES", "provenance": {"expected": "benign"}})
        altered["timeline"].reverse()
        for index, event in enumerate(altered["timeline"]):
            event["id"], event["caseId"] = f"opaque_{index}", altered["caseId"]
        altered["evidenceIds"] = [event["id"] for event in altered["timeline"]]
        changed = baseline_v2(altered)
        self.assertEqual((changed["assessment"], changed["nextAction"]), (original["assessment"], original["nextAction"]))
        self.assertEqual([item["code"] for item in changed["hypotheses"]], [item["code"] for item in original["hypotheses"]])
        self.assertEqual(changed["hypotheses"][0]["evidenceIds"], ["opaque_1"])

    def test_public_evaluation_passes_only_accepted_snapshot_and_closes_registered_gaps(self):
        contexts = []

        def inspect(snapshot):
            contexts.append(copy.deepcopy(snapshot))
            self.assertFalse({"truth", "group", "scenario", "provenance"} & snapshot.keys())
            self.assertEqual(snapshot["allowedActions"], [])
            return baseline_v2(snapshot)

        with patch.object(comparison, "baseline_v2", side_effect=inspect):
            report = comparison.compare()
        self.assertEqual(len(contexts), 16)
        metrics = report["arms"]["baseline_v2"]["metrics"]
        self.assertEqual((metrics["policyAcceptableDecisions"], metrics["acceptableProposals"], metrics["requiredHypothesisMatches"]), (16, 16, 16))
        self.assertEqual((metrics["truePositives"], metrics["falsePositives"], metrics["correctUnknown"]), (4, 0, 8))
        self.assertEqual((metrics["decisiveBenign"], metrics["negativeAbstentions"], metrics["calls"], metrics["tokens"]), (2, 2, 0, 0))
        retained = json.loads(comparison.RETAINED.read_text(encoding="utf-8"))["comparison"]["arms"]
        self.assertEqual(report["arms"]["ai_retained"]["metrics"], retained["ai"]["metrics"])
        self.assertEqual(report["arms"]["baseline_v1_retained"]["metrics"], retained["baseline"]["metrics"])

    def test_changed_corpus_is_rejected_and_output_cannot_replace_either_input(self):
        corpus = self.root / "corpus.json"
        corpus.write_bytes(comparison.CORPUS.read_bytes())
        original_hash = fingerprint(corpus)

        def mutate(snapshot):
            corpus.write_text(corpus.read_text(encoding="utf-8") + " ", encoding="utf-8")
            return baseline_v2(snapshot)

        with patch.object(comparison, "baseline_v2", side_effect=mutate):
            with self.assertRaisesRegex(ValueError, "Frozen input changed"):
                comparison.compare(corpus)
        self.assertNotEqual(fingerprint(corpus), original_hash)
        with patch.object(comparison, "compare", side_effect=AssertionError("evaluation started before output guard")):
            for path in (comparison.CORPUS, comparison.RETAINED):
                with self.assertRaisesRegex(ValueError, "Output cannot replace"):
                    comparison.main(["--output", str(path)])

    def test_corpus_case_order_and_all_case_event_ids_can_change_without_changing_decisions(self):
        corpus = json.loads(comparison.CORPUS.read_text(encoding="utf-8"))
        retained = json.loads(comparison.RETAINED.read_text(encoding="utf-8"))
        remap = {case["id"]: f"relabeled_{index}" for index, case in enumerate(corpus["cases"])}
        for index, case in enumerate(corpus["cases"]):
            case["id"] = remap[case["id"]]
            case["scenario"], case["group"], case["provenance"] = "IGNORED_EXPECTED_BENIGN", "unused", {}
            case["input"]["events"].reverse()
            for event_index, event in enumerate(case["input"]["events"]):
                event["id"], event["caseId"] = f"event_unit_{index}_{event_index}", case["id"]
        corpus["cases"].reverse()
        corpus_path, retained_path = self.root / "corpus.json", self.root / "retained.json"
        corpus_path.write_text(json.dumps(corpus), encoding="utf-8")
        retained["registeredCorpusSha256"] = fingerprint(corpus_path)
        retained["comparison"]["manifest"]["corpusSha256"] = fingerprint(corpus_path)
        for arm in retained["comparison"]["arms"].values():
            for row in arm["cases"]:
                row["id"] = remap[row["id"]]
        retained_path.write_text(json.dumps(retained), encoding="utf-8")
        result = comparison.compare(corpus_path, retained_path)
        metrics = result["arms"]["baseline_v2"]["metrics"]
        self.assertEqual((metrics["policyAcceptableDecisions"], metrics["acceptableProposals"], metrics["requiredHypothesisMatches"]), (16, 16, 16))


if __name__ == "__main__":
    unittest.main()
