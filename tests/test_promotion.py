"""Promotion effect, immutable-byte binding, single-use and cache-race checks."""

from concurrent.futures import ThreadPoolExecutor
import gzip
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lab.anti_rea import PRIVATE_MARKER, _exports, write_artifacts
from lab.promotion import PromotionLab, request, verify
import openshield.promotion as promotion
from openshield.promotion import PromotionError


class PromotionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.before, self.candidate = write_artifacts(self.root / "release")

    def tearDown(self):
        self.directory.cleanup()

    def stage(self, lab, preview):
        staged = lab.gate.stage(self.candidate, preview.url, authorized=True)
        return staged, lab.gate.approve_promotion(staged["candidateId"], staged["expectedGeneration"])

    def test_real_http_negative_positive_and_historical_counterexample(self):
        report = verify()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(len(report["checks"]), 27)
        self.assertTrue(all(item["passed"] for item in report["checks"]))
        self.assertEqual(report["phases"]["edge_without_explicit_purge"]["privateCanaryDeliveries"], 4)
        self.assertEqual(report["phases"]["edge_after_retirement"]["privateCanaryDeliveries"], 0)
        self.assertEqual(report["phases"]["edge_after_retirement"]["requiredGetSuccesses"], 6)
        self.assertTrue(report["derivedFacts"]["historicalDownloadRetainsPrivateBytes"])
        self.assertEqual(report["modelCalls"], 0)
        self.assertIs(report["productionActions"], False)
        serialized = json.dumps(report)
        for forbidden in (PRIVATE_MARKER, "127.0.0.1", "candidate_", "SYNTHETIC_UNREVIEWED_CHANGE", str(self.root)):
            self.assertNotIn(forbidden, serialized)

    def test_source_changes_after_last_check_never_replace_frozen_approved_bytes(self):
        with PromotionLab() as lab, lab.preview(self.candidate) as preview:
            staged, grant = self.stage(lab, preview)
            snapshot = promotion._snapshot

            def edit_after_check(directory):
                value = snapshot(directory)
                (self.candidate / "app.js").write_bytes(b"// SYNTHETIC_UNREVIEWED_AFTER_CHECK\n")
                return value

            with patch.object(promotion, "_snapshot", side_effect=edit_after_check):
                receipt = lab.gate.promote(grant)
            self.assertEqual(receipt["artifactSha256"], staged["artifactSha256"])
            status, body, compressed = request(lab.origin_url, "/app.js", "gzip")
            self.assertEqual(status, 200)
            self.assertTrue(compressed)
            self.assertEqual(gzip.decompress(body), _exports(True)["/app.js"])
            self.assertNotEqual((self.candidate / "app.js").read_bytes(), _exports(True)["/app.js"])

    def test_grant_expiry_is_rechecked_after_candidate_validation(self):
        now = [0.0]
        with PromotionLab(clock=lambda: now[0]) as lab, lab.preview(self.candidate) as preview:
            _, grant = self.stage(lab, preview)
            initial = lab.gate.state
            snapshot = promotion._snapshot

            def expire_during_check(directory):
                value = snapshot(directory)
                now[0] = 11.0
                return value

            with patch.object(promotion, "_snapshot", side_effect=expire_during_check):
                with self.assertRaises(PromotionError):
                    lab.gate.promote(grant)
            self.assertEqual(lab.gate.state, initial)
            with self.assertRaises(PromotionError):
                lab.gate.promote(grant)

    def test_single_grant_has_one_successful_concurrent_consumer(self):
        with PromotionLab() as lab, lab.preview(self.candidate) as preview:
            _, grant = self.stage(lab, preview)

            def attempt(_):
                try:
                    lab.gate.promote(grant)
                    return True
                except PromotionError:
                    return False

            with ThreadPoolExecutor(max_workers=8) as pool:
                successes = list(pool.map(attempt, range(16)))
            self.assertEqual(sum(successes), 1)
            self.assertEqual(lab.gate.state["generation"], 1)
            self.assertEqual(request(lab.origin_url, "/app.js")[1], _exports(True)["/app.js"])

    def test_old_inflight_origin_reply_cannot_refill_cache_after_purge(self):
        with PromotionLab() as lab, lab.preview(self.candidate) as preview:
            epoch, _ = lab.gate.cached("/app.js", "gzip")
            delayed_origin_reply = request(lab.origin_url, "/app.js", "gzip")
            self.assertIn(PRIVATE_MARKER.encode(), gzip.decompress(delayed_origin_reply[1]))
            _, grant = self.stage(lab, preview)
            lab.gate.promote(grant)
            lab.gate.retire(lab.gate.approve_retirement(1))
            rejected = lab.gate.cache_response(epoch, "/app.js", "gzip", delayed_origin_reply)
            self.assertEqual(rejected[0], 503)
            self.assertNotIn(PRIVATE_MARKER.encode(), rejected[1])
            status, body, compressed = request(lab.edge_url, "/app.js", "gzip")
            self.assertEqual(status, 200)
            self.assertTrue(compressed)
            self.assertEqual(gzip.decompress(body), _exports(True)["/app.js"])

    def test_retirement_cannot_precede_promotion_or_reuse_wrong_operation_grant(self):
        with PromotionLab() as lab, lab.preview(self.candidate) as preview:
            with self.assertRaises(PromotionError):
                lab.gate.approve_retirement(0)
            staged, grant = self.stage(lab, preview)
            with self.assertRaises(PromotionError):
                lab.gate.retire(grant)
            with self.assertRaises(PromotionError):
                lab.gate.promote(grant)
            with self.assertRaises(PromotionError):
                lab.gate.approve_promotion(staged["candidateId"], True)
            self.assertEqual(lab.gate.state["generation"], 0)

    def test_candidate_preview_mismatch_and_unsupported_tree_cannot_stage(self):
        with PromotionLab() as lab, lab.preview(self.before) as wrong_preview:
            with self.assertRaises(PromotionError):
                lab.gate.stage(self.candidate, wrong_preview.url, authorized=True)
            self.assertEqual(lab.gate.state["generation"], 0)
        (self.candidate / "server.py").write_text("# synthetic private module\n", encoding="utf-8")
        with PromotionLab() as lab, lab.preview(self.candidate) as preview:
            with self.assertRaises(PromotionError):
                lab.gate.stage(self.candidate, preview.url, authorized=True)
            self.assertEqual(lab.gate.state["generation"], 0)

    def test_stale_distinct_approval_cannot_rollback_or_mutate_retirement_state(self):
        with PromotionLab() as lab, lab.preview(self.candidate) as preview:
            staged, first = self.stage(lab, preview)
            second = lab.gate.approve_promotion(staged["candidateId"], 0)
            lab.gate.promote(first)
            lab.gate.retire(lab.gate.approve_retirement(1))
            before = lab.gate.state
            with self.assertRaises(PromotionError):
                lab.gate.promote(second)
            self.assertEqual(lab.gate.state, before)
            self.assertEqual(request(lab.edge_url, "/app.js.map", "gzip")[0], 410)


if __name__ == "__main__":
    unittest.main()
