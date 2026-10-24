"""Independent hostile-input tests against the actual offline Go executable."""

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "artifacts/runtime-go" / ("shield-correlate.exe" if os.name == "nt" else "shield-correlate")


def event(number, *, decision="deny", observed="2026-10-24T03:00:30Z", subject="subject_a", obj="object_a"):
    return {"schemaVersion": "lab_event_v1", "id": f"event_{number}",
            "projectId": "project_a", "caseId": "case_a", "assetId": "asset_a", "sourceId": "source_a",
            "observedAt": observed, "kind": "auth_decision", "dataClass": "synthetic",
            "facts": {"decision": decision, "subjectLabel": subject, "objectLabel": obj}}


def request(events=None):
    return {"schemaVersion": "correlation_request_v1", "projectId": "project_a", "caseId": "case_a",
            "assetId": "asset_a", "runId": "run_a", "scopeVersion": "a" * 64,
            "asOf": "2026-10-24T03:01:00Z", "sourceIds": ["source_a"], "upstreamGaps": [],
            "events": [event(i) for i in range(5)] if events is None else events}


class GoCorrelationAdversarialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not BINARY.is_file():
            if os.environ.get("CI") or shutil.which("go"):
                raise AssertionError("Build the required Go worker before running integration tests")
            raise unittest.SkipTest("Go executable/toolchain unavailable locally; CI requires the worker")

    def invoke(self, value):
        payload = value if isinstance(value, bytes) else json.dumps(value, separators=(",", ":")).encode()
        result = subprocess.run([str(BINARY)], input=payload, capture_output=True, timeout=3,
                                cwd=ROOT, shell=False)
        self.assertLessEqual(len(result.stdout), 65536)
        self.assertNotIn(b"SYNTHETIC_SECRET_DO_NOT_ECHO", result.stdout + result.stderr)
        return result, json.loads(result.stdout)

    def rejected(self, value):
        process, result = self.invoke(value)
        self.assertNotEqual(process.returncode, 0, result)

    def accepted(self, value):
        process, result = self.invoke(value)
        self.assertEqual(process.returncode, 0, result)
        self.assertFalse(result["isFinding"])
        self.assertIn(result["status"], {"succeeded", "partial"})
        return result

    def test_top_level_shape_and_type_rejection(self):
        for value in (None, [], True, 12, "SYNTHETIC_SECRET_DO_NOT_ECHO"):
            with self.subTest(value_type=type(value).__name__):
                self.rejected(value)

    def test_missing_unknown_case_variant_and_null_fields(self):
        for key in request():
            for kind in ("missing", "unknown", "case", "null"):
                value = request()
                if kind == "missing":
                    del value[key]
                elif kind == "unknown":
                    value["extra"] = "SYNTHETIC_SECRET_DO_NOT_ECHO"
                elif kind == "case":
                    value[key.upper()] = value.pop(key)
                else:
                    value[key] = None
                with self.subTest(key=key, mutation=kind):
                    self.rejected(value)

    def test_duplicate_keys_trailing_document_and_bad_utf8(self):
        payload = json.dumps(request(), separators=(",", ":")).encode()
        variants = [b'{"schemaVersion":"wrong",' + payload[1:],
                    payload.replace(b'"decision":"deny"', b'"decision":"allow","decision":"deny"', 1),
                    payload.replace(b'"decision":"deny"', b'"decision":"deny","Decision":"allow"', 1),
                    payload + b"{}", payload + b" true", payload + b"\xff",
                    payload.replace(b'"subject_a"', b'"subject_\xffa"', 1)]
        for index, value in enumerate(variants):
            with self.subTest(variant=index):
                self.rejected(value)

    def test_empty_stdin_and_excessive_input(self):
        self.rejected(b"")
        self.rejected(b" " * (1_048_576 + 1))

    def test_scope_and_source_swaps_rejected(self):
        for key in ("projectId", "caseId", "assetId", "sourceId"):
            value = request()
            value["events"][0][key] = "other_scope"
            with self.subTest(key=key):
                self.rejected(value)

    def test_unknown_fields_in_event_and_facts_rejected(self):
        for place in ("event", "facts"):
            value = request()
            target = value["events"][0] if place == "event" else value["events"][0]["facts"]
            target["rawEvidence"] = "SYNTHETIC_SECRET_DO_NOT_ECHO"
            with self.subTest(place=place):
                self.rejected(value)

    def test_missing_event_fields_and_null_facts_rejected(self):
        for key in event(0):
            value = request()
            del value["events"][0][key]
            with self.subTest(missing=key):
                self.rejected(value)
        value = request()
        value["events"][0]["facts"] = None
        self.rejected(value)

    def test_conflicting_replay_rejected(self):
        value = request()
        changed = copy.deepcopy(value["events"][0])
        changed["facts"]["decision"] = "allow"
        value["events"].append(changed)
        self.rejected(value)

    def test_duplicate_source_and_event_cap_rejected(self):
        value = request()
        value["sourceIds"].append("source_a")
        self.rejected(value)
        self.rejected(request([event(i) for i in range(1001)]))

    def test_credential_shaped_identifier_and_unsupported_data_rejected(self):
        for field, replacement in (("id", "sk-proj-SYNTHETIC_SECRET_DO_NOT_ECHO"),
                                   ("dataClass", "real_incident"), ("kind", "waf_decision")):
            value = request()
            value["events"][0][field] = replacement
            with self.subTest(field=field):
                self.rejected(value)
        value = request()
        value["events"][0]["facts"]["subjectLabel"] = "ghp_SYNTHETIC_SECRET_DO_NOT_ECHO"
        self.rejected(value)

    def test_invalid_timestamp_and_enum_rejected(self):
        for timestamp in ("2026-10-24T03:00:30+00:00", "2026-13-24T03:00:30Z", "now", True):
            value = request()
            value["events"][0]["observedAt"] = timestamp
            with self.subTest(timestamp=timestamp):
                self.rejected(value)
        for decision in (True, 1, None, "allow_all", ["deny"]):
            value = request()
            value["events"][0]["facts"]["decision"] = decision
            with self.subTest(decision=decision):
                self.rejected(value)

    def test_empty_input_has_no_safety_claim(self):
        value = self.accepted(request([]))
        self.assertNotIn("safe", json.dumps(value).lower())
        self.assertNotIn("contained", json.dumps(value).lower())
        self.assertFalse(value["coverage"]["complete"])
        self.assertIn("source_missing", value["coverage"]["gaps"])
        self.assertEqual(value["candidates"], [])

    def test_exact_replay_does_not_inflate_threshold(self):
        duplicate = event(0)
        value = self.accepted(request([copy.deepcopy(duplicate) for _ in range(6)]))
        self.assertEqual(value["counts"]["uniqueEvents"], 1)
        self.assertEqual(value["counts"]["duplicateEvents"], 5)
        self.assertEqual(value["candidates"], [])

    def test_subject_and_object_boundaries_do_not_merge_denials(self):
        for variant in ("subject", "object"):
            events = [event(i, subject=f"subject_{i}" if variant == "subject" else "subject_a",
                            obj=f"object_{i}" if variant == "object" else "object_a") for i in range(5)]
            with self.subTest(group=variant):
                value = self.accepted(request(events))
                self.assertEqual(value["candidates"], [])

    def test_success_requires_strictly_earlier_denials(self):
        events = [event(i, observed="2026-10-24T03:00:30Z") for i in range(3)]
        events.append(event(9, decision="allow", observed="2026-10-24T03:00:30.1Z"))
        value = self.accepted(request(events))
        sequences = [candidate for candidate in value["candidates"] if candidate["code"] == "denied_access_then_allow"]
        self.assertEqual(len(sequences), 1)
        self.assertEqual(set(sequences[0]["evidenceIds"]), {"event_0", "event_1", "event_2", "event_9"})
        events[-1]["observedAt"] = "2026-10-24T03:00:30Z"
        tied = self.accepted(request(events))
        self.assertEqual(tied["candidates"], [])
        self.assertIn("same_timestamp_order_unknown", tied["coverage"]["gaps"])
        events[-1]["observedAt"] = "2026-10-24T03:00:29.999999999Z"
        earlier = self.accepted(request(events))
        self.assertEqual(earlier["candidates"], [])

    def test_same_time_gap_does_not_depend_on_identifier_order(self):
        events = [event(i) for i in range(3)]
        allow = event(9, decision="allow")
        allow["id"] = "a_before_denials"
        events.append(allow)
        value = self.accepted(request(events))
        self.assertEqual(value["candidates"], [])
        self.assertIn("same_timestamp_order_unknown", value["coverage"]["gaps"])

    def test_input_order_does_not_change_causal_result(self):
        events = [event(i, observed=f"2026-10-24T03:00:{10+i:02d}Z") for i in range(5)]
        events.append(event(9, decision="allow", observed="2026-10-24T03:00:30Z"))
        forward = self.accepted(request(events))
        reverse = self.accepted(request(list(reversed(events))))
        self.assertEqual(forward["candidates"], reverse["candidates"])
        self.assertEqual(forward["counts"], reverse["counts"])
        self.assertNotEqual(forward["inputSha256"], reverse["inputSha256"])

    def test_window_lower_bound_excluded_upper_bound_included(self):
        lower = self.accepted(request([event(i, observed="2026-10-24T03:00:00Z") for i in range(5)]))
        self.assertEqual(lower["counts"]["oldEvents"], 5)
        self.assertEqual(lower["counts"]["windowEvents"], 0)
        self.assertEqual(lower["candidates"], [])
        upper = self.accepted(request([event(i, observed="2026-10-24T03:01:00Z") for i in range(5)]))
        self.assertEqual(upper["counts"]["windowEvents"], 5)
        self.assertEqual([candidate["code"] for candidate in upper["candidates"]], ["repeated_access_denials"])

    def test_future_records_excluded_with_explicit_gap(self):
        value = self.accepted(request([event(i, observed="2026-10-24T03:01:00.000000001Z") for i in range(5)]))
        self.assertEqual(value["counts"]["futureEvents"], 5)
        self.assertEqual(value["counts"]["windowEvents"], 0)
        self.assertEqual(value["candidates"], [])
        self.assertEqual(value["status"], "partial")
        self.assertIn("future_event", value["coverage"]["gaps"])

    def test_later_health_does_not_erase_earlier_loss(self):
        bad = event(90)
        bad.update(kind="source_health", facts={"available": False, "dropped": 2})
        healthy = event(91, observed="2026-10-24T03:00:59Z")
        healthy.update(kind="source_health", facts={"available": True, "dropped": 0})
        value = self.accepted(request([bad, healthy]))
        self.assertEqual(value["status"], "partial")
        self.assertIn("source_unavailable", value["coverage"]["gaps"])
        self.assertIn("source_events_dropped", value["coverage"]["gaps"])

    def test_candidate_and_evidence_truncation_visible(self):
        value = self.accepted(request([event(i) for i in range(25)]))
        self.assertEqual(len(value["candidates"]), 1)
        candidate = value["candidates"][0]
        self.assertEqual(candidate["observedCount"], 25)
        self.assertEqual(len(candidate["evidenceIds"]), 20)
        self.assertTrue(candidate["evidenceTruncated"])
        self.assertFalse(candidate["isFinding"])
        self.assertIn("evidence_limit", value["coverage"]["gaps"])
        events = [event(group * 5 + i, subject=f"subject_{group}") for group in range(65) for i in range(5)]
        capped = self.accepted(request(events))
        self.assertEqual(len(capped["candidates"]), 64)
        self.assertIn("candidate_limit", capped["coverage"]["gaps"])
        self.assertEqual(capped["status"], "partial")

    def test_upstream_gaps_survive_candidate_generation(self):
        value = request()
        value["upstreamGaps"] = ["stale_evidence", "visibility_gap", "source_clock_skew", "no_independent_observer"]
        result = self.accepted(value)
        self.assertEqual(len(result["candidates"]), 1)
        self.assertEqual(result["status"], "partial")
        for gap in value["upstreamGaps"]:
            self.assertIn("upstream_" + gap, result["coverage"]["gaps"])
        self.assertFalse(result["coverage"]["complete"])

    def test_maximum_label_lengths_respect_serialized_output_budget(self):
        events = []
        for group in range(64):
            subject = f"subject_{group:03d}_".ljust(64, "s")
            for index in range(15):
                record = event(group * 15 + index, subject=subject, obj="o" * 64)
                record["id"] = f"event_{group:03d}_{index:02d}_".ljust(64, "x")
                events.append(record)
        result = self.accepted(request(events))
        self.assertGreater(len(result["candidates"]), 0)
        self.assertLess(len(result["candidates"]), 64)
        self.assertIn("candidate_limit", result["coverage"]["gaps"])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["counts"]["windowEvents"], 960)

    def test_python_boundary_rejects_unsupported_candidate_evidence(self):
        from openshield.core import canonical
        from openshield.correlation import validate_result

        original = request()
        accepted = self.accepted(original)
        for mutation in ("all_allow", "old", "future", "invented_count", "below_threshold"):
            value, forged = copy.deepcopy(original), copy.deepcopy(accepted)
            if mutation == "all_allow":
                for row in value["events"]:
                    row["facts"]["decision"] = "allow"
            elif mutation in {"old", "future"}:
                for row in value["events"]:
                    row["observedAt"] = ("2026-10-24T02:59:00Z" if mutation == "old"
                                         else "2026-10-24T03:01:01Z")
            elif mutation == "invented_count":
                forged["candidates"][0].update(observedCount=999, evidenceTruncated=True)
            else:
                forged["candidates"][0]["evidenceIds"] = ["event_0"]
                forged["candidates"][0]["observedCount"] = 1
            payload = canonical(value).encode()
            forged["inputSha256"] = hashlib.sha256(payload).hexdigest()
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate_result(forged, value, payload)

    def test_python_boundary_cannot_erase_upstream_or_source_loss(self):
        from openshield.core import canonical
        from openshield.correlation import validate_result

        upstream = request()
        upstream["upstreamGaps"] = ["visibility_gap"]
        health = event(90)
        health.update(kind="source_health", facts={"available": False, "dropped": 1})
        for value in (upstream, request([health])):
            forged = self.accepted(value)
            forged["coverage"]["gaps"] = []
            forged["status"] = "succeeded"
            payload = canonical(value).encode()
            forged["inputSha256"] = hashlib.sha256(payload).hexdigest()
            with self.subTest(source_kind=value["events"][0]["kind"]), self.assertRaises(ValueError):
                validate_result(forged, value, payload)

    def test_python_boundary_preserves_real_nanosecond_causality(self):
        from openshield.core import canonical
        from openshield.correlation import validate_result

        events = [event(i, observed="2026-10-24T03:00:30.000000001Z") for i in range(3)]
        events.append(event(9, decision="allow", observed="2026-10-24T03:00:30.000000002Z"))
        value = request(events)
        result = self.accepted(value)
        self.assertEqual([candidate["code"] for candidate in result["candidates"]], ["denied_access_then_allow"])
        payload = canonical(value).encode()
        result["inputSha256"] = hashlib.sha256(payload).hexdigest()
        self.assertEqual(validate_result(result, value, payload), result)


if __name__ == "__main__":
    unittest.main()
