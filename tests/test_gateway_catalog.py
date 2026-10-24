"""Real gateway HTTP/catalog integration using explicitly fixed completion doubles."""

import copy
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from openshield.core import Store, Supervisor
from openshield.gateway import Config, Gateway, GatewayError


class CatalogProviderDouble:
    """A scripted transport peer, never a real model or efficacy measurement."""

    def __init__(self, behavior="catalog_then_done"):
        self.behavior, self.payloads, self.contexts = behavior, [], []

    def __enter__(self):
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                context = json.loads(payload["messages"][1]["content"])
                owner.payloads.append(payload)
                owner.contexts.append(context)
                reads = []
                if owner.behavior == "catalog_then_done" and len(owner.contexts) == 1:
                    reads = [{"catalogId": "access_patterns", "limit": 1}]
                elif owner.behavior == "always_ask" or owner.behavior == "budget_aware" and context.get("readRoundsRemaining", 2) > 0:
                    reads = [{"catalogId": "control_posture", "limit": 1}]
                result = {"schemaVersion": "analysis_v1", "assessment": "insufficient_evidence",
                          "hypotheses": [], "nextAction": "needs_human", "evidenceIds": context["evidenceIds"],
                          "readRequests": reads, "limitations": ["synthetic_lab_only"]}
                body = json.dumps({"model": "catalog_transport_double", "choices": [{"finish_reason": "stop",
                                   "message": {"content": json.dumps(result)}}], "usage": {"total_tokens": 10}}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.gateway = Gateway(Config(f"http://127.0.0.1:{self.server.server_port}", "catalog_transport_double",
                                      allow_loopback_http=True))
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


class GatewayCatalogTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.directory.name) / "state.sqlite3",
                           clock=lambda: datetime(2026, 10, 24, 3, 1, tzinfo=timezone.utc))
        self.store.enroll("project_a", "asset_a", "operator_a", source_ids=("source_a",), allowed_actions=())
        for index in range(5):
            self.store.ingest({"schemaVersion": "lab_event_v1", "id": f"event_{index}", "projectId": "project_a",
                               "caseId": "case_a", "assetId": "asset_a", "sourceId": "source_a", "kind": "auth_decision",
                               "observedAt": "2026-10-24T03:00:30Z", "dataClass": "synthetic",
                               "facts": {"decision": "deny", "subjectLabel": "subject_a", "objectLabel": "object_a"}})
        self.environment = patch.dict(os.environ, {"SHIELD_CLIPROXY_API_KEY": "SYNTHETIC_CATALOG_AUTH_CANARY"})
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        self.store.close()
        self.directory.cleanup()

    def case_with_catalog(self):
        case = self.store.case("project_a", "case_a")
        case["catalogObservations"] = Supervisor(self.store)._reads(case, [{"catalogId": "access_patterns", "limit": 1}])
        return case

    def test_actual_http_second_call_receives_go_candidates_gaps_and_completes(self):
        with CatalogProviderDouble() as peer:
            result = Supervisor(self.store, peer.gateway).tick()[0]
        self.assertEqual(result["aiStatus"], "succeeded")
        self.assertEqual(result["calls"], 2)
        self.assertIsNone(result["aiFailureCode"])
        self.assertEqual(len(peer.contexts), 2)
        projected = peer.contexts[1]["catalogObservations"][0]
        self.assertEqual(projected["catalogId"], "access_patterns")
        self.assertEqual(projected["candidates"], [{"code": "repeated_access_denials",
                                                   "evidenceIds": [f"event_{index}" for index in range(5)]}])
        self.assertEqual(projected["status"], "partial")
        self.assertFalse(projected["coverage"]["complete"])
        self.assertIn("upstream_no_independent_observer", projected["coverage"]["gaps"])
        self.assertIn("candidate_not_compromise", projected["limitations"])
        self.assertFalse(projected["isFinding"])
        for raw_field in ("subjectLabel", "objectLabel", "observedCount", "evidenceTruncated", "sourcesObserved", "events"):
            self.assertNotIn(raw_field, json.dumps(projected))
        self.assertNotIn("SYNTHETIC_CATALOG_AUTH_CANARY", json.dumps(peer.payloads))
        self.assertFalse(result["modelProvenance"]["upstreamIdentityVerified"])

    def test_malformed_cross_reference_and_unrecognized_catalog_fields_never_reach_http(self):
        baseline = self.case_with_catalog()
        mutate = [lambda item: item.update(rawEvidence="SYNTHETIC_CATALOG_SECRET_CANARY"),
                  lambda item: item.update(origin="untrusted_external_source"),
                  lambda item: item.update(omittedCandidates=True),
                  lambda item: item.update(isFinding=True),
                  lambda item: item["coverage"].update(complete=True),
                  lambda item: item["coverage"]["gaps"].append("SYNTHETIC_CATALOG_SECRET_CANARY"),
                  lambda item: item["candidates"][0].update(observedCount=True),
                  lambda item: item["candidates"][0].update(observedCount=-1),
                  lambda item: item["candidates"][0].update(observedCount=1001),
                  lambda item: item["candidates"][0].update(evidenceIds=["other_case_evidence"]),
                  lambda item: item["candidates"][0].update(subjectLabel="other_subject"),
                  lambda item: item["candidates"][0].update(extra="SYNTHETIC_CATALOG_SECRET_CANARY")]
        with CatalogProviderDouble() as peer:
            for change in mutate:
                case = copy.deepcopy(baseline)
                change(case["catalogObservations"][0])
                with self.subTest(change=change), self.assertRaises(GatewayError) as raised:
                    peer.gateway.analyze(case, before_attempt=lambda _: None)
                self.assertEqual(raised.exception.code, "INVALID_READ_CONTEXT")
            self.assertEqual(peer.payloads, [])

    def test_ordinary_catalog_still_projects_only_known_ids_and_checks_origin(self):
        case = self.store.case("project_a", "case_a")
        case["catalogObservations"] = Supervisor(self.store)._reads(case, [{"catalogId": "recent_app_events", "limit": 2}])
        with CatalogProviderDouble(behavior="done") as peer:
            peer.gateway.analyze(case, before_attempt=lambda _: None)
            self.assertEqual(peer.contexts[0]["catalogObservations"], [{"catalogId": "recent_app_events", "evidenceIds": ["event_3", "event_4"]}])
            case["catalogObservations"][0]["origin"] = "untrusted_external_source"
            with self.assertRaises(GatewayError):
                peer.gateway.analyze(case, before_attempt=lambda _: None)
            self.assertEqual(len(peer.payloads), 1)

    def test_budget_aware_peer_observes_remaining_rounds_two_one_zero(self):
        with CatalogProviderDouble(behavior="budget_aware") as peer:
            result = Supervisor(self.store, peer.gateway).tick()[0]
        self.assertEqual([context.get("readRoundsRemaining") for context in peer.contexts], [2, 1, 0])
        self.assertEqual(result["aiStatus"], "succeeded")
        self.assertEqual(result["calls"], 3)
        self.assertEqual(result["readRequests"], [])
        self.assertEqual([context["evidenceIds"] for context in peer.contexts], [[f"event_{index}" for index in range(5)]] * 3)
        self.assertTrue(all(context["allowedActions"] == [] for context in peer.contexts))

    def test_always_requesting_peer_remains_degraded_at_the_same_hard_round_limit(self):
        with CatalogProviderDouble(behavior="always_ask") as peer:
            result = Supervisor(self.store, peer.gateway).tick()[0]
        self.assertEqual([context.get("readRoundsRemaining") for context in peer.contexts], [2, 1, 0])
        self.assertEqual(result["aiStatus"], "degraded_model")
        self.assertEqual(result["aiFailureCode"], "READ_ROUND_LIMIT")
        self.assertEqual(result["calls"], 3)
        self.assertIn("model_unavailable", result["limitations"])
        self.assertIsNone(result["modelProvenance"])

    def test_invalid_round_budget_is_not_a_prompt_extension_or_network_request(self):
        case = self.store.case("project_a", "case_a")
        with CatalogProviderDouble(behavior="done") as peer:
            for invalid in (True, -1, 3, "0", None):
                with self.subTest(value=invalid), self.assertRaises(GatewayError):
                    peer.gateway.analyze({**case, "readRoundsRemaining": invalid}, before_attempt=lambda _: None)
            self.assertEqual(peer.payloads, [])

    def test_secret_shaped_gateway_error_code_is_never_exported_or_persisted(self):
        class UnsafeErrorDouble:
            config = SimpleNamespace(global_token_limit=64000)
            route_hash = "unsafe_error_unit_double"

            def analyze(self, case, *, before_attempt, deadline):
                before_attempt(10)
                raise GatewayError("Bearer SYNTHETIC_ERROR_CODE_SECRET_CANARY")

        result = Supervisor(self.store, UnsafeErrorDouble()).tick()[0]
        self.assertEqual(result["aiStatus"], "degraded_model")
        self.assertEqual(result["aiFailureCode"], "ANALYSIS_OR_TOOL_CONTRACT_REJECTED")
        persisted = self.store.db.execute("SELECT result FROM shield_episodes").fetchall()
        for value in (result, self.store.health(), [row[0] for row in persisted]):
            self.assertNotIn("SYNTHETIC_ERROR_CODE_SECRET_CANARY", json.dumps(value))


if __name__ == "__main__":
    unittest.main()
