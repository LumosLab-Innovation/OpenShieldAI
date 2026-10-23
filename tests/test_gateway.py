import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from openshield.core import Store
from openshield.gateway import Config, Gateway, GatewayError, strict_json
from test_core import event


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.store.enroll("project_lab", "asset_lab", "operator_lab")
        self.store.ingest(event())
        self.case = self.store.case("project_lab", "case_lab")
        self.requests = []
        self.replies = []
        owner = self

        class SyntheticProvider(BaseHTTPRequestHandler):
            def do_POST(self):
                payload = self.rfile.read(int(self.headers["Content-Length"]))
                owner.requests.append((self.path, self.headers.get("Authorization"), json.loads(payload)))
                status, headers, body = owner.replies.pop(0)
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), SyntheticProvider)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.config = Config(f"http://127.0.0.1:{self.server.server_port}/v1", "unit_test_alias",
                             allow_loopback_http=True)
        self.env = patch.dict(os.environ, {"SHIELD_CLIPROXY_API_KEY": "synthetic-unit-test-key"})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.store.close()

    def completion(self, **changes):
        analysis = {"schemaVersion": "analysis_v1", "assessment": "benign",
                    "hypotheses": [{"code": "authorized_activity", "evidenceIds": ["event_1"]}],
                    "nextAction": "observe", "evidenceIds": ["event_1"], "readRequests": [], "limitations": []}
        analysis.update(changes)
        value = {"model": "unit_test_alias", "choices": [{"finish_reason": "stop",
                 "message": {"role": "assistant", "content": json.dumps(analysis)}}], "usage": {"total_tokens": 100}}
        return (200, {"Content-Type": "application/json"}, json.dumps(value).encode())

    def test_real_http_adapter_only_sends_fixed_path_sanitized_facts_without_tools(self):
        self.replies.append(self.completion())
        gateway = Gateway(self.config)
        reservations = []
        result = gateway.analyze(self.case, before_attempt=reservations.append)
        path, authorization, payload = self.requests[0]
        self.assertEqual(path, "/v1/chat/completions")
        self.assertEqual(authorization, "Bearer synthetic-unit-test-key")
        self.assertNotIn("synthetic-unit-test-key", json.dumps(payload))
        self.assertNotIn("tools", payload)
        self.assertEqual(payload["model"], "unit_test_alias")
        self.assertEqual(result["assessment"], "benign")
        self.assertEqual(len(reservations), 1)
        self.assertFalse(gateway.last_metadata["upstreamIdentityVerified"])

    def test_redirect_denied_and_response_body_not_echoed(self):
        self.replies.append((302, {"Location": "https://elsewhere.invalid", "Content-Type": "text/plain"},
                             b"synthetic-secret-in-provider-error"))
        with self.assertRaises(GatewayError) as raised:
            Gateway(self.config).analyze(self.case, before_attempt=lambda _: None)
        self.assertEqual(str(raised.exception), "PROVIDER_HTTP_FAILURE")
        self.assertEqual(len(self.requests), 1)

    def test_transient_retry_bounded_and_each_attempt_reserves_budget(self):
        self.replies.extend([(503, {"Content-Type": "application/json"}, b"{}"), self.completion()])
        reservations = []
        self.assertEqual(Gateway(self.config).analyze(self.case, before_attempt=reservations.append)["assessment"], "benign")
        self.assertEqual(len(reservations), 2)
        self.replies.extend([(503, {"Content-Type": "application/json"}, b"{}") for _ in range(2)])
        with self.assertRaises(GatewayError):
            Gateway(self.config).analyze(self.case, before_attempt=lambda _: None)
        self.assertEqual(len(self.requests), 4)

    def test_untrusted_completion_refs_tools_unknown_fields_and_oversize_fail_closed(self):
        for reply in (self.completion(evidenceIds=["other_case"]), self.completion(approved=True),
                      (200, {"Content-Type": "application/json"}, b"x" * 65537)):
            self.replies.append(reply)
            with self.assertRaises(GatewayError):
                Gateway(self.config).analyze(self.case, before_attempt=lambda _: None)

    def test_unknown_case_fields_cannot_smuggle_prompt_content(self):
        self.replies.append(self.completion())
        case = {**self.case, "rawPassword": "synthetic-canary-not-for-prompt"}
        Gateway(self.config).analyze(case, before_attempt=lambda _: None)
        self.assertNotIn("synthetic-canary-not-for-prompt", json.dumps(self.requests[0][2]))

    def test_unconfigured_and_configured_missing_credential_never_fallback_to_openai_key(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": "unrelated-canary"}, clear=True):
            self.assertIsNone(Gateway.from_env())
            with self.assertRaises(GatewayError) as raised:
                Gateway(self.config).analyze(self.case, before_attempt=lambda _: None)
            self.assertEqual(raised.exception.code, "CREDENTIAL_UNAVAILABLE")
        self.assertEqual(self.requests, [])

    def test_route_validation_and_duplicate_json_rejection(self):
        for url in ("http://example.com", "http://localhost:8317", "https://user:pass@example.com", "https://example.com/evil",
                    "https://example.com/v1?token=canary", "file:///tmp/config"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                Config(url, "unit_test_alias", allow_loopback_http=True)
        with self.assertRaises(ValueError):
            Config("http://127.0.0.1:8317/v1", "unit_test_alias")
        with self.assertRaises(ValueError):
            strict_json('{"verdict":1,"verdict":2}')


if __name__ == "__main__":
    unittest.main()
