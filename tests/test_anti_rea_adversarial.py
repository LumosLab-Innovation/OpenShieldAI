"""Independent falsifiers: passing a release policy is not reverse-engineering immunity."""

import gzip
import contextlib
import io
from http.client import HTTPConnection, HTTPException
import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import unittest
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from openshield.exposure import exposure_audit
from openshield.cli import main
from lab.anti_rea import AntiReaLab


class ReleaseExposureChallenge(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def write(self, name, value):
        destination = self.root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(value if isinstance(value, bytes) else value.encode())
        return destination

    def audit(self, **options):
        return exposure_audit(self.root, authorized=True, **options)

    def codes(self, report):
        return {item["code"] for item in report["categories"] + report["gaps"]}

    def test_authorization_is_not_truthiness(self):
        self.write("client.js", "export const ui='public';")
        for value in (False, None, 1, "true", {}, []):
            with self.subTest(value=value):
                report = exposure_audit(self.root, authorized=value)
                self.assertEqual(report["status"], "blocked")
                self.assertEqual(report["counts"]["files"], 0)

    def test_orphan_map_without_bundle_reference_still_blocks(self):
        self.write("client.js", "export const ui='public';")
        self.write("orphan.map", json.dumps({"version": 3, "sources": ["private.ts"],
                                             "sourcesContent": ["synthetic internal formula"]}))
        report = self.audit()
        self.assertEqual(report["status"], "blocked")
        self.assertTrue({"SOURCE_MAP_FILE", "SOURCE_MAP_ORIGINAL_CONTENT"} <= self.codes(report))

    def test_map_with_json_extension_still_blocks(self):
        self.write("manifest.json", '{"version":3,"sections":[]}')
        self.assertIn("SOURCE_MAP_FILE", self.codes(self.audit()))

    def test_inline_map_pragmas_inside_html_are_not_clean(self):
        self.write("index.html", '<script>const x=1;\n//# sourceMappingURL=data:application/json;base64,e30=\n</script>')
        self.assertNotEqual(self.audit()["status"], "pass")

    def test_quoted_map_lookalike_is_not_an_executable_pragma(self):
        self.write("client.js", 'export const help="//# sourceMappingURL=public-documentation";')
        report = self.audit()
        self.assertEqual(report["status"], "pass")
        self.assertNotIn("SOURCE_MAP_REFERENCE", self.codes(report))

    def test_encoded_map_scheme_does_not_bypass_inline_detection(self):
        self.write("client.js", "//# sourceMappingURL=d%61ta:application/json;base64,e30=\n")
        self.assertIn("INLINE_SOURCE_MAP", self.codes(self.audit()))

    def test_compressed_copy_prevents_clean_verdict_without_decompression(self):
        self.write("client.js", "export const ui='public';")
        self.write("client.js.gz", gzip.compress(b"//# sourceMappingURL=private.map\n"))
        report = self.audit()
        self.assertNotEqual(report["status"], "pass")
        self.assertFalse(report["complete"])
        self.assertIn("UNINSPECTED_CONTAINER", self.codes(report))

    def test_hardlink_prevents_clean_verdict(self):
        original = self.write("client.js", "export const ui='public';")
        os.link(original, self.root / "copy.js")
        report = self.audit()
        self.assertNotEqual(report["status"], "pass")
        self.assertIn("HARDLINK_NOT_ALLOWED", self.codes(report))

    def test_limits_cannot_create_false_clean_or_nonfinite_budget(self):
        self.write("client.js", "export const ui='public';")
        for limits in ({"fileBytes": 1}, {"files": 0}, {"files": True},
                       {"seconds": float("nan")}, {"seconds": float("inf")}, {"unknown": 1}):
            with self.subTest(limits=limits):
                self.assertNotEqual(self.audit(limits=limits)["status"], "pass")

    def test_reports_never_echo_source_map_content_or_sensitive_filename(self):
        marker = "SYNTHETIC_DO_NOT_ECHO_47B6"
        self.write(marker + ".map", json.dumps({"version": 3, "sources": [marker],
                                                "sourcesContent": [marker]}))
        report = self.audit()
        self.assertEqual(report["status"], "blocked")
        self.assertNotIn(marker, json.dumps(report))
        self.assertFalse(report["targetCodeExecuted"])
        self.assertFalse(report["networkRequestsMade"])
        self.assertFalse(report["isFinding"])

    def test_complete_digest_binds_all_inspected_paths_and_bytes(self):
        original = self.write("client.js", "export const ui='public';")
        first = self.audit()
        original.rename(self.root / "other.js")
        renamed = self.audit()
        self.write("other.js", "export const ui='different';")
        changed = self.audit()
        self.assertTrue(all(item["complete"] for item in (first, renamed, changed)))
        self.assertEqual(len({item["artifactSha256"] for item in (first, renamed, changed)}), 3)

    def test_pass_explicitly_does_not_claim_arbitrary_secret_detection(self):
        # A usable regression gate cannot prove confidentiality of arbitrary literals.
        self.write("client.js", 'export const answer="SYNTHETIC_PRIVATE"+"_FORMULA";')
        report = self.audit()
        self.assertEqual(report["status"], "pass")
        self.assertIn("NO_GENERAL_SECRET_OR_PII_DETECTION", report["limitations"])
        self.assertIn("PASS_IS_ONLY_THIS_RELEASE_POLICY", report["limitations"])

    def test_cli_report_hardlink_cannot_overwrite_audited_release_bytes(self):
        release = self.root / "release"
        release.mkdir()
        source = release / "client.js"
        expected = b"export const ui='owned-synthetic';"
        source.write_bytes(expected)
        report = self.root / "outside-report.json"
        os.link(source, report)
        with contextlib.redirect_stdout(io.StringIO()):
            try:
                main(["release-audit", str(release), "--authorized", "--output", str(report)])
            except ValueError:
                pass  # A refused output target is an acceptable fail-closed result.
        self.assertEqual(source.read_bytes(), expected)
        self.assertEqual(list(self.root.glob(".shield-report-*")), [])


class ServerAuthorityChallenge(unittest.TestCase):
    """Real loopback HTTP; deliberately bypasses the fixture's client helper/UI."""

    def setUp(self):
        self.now = [100.0]
        self.lab = AntiReaLab(protected=True, clock=lambda: self.now[0])
        self.lab.__enter__()
        self.addCleanup(self.lab.__exit__, None, None, None)
        self.alice = self.lab.issue_session("alice")
        self.bob = self.lab.issue_session("bob")

    def http(self, path, payload, session=None, capability=None, raw=None):
        headers = {"Content-Type": "application/json"}
        if session:
            headers["Authorization"] = "Bearer " + session
        if capability:
            headers["X-Lab-Capability"] = capability
        body = json.dumps(payload).encode() if raw is None else raw
        request = Request(self.lab.url + path, data=body, headers=headers, method="POST")
        try:
            with urlopen(request, timeout=3) as response:
                return response.status, json.loads(response.read(65536))
        except HTTPError as error:
            return error.code, json.loads(error.read(65536))

    def grant(self, session=None, obj="quote-a", quantity=1):
        code, body = self.http("/api/grants", {"object": obj, "quantity": quantity}, session or self.alice)
        self.assertTrue(200 <= code < 300, body)
        return body["capability"]

    def quote(self, capability, session=None, obj="quote-a", quantity=1):
        return self.http("/api/quote", {"object": obj, "quantity": quantity}, session or self.alice, capability)

    def explicit_headers(self, path, headers):
        body = b'{"object":"quote-a","quantity":1}'
        connection = HTTPConnection("127.0.0.1", urlsplit(self.lab.url).port, timeout=3)
        try:
            connection.putrequest("POST", path)
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", str(len(body)))
            for name, value in headers:
                connection.putheader(name, value)
            connection.endheaders(body)
            response = connection.getresponse()
            return response.status, json.loads(response.read(65536))
        finally:
            connection.close()

    def test_direct_requests_without_capability_or_identity_do_not_gain_authority(self):
        for session, capability in ((None, None), (self.alice, None), ("synthetic-invalid-session", None),
                                    (self.alice, "synthetic-invalid-capability")):
            with self.subTest(session=bool(session), capability=bool(capability)):
                code, _ = self.http("/api/quote", {"object": "quote-a", "quantity": 1}, session, capability)
                self.assertTrue(400 <= code < 500)

    def test_auth_grammar_and_duplicate_authority_headers_fail_closed(self):
        for value in (self.alice, "Basic " + self.alice):
            code, _ = self.explicit_headers("/api/grants", [("Authorization", value)])
            self.assertTrue(400 <= code < 500)
        code, _ = self.explicit_headers("/api/grants", [("Authorization", "Bearer " + self.alice)] * 2)
        self.assertTrue(400 <= code < 500)
        capability = self.grant()
        code, _ = self.explicit_headers("/api/quote", [("Authorization", "Bearer " + self.alice),
                                                     ("X-Lab-Capability", capability),
                                                     ("X-Lab-Capability", "synthetic-invalid")])
        self.assertTrue(400 <= code < 500)
        self.assertEqual(self.quote(capability)[0], 200)

    def test_grant_does_not_cross_object_or_session_and_rejection_does_not_spend_it(self):
        capability = self.grant()
        other_alice_session = self.lab.issue_session("alice")
        attempts = ((self.alice, "quote-b", 1), (self.alice, "quote-a", 2),
                    (self.bob, "quote-a", 1), (other_alice_session, "quote-a", 1))
        for session, obj, quantity in attempts:
            with self.subTest(obj=obj, quantity=quantity):
                code, _ = self.quote(capability, session, obj, quantity)
                self.assertTrue(400 <= code < 500)
        code, answer = self.quote(capability)
        self.assertEqual((code, answer), (200, {"totalCents": 166}))

    def test_object_access_is_checked_before_minting_grant(self):
        for session, obj in ((self.alice, "quote-b"), (self.bob, "quote-a"), (self.alice, "unknown")):
            code, _ = self.http("/api/grants", {"object": obj, "quantity": 1}, session)
            self.assertTrue(400 <= code < 500)

    def test_single_use_is_atomic_across_concurrent_http_requests(self):
        capability = self.grant()
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.quote(capability)[0], range(2)))
        self.assertEqual(results.count(200), 1, results)
        self.assertTrue(all(code == 200 or 400 <= code < 500 for code in results))

    def test_expiry_uses_server_clock(self):
        capability = self.grant()
        self.now[0] += 31
        code, _ = self.quote(capability)
        self.assertTrue(400 <= code < 500)

    def test_new_sessions_and_grants_do_not_reset_principal_budget(self):
        for quantity in range(1, 5):
            session = self.lab.issue_session("alice")
            capability = self.grant(session, quantity=quantity)
            self.assertEqual(self.quote(capability, session, quantity=quantity)[0], 200)
        session = self.lab.issue_session("alice")
        code, body = self.http("/api/grants", {"object": "quote-a", "quantity": 5}, session)
        if 200 <= code < 300:
            code, _ = self.quote(body["capability"], session, quantity=5)
        self.assertEqual(code, 429)
        # Another authorized subject has its own remaining budget and intended result.
        capability = self.grant(self.bob, obj="quote-b", quantity=100)
        self.assertEqual(self.quote(capability, self.bob, "quote-b", 100),
                         (200, {"totalCents": 13729}))

    def test_schema_rejects_bool_nonfinite_and_unknown_fields(self):
        for quantity in (True, False, None, "1", 1.0, -1, 0, 101, float("nan"), float("inf")):
            with self.subTest(quantity=quantity):
                code, _ = self.http("/api/grants", {"object": "quote-a", "quantity": quantity}, self.alice)
                self.assertTrue(400 <= code < 500)
        code, _ = self.http("/api/grants", {"object": "quote-a", "quantity": 1, "role": "admin"}, self.alice)
        self.assertTrue(400 <= code < 500)

    def test_oversized_or_malformed_body_does_not_succeed_or_expose_trace(self):
        for raw in (b"{" + b"x" * 65536, b"{broken-json"):
            try:
                code, body = self.http("/api/grants", {}, self.alice, raw=raw)
            except (ConnectionError, HTTPException):
                # Closing before draining an oversized body may reset TCP on Windows.
                self.assertGreater(len(raw), 512)
                continue
            self.assertTrue(400 <= code < 500)
            self.assertNotIn("Traceback", json.dumps(body))
        self.assertEqual(self.lab.audit["accepted"], 0)
        capability = self.grant()
        self.assertEqual(self.quote(capability)[0], 200)

    def test_two_allowed_outputs_still_reveal_this_simple_synthetic_formula(self):
        results = []
        for quantity in (1, 2, 3):
            capability = self.grant(quantity=quantity)
            code, body = self.quote(capability, quantity=quantity)
            self.assertEqual(code, 200)
            results.append(body["totalCents"])
        inferred_slope = results[1] - results[0]
        inferred_intercept = results[0] - inferred_slope
        self.assertEqual(inferred_slope * 3 + inferred_intercept, results[2])


if __name__ == "__main__":
    unittest.main()
