"""Independent counterexamples; fixture HTTP is not a real AI-provider result."""

import json
import os
import gzip
import http.client
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from urllib.parse import urlsplit

from lab.anti_rea import PRIVATE_MARKER, write_artifacts
from lab.promotion import PromotionLab
from openshield.evaluation import compare
from openshield.gateway import Config, Gateway, GatewayError
from openshield.promotion import PromotionError


ROOT = Path(__file__).resolve().parents[1]


class SyntheticCompletionServer:
    """Transport test double: a recorded fixed completion, never evidence of AI skill."""

    def __init__(self, malformed=False):
        self.malformed, self.requests = malformed, []

    def __enter__(self):
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                owner.requests.append(payload)
                context = json.loads(payload["messages"][1]["content"])
                analysis = {"schemaVersion": "analysis_v1", "assessment": "suspicious",
                            "hypotheses": [{"code": "business_abuse", "evidenceIds": context["evidenceIds"]}],
                            "nextAction": "needs_human", "evidenceIds": context["evidenceIds"],
                            "readRequests": [], "limitations": []}
                content = "SYNTHETIC_UNTRUSTED_PROVIDER_OUTPUT" if owner.malformed else json.dumps(analysis)
                body = json.dumps({"model": "transport_test_only", "choices": [{"finish_reason": "stop",
                                   "message": {"content": content}}], "usage": {"total_tokens": 50}}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


class ComparisonFairnessChallenge(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "cases.json"
        self.corpus = {"schemaVersion": "heldout_corpus_v1", "synthetic": True,
                       "description": "SYNTHETIC_HIDDEN_DESCRIPTION_CANARY",
                       "registration": {"replayClockUTC": "2026-10-24T00:42:00Z"},
                       "cases": []}
        for case_id, event_id in (("opaque_r7", "opaque_h4"), ("opaque_m2", "opaque_k8")):
            event = {"schemaVersion": "lab_event_v1", "id": event_id, "projectId": "p_eval",
                     "caseId": case_id, "assetId": "a_eval", "sourceId": "lab",
                     "observedAt": "2026-10-24T00:41:00Z", "dataClass": "synthetic",
                     "kind": "app_operation", "facts": {"authorized": False, "count": 1}}
            self.corpus["cases"].append({"id": case_id, "group": "SYNTHETIC_HIDDEN_GROUP_CANARY",
                                         "input": {"events": [event]},
                                         "truth": {"ingest": "accept", "incident": "supported",
                                                   "privateNote": "SYNTHETIC_HIDDEN_TRUTH_CANARY"}})
        self.path.write_text(json.dumps(self.corpus), encoding="utf-8")

    def tearDown(self):
        self.directory.cleanup()

    def test_actual_http_prompt_carries_facts_without_evaluator_truth_or_credentials(self):
        with SyntheticCompletionServer() as server:
            route = Config(server.url, "transport_test_only", allow_loopback_http=True)
            with patch.dict(os.environ, {"SHIELD_CLIPROXY_API_KEY": "SYNTHETIC_AUTH_CANARY"}):
                report = compare(self.path, Gateway(route))
            self.assertEqual(len(server.requests), 2)
            prompt = json.dumps(server.requests)
            for hidden in ("SYNTHETIC_HIDDEN_DESCRIPTION_CANARY", "SYNTHETIC_HIDDEN_GROUP_CANARY",
                           "SYNTHETIC_HIDDEN_TRUTH_CANARY", "SYNTHETIC_AUTH_CANARY"):
                self.assertNotIn(hidden, prompt)
            for payload, scenario in zip(server.requests, self.corpus["cases"]):
                context = json.loads(payload["messages"][1]["content"])
                self.assertEqual(context["timeline"], scenario["input"]["events"])
                self.assertEqual(set(context["allowedActions"]), {"set_site_ingress_mode", "restore_isolated"})
                self.assertNotIn("tools", payload)
            self.assertEqual(report["arms"]["ai"]["metrics"]["providerUnavailableCases"], 0)
            self.assertTrue(all(row["available"] for row in report["arms"]["ai"]["cases"]))
            self.assertFalse(report["manifest"]["aiRoute"]["upstreamIdentityVerified"])

    def test_provider_failure_cannot_credit_correct_fallback_to_ai(self):
        with SyntheticCompletionServer(malformed=True) as server:
            route = Config(server.url, "transport_test_only", allow_loopback_http=True)
            with patch.dict(os.environ, {"SHIELD_CLIPROXY_API_KEY": "SYNTHETIC_AUTH_CANARY"}):
                report = compare(self.path, Gateway(route))
        self.assertEqual(report["arms"]["baseline"]["metrics"]["truePositives"], 2)
        ai = report["arms"]["ai"]
        self.assertEqual(ai["metrics"]["truePositives"], 0)
        self.assertEqual(ai["metrics"]["policyAcceptableDecisions"], 0)
        self.assertEqual(ai["metrics"]["providerUnavailableCases"], 2)
        self.assertTrue(all(row["assessment"] == "suspicious" and not row["correct"] and not row["available"]
                            and row["aiStatus"] == "degraded_model" for row in ai["cases"]))
        self.assertNotIn("SYNTHETIC_UNTRUSTED_PROVIDER_OUTPUT", json.dumps(report))

    def test_unconfigured_provider_and_insufficient_budget_never_invent_ai_score(self):
        unavailable = compare(self.path)
        self.assertEqual(unavailable["arms"]["ai"]["status"], "blocked_provider_unconfigured")
        self.assertIsNone(unavailable["arms"]["ai"]["metrics"])
        with SyntheticCompletionServer() as server:
            route = Config(server.url, "transport_test_only", allow_loopback_http=True, global_token_limit=1)
            with patch.dict(os.environ, {"SHIELD_CLIPROXY_API_KEY": "SYNTHETIC_AUTH_CANARY"}):
                limited = compare(self.path, Gateway(route))
            self.assertEqual(server.requests, [])
        ai = limited["arms"]["ai"]
        self.assertEqual(ai["metrics"]["calls"], 0)
        self.assertEqual(ai["metrics"]["truePositives"], 0)
        self.assertTrue(all(row["aiStatus"] == "degraded_budget" for row in ai["cases"]))


class GatewayAbsoluteDeadlineChallenge(unittest.TestCase):
    def test_trickled_response_headers_cannot_extend_absolute_call_deadline(self):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                try:
                    self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Slow: ")
                    self.wfile.flush()
                    for _ in range(40):
                        self.wfile.write(b"x")
                        self.wfile.flush()
                        time.sleep(0.025)
                    self.wfile.write(b"\r\nContent-Length: 2\r\n\r\n{}")
                    self.wfile.flush()
                except OSError:
                    pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            gateway = Gateway(Config(f"http://127.0.0.1:{server.server_port}", "transport_test_only",
                                     allow_loopback_http=True))
            started = time.monotonic()
            with self.assertRaises(GatewayError):
                gateway._request(b"{}", "SYNTHETIC_AUTH_CANARY", started + 0.15)
            self.assertLess(time.monotonic() - started, 0.65,
                            "socket inactivity timeout allowed a slow header stream past the absolute deadline")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


class RealPublicationChallenge(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        _, self.candidate = write_artifacts(Path(self.directory.name) / "releases")

    def tearDown(self):
        self.directory.cleanup()

    @staticmethod
    def get(url, path, encoding="identity", method="GET"):
        parsed = urlsplit(url)
        connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=2)
        try:
            connection.request(method, path, headers={"Accept-Encoding": encoding})
            reply = connection.getresponse()
            body = reply.read(65537)
            if reply.getheader("Content-Encoding") == "gzip":
                body = gzip.decompress(body)
            return reply.status, body
        finally:
            connection.close()

    def stage(self, lab, preview):
        return lab.gate.stage(self.candidate, preview.url, authorized=True)

    def promote(self, lab, staged):
        approval = lab.gate.approve_promotion(staged["candidateId"], staged["expectedGeneration"])
        return approval, lab.gate.promote(approval)

    def test_promotion_cannot_recall_cache_or_historical_download_but_explicit_retirement_stops_delivery(self):
        with PromotionLab() as lab, lab.preview(self.candidate) as preview:
            old = {}
            for path in ("/app.js", "/app.js.map"):
                for encoding in ("identity", "gzip"):
                    status, body = self.get(lab.edge_url, path, encoding)
                    self.assertEqual(status, 200)
                    self.assertIn(PRIVATE_MARKER.encode(), body)
                    old[(path, encoding)] = body
            _, promoted = self.promote(lab, self.stage(lab, preview))
            self.assertEqual(promoted["generation"], 1)
            for path in ("/app.js", "/app.js.map"):
                for encoding in ("identity", "gzip"):
                    _, origin = self.get(lab.origin_url, path, encoding)
                    self.assertNotIn(PRIVATE_MARKER.encode(), origin)
                    self.assertEqual(self.get(lab.edge_url, path, encoding), (200, old[(path, encoding)]))
            grant = lab.gate.approve_retirement(1)
            lab.gate.retire(grant)
            for url in (lab.origin_url, lab.edge_url):
                for encoding in ("identity", "gzip"):
                    self.assertEqual(self.get(url, "/app.js.map", encoding), (410, b""))
                    for path in ("/", "/index.html", "/app.js"):
                        expected = (self.candidate / ("index.html" if path == "/" else path[1:])).read_bytes()
                        self.assertEqual(self.get(url, path, encoding), (200, expected))
            self.assertTrue(all(PRIVATE_MARKER.encode() in body for body in old.values()))

    def test_duplicate_approved_promotions_have_one_atomic_generation_change(self):
        with PromotionLab() as lab, lab.preview(self.candidate) as preview:
            staged = self.stage(lab, preview)
            grants = [lab.gate.approve_promotion(staged["candidateId"], 0) for _ in range(2)]
            results, barrier = [], threading.Barrier(2)

            def compete(grant):
                barrier.wait(timeout=3)
                try:
                    results.append(lab.gate.promote(grant)["status"])
                except PromotionError:
                    results.append("denied")

            threads = [threading.Thread(target=compete, args=(grant,)) for grant in grants]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
            self.assertEqual(sorted(results), ["denied", "promoted"])
            self.assertEqual(lab.gate.state["generation"], 1)
            for grant in grants:
                with self.assertRaises(PromotionError):
                    lab.gate.promote(grant)

    def test_last_moment_source_swap_cannot_change_installed_approved_snapshot(self):
        from openshield import promotion
        with PromotionLab() as lab, lab.preview(self.candidate) as preview:
            staged = self.stage(lab, preview)
            grant = lab.gate.approve_promotion(staged["candidateId"], 0)
            expected = (self.candidate / "app.js").read_bytes()
            snapshot = promotion._snapshot

            def change_after_validated_read(directory):
                result = snapshot(directory)
                (self.candidate / "app.js").write_bytes(expected + b"\n// SYNTHETIC_LATE_PRIVATE_SWAP\n")
                return result

            with patch.object(promotion, "_snapshot", side_effect=change_after_validated_read):
                lab.gate.promote(grant)
            self.assertIn(b"SYNTHETIC_LATE_PRIVATE_SWAP", (self.candidate / "app.js").read_bytes())
            self.assertEqual(self.get(lab.origin_url, "/app.js"), (200, expected))

    def test_expiry_untrusted_http_and_changed_source_never_change_active_release(self):
        clock = [100.0]
        with PromotionLab(clock=lambda: clock[0]) as lab, lab.preview(self.candidate) as preview:
            initial = lab.gate.state
            for authorization in (False, 1, "true", None):
                with patch("openshield.promotion.delivery_audit", side_effect=AssertionError("Unauthorized network access")):
                    with self.assertRaises(PromotionError):
                        lab.gate.stage(self.candidate, preview.url, authorized=authorization)
            self.assertEqual(self.get(lab.origin_url, "/approve", method="POST")[0], 405)
            self.assertEqual(lab.gate.state, initial)
            staged = self.stage(lab, preview)
            grant = lab.gate.approve_promotion(staged["candidateId"], 0)
            clock[0] = 110.0
            with self.assertRaises(PromotionError):
                lab.gate.promote(grant)
            self.assertEqual(lab.gate.state, initial)
            staged = self.stage(lab, preview)
            grant = lab.gate.approve_promotion(staged["candidateId"], 0)
            path = self.candidate / "app.js"
            path.write_bytes(path.read_bytes() + b"\n// SYNTHETIC_CHANGED_AFTER_APPROVAL\n")
            with self.assertRaises(PromotionError):
                lab.gate.promote(grant)
            self.assertEqual(lab.gate.state, initial)

    def test_old_inflight_cache_fill_cannot_resurrect_retired_map_or_stale_script(self):
        with PromotionLab() as lab, lab.preview(self.candidate) as preview:
            epoch, _ = lab.gate.cached("/app.js.map", "gzip")
            old_map = lab.gate.origin("/app.js.map", "gzip")
            old_script = lab.gate.origin("/app.js", "identity")
            self.promote(lab, self.stage(lab, preview))
            lab.gate.retire(lab.gate.approve_retirement(1))
            self.assertEqual(lab.gate.cache_response(epoch, "/app.js.map", "gzip", old_map), (410, b"", False))
            self.assertEqual(lab.gate.cache_response(epoch, "/app.js", "identity", old_script), (503, b"", False))
            self.assertEqual(self.get(lab.edge_url, "/app.js.map", "gzip"), (410, b""))
            self.assertEqual(self.get(lab.edge_url, "/app.js"), (200, (self.candidate / "app.js").read_bytes()))


class RealBusinessFlowChallenge(unittest.TestCase):
    @unittest.skipUnless(shutil.which("go"), "Go toolchain unavailable")
    def test_exact_go_source_with_independent_effect_observers_and_counterexamples(self):
        source = r'''package flowlab
import (
 "sync"
 "testing"
 "time"
)
func TestIndependentActualDisclosureAndEveryVerifierRevocation(t *testing.T) {
 unsafe:=newLab(false);defer unsafe.close();u,_:=unsafe.session("principal_alpha")
 wrong:=sample("read");wrong.Object="object_beta"
 r,e:=unsafe.post("/v1/resource",u,"",encode(wrong));if e!=nil || r.status!=200 || r.objectValue!="synthetic_beta" {t.Fatal("negative control did not disclose other object's value")}
 safe:=newLab(true);defer safe.close();s,_:=safe.session("principal_alpha");b,_:=safe.session("principal_beta")
 for _,path:=range []string{"/v1/resource","/v2/resource"} {
  r,e=safe.post(path,s,"",encode(wrong));if e!=nil || r.status!=403 || r.objectValue!="" || safe.ledger.snapshot().Reads!=0 {t.Fatal("cross-object value or effect escaped")}
 }
 own:=sample("read");r,e=safe.post("/v2/resource",s,"",encode(own));if e!=nil || r.status!=200 || r.objectValue!="synthetic_alpha" {t.Fatal("valid read destroyed")}
 safe.revoke(s);before:=safe.ledger.snapshot()
 for _,path:=range []string{"/v1/resource","/v2/resource"} {
  r,e=safe.post(path,s,"",encode(own));if e!=nil || r.status!=403 || r.objectValue!="" || safe.ledger.snapshot()!=before {t.Fatal("revoked token still reads at a declared verifier")}
 }
 beta:=own;beta.Object="object_beta";r,e=safe.post("/v2/resource",b,"",encode(beta));if e!=nil || r.status!=200 || r.objectValue!="synthetic_beta" {t.Fatal("unrelated identity was locked out")}
}
func TestIndependentIdempotencyRacesAndPayloadConflict(t *testing.T) {
 l:=newLab(true);defer l.close();s,_:=l.session("principal_alpha")
 op:=sample("charge");op.Key="tx_shared";op.Units=1
 var wg sync.WaitGroup
 grants:=make([]string,24);for i:=range grants {g,e:=l.issue(s,op,true);if e!=nil {t.Fatal(e)};grants[i]=g}
 for _,g:=range grants {wg.Add(1);go func(g string){defer wg.Done();r,e:=l.post("/v1/resource",s,g,encode(op));if e!=nil || r.status!=200 && r.status!=429 {t.Errorf("unexpected race status %v %v",r,e)}}(g)};wg.Wait()
 if l.ledger.rowCount(op.Key)!=1 || l.ledger.snapshot().ChargedUnits!=1 {t.Fatal("multiple independently counted business commits")}
 changed:=op;changed.Units=2;g,e:=l.issue(s,changed,true);if e!=nil {t.Fatal(e)}
 r,e:=l.post("/v2/resource",s,g,encode(changed));if e!=nil || r.status!=409 || l.ledger.rowCount(op.Key)!=1 {t.Fatal("same key allowed changed business effect")}
 changed.Key="tx_fresh";g,e=l.issue(s,changed,true);if e!=nil {t.Fatal(e)};r,e=l.post("/v1/resource",s,g,encode(changed))
 if e!=nil || r.status!=200 || l.ledger.rowCount(changed.Key)!=1 || l.ledger.snapshot().ChargedUnits!=3 {t.Fatal("valid new transaction destroyed")}
 g,e=l.issue(s,changed,true);if e!=nil {t.Fatal(e)};l.advance(30*time.Second);before:=l.ledger.snapshot()
 r,e=l.post("/v1/resource",s,g,encode(changed));if e!=nil || r.status!=403 || l.ledger.snapshot()!=before {t.Fatal("expired capability retained effect authority")}
}
func TestIndependentActualReceiverAndRedirectEffects(t *testing.T) {
 unsafe:=newLab(false);defer unsafe.close();u,_:=unsafe.session("principal_alpha")
 op:=sample("export");op.Recipient="inbox_outside";r,e:=unsafe.post("/v1/resource",u,"",encode(op));_,out,requests:=unsafe.receivers.snapshot()
 if e!=nil || r.status!=200 || out!=1 || requests!=1 {t.Fatal("negative control did not deliver actual synthetic payload")}
 safe:=newLab(true);defer safe.close();s,_:=safe.session("principal_alpha")
 r,e=safe.post("/v1/resource",s,"",encode(op));a,out,requests:=safe.receivers.snapshot();if e!=nil || r.status!=403 || a!=0 || out!=0 || requests!=0 {t.Fatal("forbidden recipient observed a request")}
 op.Recipient="inbox_alpha";g,e:=safe.issue(s,op,true);if e!=nil {t.Fatal(e)};r,e=safe.post("/v1/resource",s,g,encode(op));a,out,requests=safe.receivers.snapshot()
 if e!=nil || r.status!=200 || a!=1 || out!=0 || requests!=0 {t.Fatal("positive delivery did not reach allowed recipient")}
 safe.receivers.mu.Lock();safe.receivers.redirect=true;safe.receivers.mu.Unlock();g,e=safe.issue(s,op,true);if e!=nil {t.Fatal(e)}
 r,e=safe.post("/v2/resource",s,g,encode(op));a,out,requests=safe.receivers.snapshot();if e!=nil || r.status!=502 || a!=1 || out!=0 || requests!=0 {t.Fatal("redirect leaked a request to forbidden receiver")}
 r,e=safe.post("/v2/resource",s,g,encode(op));a,out,requests=safe.receivers.snapshot();if e!=nil || r.status!=403 || a!=1 || out!=0 || requests!=0 {t.Fatal("replay retried ambiguous transfer")}
}
'''
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory)
            (package / "go.mod").write_text("module independent-flow-challenge\n\ngo 1.24\n", encoding="utf-8")
            for path in (ROOT / "runtime-go/flowlab").glob("*.go"):
                if not path.name.endswith("_test.go"):
                    shutil.copyfile(path, package / path.name)
            (package / "independent_test.go").write_text(source, encoding="utf-8")
            result = subprocess.run(["go", "test", "-count=1", "-v", "."], cwd=package, capture_output=True,
                                    text=True, timeout=45, shell=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for name in ("TestIndependentActualDisclosureAndEveryVerifierRevocation",
                         "TestIndependentIdempotencyRacesAndPayloadConflict", "TestIndependentActualReceiverAndRedirectEffects"):
                self.assertIn(name, result.stdout)


if __name__ == "__main__":
    unittest.main()
