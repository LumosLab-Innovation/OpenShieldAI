"""Independent falsifiers for selected real-loopback defense boundaries."""

import gzip
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest

from lab.anti_rea import AntiReaLab, write_artifacts
from openshield.authority import Authority, AuthorityError


OPERATION = {"object": "quote-a", "quantity": 1}
ROOT = Path(__file__).resolve().parents[1]


class DurableAuthorityChallenge(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "authority.sqlite3"

    def tearDown(self):
        self.directory.cleanup()

    def authority(self, **options):
        return Authority(self.path, clock=lambda: 1000, **options)

    def grant(self, authority, session, quantity=1):
        status, body = authority.operate("/api/grants", session, "", "quote-a", quantity)
        self.assertEqual(status, 201, body)
        return body["capability"]

    def test_restart_does_not_resurrect_consumed_grant(self):
        first = self.authority()
        session = first.issue_session()
        capability = self.grant(first, session)
        self.assertEqual(first.operate("/api/quote", session, capability, "quote-a", 1)[0], 200)
        reopened = self.authority()
        self.assertEqual(reopened.operate("/api/quote", session, capability, "quote-a", 1)[0], 403)
        self.assertEqual(reopened.audit["accepted"], 1)

    def test_revocation_invalidates_existing_grant_after_restart(self):
        first = self.authority()
        session = first.issue_session()
        capability = self.grant(first, session)
        self.assertTrue(first.revoke_session(session))
        reopened = self.authority()
        self.assertFalse(reopened.revoke_session(session))
        self.assertEqual(reopened.operate("/api/quote", session, capability, "quote-a", 1)[0], 403)
        self.assertEqual(reopened.audit["accepted"], 0)

    def test_mismatch_does_not_consume_real_matching_authority(self):
        authority = self.authority()
        session = authority.issue_session()
        other = authority.issue_session()
        capability = self.grant(authority, session)
        for scope in ((other, "quote-a", 1), (session, "quote-b", 1), (session, "quote-a", 2)):
            with self.subTest(scope=scope[1:]):
                self.assertEqual(authority.operate("/api/quote", scope[0], capability, *scope[1:])[0], 403)
        self.assertEqual(authority.operate("/api/quote", session, capability, "quote-a", 1)[0], 200)

    def test_quota_is_principal_wide_across_restart_and_new_sessions(self):
        for _ in range(4):
            authority = self.authority()
            session = authority.issue_session()
            capability = self.grant(authority, session)
            self.assertEqual(authority.operate("/api/quote", session, capability, "quote-a", 1)[0], 200)
        reopened = self.authority()
        session = reopened.issue_session()
        self.assertEqual(reopened.operate("/api/grants", session, "", "quote-a", 1)[0], 429)
        bob = reopened.issue_session("bob")
        self.assertEqual(reopened.operate("/api/grants", bob, "", "quote-b", 1)[0], 201)

    def test_clock_rollback_and_configuration_drift_fail_closed(self):
        authority = self.authority()
        session = authority.issue_session()
        capability = self.grant(authority, session)
        with self.assertRaises(AuthorityError):
            Authority(self.path, clock=lambda: 999)
        for config in ({"quota": 5}, {"grant_ttl": 31}):
            with self.subTest(config=config), self.assertRaises(AuthorityError):
                self.authority(**config)
        self.assertEqual(self.authority().operate("/api/quote", session, capability, "quote-a", 1)[0], 200)

    def test_only_hashes_of_ephemeral_credentials_persist(self):
        authority = self.authority()
        session = authority.issue_session()
        capability = self.grant(authority, session)
        data = b"".join(path.read_bytes() for path in self.path.parent.iterdir())
        for token in (session, capability):
            self.assertNotIn(token.encode(), data)
            self.assertIn(hashlib.sha256(token.encode()).hexdigest().encode(), data)

    def test_corrupt_deleted_and_replaced_state_never_reinitializes_authority(self):
        authority = self.authority()
        session = authority.issue_session()
        capability = self.grant(authority, session)
        self.path.unlink()
        with self.assertRaises(AuthorityError):
            authority.operate("/api/quote", session, capability, "quote-a", 1)
        self.assertFalse(self.path.exists())
        self.path.write_bytes(b"SYNTHETIC_INVALID_SQLITE")
        with self.assertRaises(AuthorityError):
            self.authority()

    def compete(self, capabilities, session, quota=4):
        script = """import json,sys
from pathlib import Path
from openshield.authority import Authority
request=json.loads(sys.stdin.readline())
authority=Authority(Path(request['path']),clock=lambda:1000,quota=request['quota'])
print('ready',flush=True)
sys.stdin.readline()
print(authority.operate('/api/quote',request['session'],request['capability'],'quote-a',1)[0],flush=True)
"""
        processes = []
        try:
            for capability in capabilities:
                process = subprocess.Popen([sys.executable, "-c", script], cwd=ROOT, stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                process.stdin.write(json.dumps({"path": str(self.path), "quota": quota,
                                                "session": session, "capability": capability}) + "\n")
                process.stdin.flush()
                processes.append(process)
            for process in processes:
                self.assertEqual(process.stdout.readline().strip(), "ready")
            for process in processes:
                process.stdin.write("go\n")
                process.stdin.flush()
            statuses = []
            for process in processes:
                stdout, stderr = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, stderr)
                statuses.append(int(stdout.strip()))
            return statuses
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)

    def test_separate_processes_cannot_consume_the_same_grant_twice(self):
        authority = self.authority()
        session = authority.issue_session()
        capability = self.grant(authority, session)
        self.assertEqual(sorted(self.compete([capability] * 2, session)), [200, 403])
        self.assertEqual(self.authority().audit["accepted"], 1)

    def test_distinct_grants_racing_share_last_principal_budget(self):
        authority = self.authority(quota=1)
        session = authority.issue_session()
        capabilities = [self.grant(authority, session) for _ in range(2)]
        self.assertEqual(sorted(self.compete(capabilities, session, quota=1)), [200, 429])
        self.assertEqual(self.authority(quota=1).audit["accepted"], 1)

    def test_actual_http_session_revocation_and_quota_survive_restart(self):
        with AntiReaLab(state_path=self.path, clock=lambda: 1000, quota=1) as first:
            session = first.issue_session()
            status, result = first.request("POST", "/api/grants", OPERATION, session)
            self.assertEqual(status, 201)
            capability = result["capability"]
        with AntiReaLab(state_path=self.path, clock=lambda: 1000, quota=1) as reopened:
            self.assertEqual(reopened.request("POST", "/api/quote", OPERATION, session, capability)[0], 200)
            self.assertEqual(reopened.request("POST", "/api/grants", OPERATION, reopened.issue_session())[0], 429)
            bob = reopened.issue_session("bob")
            body = {"object": "quote-b", "quantity": 1}
            _, result = reopened.request("POST", "/api/grants", body, bob)
            self.assertTrue(reopened.revoke_session(bob))
            self.assertEqual(reopened.request("POST", "/api/quote", body, bob, result["capability"])[0], 403)


class RepresentationServer:
    def __init__(self, files, mutate):
        self.files, self.mutate, self.requests = files, mutate, []

    def __enter__(self):
        controller = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                encoding = self.headers.get("Accept-Encoding", "identity")
                controller.requests.append((self.path, encoding))
                status = 200 if self.path in controller.files else 404
                body = controller.files.get(self.path, b"missing")
                headers = []
                status, body, headers = controller.mutate(self.path, encoding, status, body, headers)
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                for key, value in headers:
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


class DeliveryRepresentationChallenge(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        _, self.reference = write_artifacts(Path(self.directory.name) / "releases")
        self.files = {"/" + path.name: path.read_bytes() for path in self.reference.iterdir()}
        self.files["/"] = self.files["/index.html"]

    def tearDown(self):
        self.directory.cleanup()

    def audit(self, mutate, **options):
        from openshield.delivery import delivery_audit
        with RepresentationServer(self.files, mutate) as server:
            report = delivery_audit(self.reference, server.url, authorized=True,
                                    retired_paths=("/retired/app.js.map",), **options)
            return report, list(server.requests)

    def test_exact_identity_and_gzip_are_usable_positive_controls(self):
        def mutate(_path, encoding, status, body, headers):
            if status == 200 and encoding == "gzip":
                return status, gzip.compress(body), [("Content-Encoding", "gzip")]
            return status, body, headers
        report, requests = self.audit(mutate)
        self.assertEqual(report["status"], "pass", report)
        self.assertTrue(report["complete"])
        for path in self.files:
            self.assertIn((path, "identity"), requests)
            self.assertIn((path, "gzip"), requests)

    def test_stale_gzip_can_never_pass_correct_identity(self):
        def mutate(path, encoding, status, body, headers):
            if path == "/app.js" and encoding == "gzip":
                return 200, gzip.compress(b"SYNTHETIC_STALE_PRIVATE_SOURCE"), [("Content-Encoding", "gzip")]
            return status, body, headers
        report, _ = self.audit(mutate)
        self.assertNotEqual(report["status"], "pass", report)

    def test_root_alias_cannot_distribute_unreviewed_bytes(self):
        def mutate(path, _encoding, status, body, headers):
            return (200, b"SYNTHETIC_UNREVIEWED_ROOT_EXPORT", headers) if path == "/" else (status, body, headers)
        report, _ = self.audit(mutate)
        self.assertEqual(report["status"], "blocked", report)

    def test_gzip_extra_member_trailing_garbage_and_truncation_never_pass(self):
        for variant in ("extra_member", "tail", "truncated"):
            def mutate(path, encoding, status, body, headers):
                if path == "/app.js" and encoding == "gzip":
                    encoded = gzip.compress(body)
                    encoded = encoded + gzip.compress(b"unapproved") if variant == "extra_member" else encoded + b"tail" if variant == "tail" else encoded[:-4]
                    return 200, encoded, [("Content-Encoding", "gzip")]
                return status, body, headers
            with self.subTest(variant=variant):
                report, _ = self.audit(mutate)
                self.assertNotEqual(report["status"], "pass", report)

    def test_duplicate_mixed_case_source_map_headers_cannot_hide_exposure(self):
        def mutate(path, _encoding, status, body, headers):
            if path == "/app.js":
                headers = [("sOuRcEmAp", ""), ("SourceMap", "/synthetic-private-map")]
            return status, body, headers
        report, _ = self.audit(mutate)
        self.assertEqual(report["status"], "blocked", report)

    def test_retired_spa_fallback_is_not_an_absent_export(self):
        def mutate(path, _encoding, status, body, headers):
            if path == "/retired/app.js.map":
                return 200, b"<html>application fallback</html>", headers
            return status, body, headers
        report, _ = self.audit(mutate)
        self.assertEqual(report["status"], "blocked", report)

    def test_retired_path_must_be_absent_in_compressed_representation_too(self):
        def mutate(path, encoding, status, body, headers):
            if path == "/retired/app.js.map" and encoding == "gzip":
                return 200, gzip.compress(b"SYNTHETIC_RETIRED_PRIVATE_SOURCE"), [("Content-Encoding", "gzip")]
            return status, body, headers
        report, requests = self.audit(mutate)
        self.assertEqual(report["status"], "blocked", report)
        self.assertIn(("/retired/app.js.map", "gzip"), requests)

    def test_redirect_is_not_followed_even_to_another_loopback_receiver(self):
        def untouched(_path, _encoding, status, body, headers):
            return status, body, headers
        with RepresentationServer({}, untouched) as receiver:
            def mutate(path, _encoding, status, body, headers):
                if path == "/app.js":
                    return 302, b"", [("Location", receiver.url + "/unwanted")]
                return status, body, headers
            report, _ = self.audit(mutate)
            self.assertNotEqual(report["status"], "pass", report)
            self.assertEqual(receiver.requests, [])

    def test_unknown_content_encoding_remains_unsupported(self):
        def mutate(path, _encoding, status, body, headers):
            if path == "/app.js":
                headers = [("Content-Encoding", "br")]
            return status, body, headers
        report, _ = self.audit(mutate)
        self.assertEqual(report["status"], "partial", report)
        self.assertFalse(report["complete"])

    def test_invalid_authorization_and_scope_create_no_http_requests(self):
        from openshield.delivery import delivery_audit
        def mutate(_path, _encoding, status, body, headers):
            return status, body, headers
        with RepresentationServer(self.files, mutate) as server:
            for authorization in (False, 1, "true", None):
                report = delivery_audit(self.reference, server.url, authorized=authorization)
                self.assertEqual(report["status"], "blocked", report)
                self.assertFalse(report["networkRequestsMade"])
            for retired in (("/../private",), ("/%2e%2e/private",), ("https://example.invalid/map",), ("/app.js",)):
                report = delivery_audit(self.reference, server.url, authorized=True, retired_paths=retired)
                self.assertNotEqual(report["status"], "pass", report)
                self.assertFalse(report["networkRequestsMade"])
            self.assertEqual(server.requests, [])


class GoDownstreamMediationChallenge(unittest.TestCase):
    @unittest.skipUnless(shutil.which("go"), "Go toolchain unavailable")
    def test_actual_package_with_independently_authored_http_falsifiers(self):
        source = r'''package toolguard
import (
  "bytes"
  "encoding/json"
  "net/http"
  "strings"
  "sync"
  "sync/atomic"
  "testing"
  "time"
)
func TestIndependentOperationAndScopeBinding(t *testing.T) {
 l:=newLab(true);defer l.close()
 s,err:=l.session("agent_alpha","tenant_alpha");if err!=nil {t.Fatal(err)}
 for _,op:=range []string{"read_record","mark_reviewed","send_receipt"} {
  original:=sample(op);g,err:=l.issue(s,original,time.Minute,true);if err!=nil {t.Fatal(err)}
  baseline:=l.effects.snapshot()
  for _,mutate:=range []func(*request){
   func(r *request){r.Case="case_other"},func(r *request){r.Tenant="tenant_other"},
   func(r *request){r.Recipient="inbox_other"},func(r *request){r.DataClass="confidential"},
   func(r *request){r.Scope="scope_2"},func(r *request){r.Policy="policy_2"},
   func(r *request){r.Params.Revision=2},func(r *request){r.Object="record_other"},
   func(r *request){if r.Operation=="read_record" {r.Operation="mark_reviewed"} else {r.Operation="read_record"}},
  } {
   changed:=original;mutate(&changed)
   status,err:=l.post(s,g,encode(changed));if err!=nil || status==200 || l.effects.snapshot()!=baseline {t.Fatalf("accepted substitution %s",op)}
  }
  status,err:=l.post(s,g,encode(original));if err!=nil || status!=200 {t.Fatalf("valid operation denied %s",op)}
  after:=l.effects.snapshot();if after==baseline {t.Fatalf("missing independently observed effect %s",op)}
  status,err=l.post(s,g,encode(original));if err!=nil || status==200 || l.effects.snapshot()!=after {t.Fatalf("replay effect %s",op)}
 }
 counts:=l.effects.snapshot();if counts!=(Counters{1,1,1}) {t.Fatalf("wrong effects %#v",counts)}
 if l.effects.received("inbox_alpha")!=1 || l.effects.received("inbox_other")!=0 {t.Fatal("wrong recipient received fixed message")}
 read:=sample("read_record");fresh,err:=l.issue(s,read,time.Minute,false);if err!=nil {t.Fatal(err)}
 status,reply,err:=l.call(s,fresh,encode(read));if err!=nil || status!=200 || reply.Value!="reviewed" {t.Fatal("mark did not change independently readable record")}
}
func TestIndependentConcurrentReceiptAndDirectBypass(t *testing.T) {
 l:=newLab(true);defer l.close()
 s,_:=l.session("agent_alpha","tenant_alpha");r:=sample("send_receipt");g,err:=l.issue(s,r,time.Minute,true);if err!=nil {t.Fatal(err)}
 var wg sync.WaitGroup;var successes atomic.Int32
 for range 12 {wg.Add(1);go func(){defer wg.Done();status,err:=l.post(s,g,encode(r));if err==nil && status==200 {successes.Add(1)}}()};wg.Wait()
 if successes.Load()!=1 || l.effects.snapshot().Deliveries!=1 {t.Fatal("concurrent receiver effect bypass")}
 r=sample("mark_reviewed");status,err:=l.post(s,"",encode(r));if err!=nil || status==200 || l.effects.snapshot().Marks!=0 {t.Fatal("direct executor bypass")}
 negative:=newLab(false);defer negative.close();status,err=negative.post("","",encode(r))
 if err!=nil || status!=200 || negative.effects.snapshot().Marks!=1 {t.Fatal("missing real negative-control effect")}
}
func TestIndependentParserAndHeaderAmbiguities(t *testing.T) {
 l:=newLab(true);defer l.close();s,_:=l.session("agent_alpha","tenant_alpha");r:=sample("send_receipt");g,_:=l.issue(s,r,time.Minute,true)
 raw:=string(encode(r))
 for _,body:=range []string{
  strings.Replace(raw,`"recipientId":"inbox_alpha"`,`"recipientId":"inbox_alpha","recipient\u0049d":"inbox_other"`,1),
  strings.Replace(raw,`"dataClass":"synthetic"`,`"dataClass":"synthetic","DataClass":"confidential"`,1),
  strings.Replace(raw,`"evidenceVersion":1`,`"evidenceVersion":1e0`,1),
  strings.Replace(raw,`"revision":1`,`"revision":true`,1),
  strings.Replace(raw,`"params":{`,`"approved":true,"params":{`,1),
  raw+`true`,
 } {
  if !json.Valid([]byte(body)) && !strings.HasSuffix(body,"true") {t.Fatal("bad independent fixture")}
  status,err:=l.post(s,g,[]byte(body));if err!=nil || status!=400 || l.effects.snapshot()!=(Counters{}) {t.Fatal("ambiguous body accepted")}
 }
 request,err:=http.NewRequest("POST",l.server.URL+"/tool",bytes.NewReader(encode(r)));if err!=nil {t.Fatal(err)}
 request.Header.Set("Content-Type","application/json");request.Header.Add("X-Lab-Session",s);request.Header.Add("X-Lab-Session",s);request.Header.Set("X-Lab-Grant",g)
 response,err:=l.client.Do(request);if err!=nil {t.Fatal(err)};response.Body.Close()
 if response.StatusCode==200 || l.effects.snapshot()!=(Counters{}) {t.Fatal("ambiguous authorization headers accepted")}
 status,err:=l.post(s,g,encode(r));if err!=nil || status!=200 || l.effects.snapshot().Deliveries!=1 {t.Fatal("malformed attempts consumed valid authority")}
}
'''
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory)
            (package / "go.mod").write_text("module independent-toolguard-challenge\n\ngo 1.24\n", encoding="utf-8")
            for path in (ROOT / "runtime-go/toolguard").glob("*.go"):
                if not path.name.endswith("_test.go"):
                    shutil.copyfile(path, package / path.name)
            (package / "independent_test.go").write_text(source, encoding="utf-8")
            result = subprocess.run(["go", "test", "-count=1", "-v", "."], cwd=package, capture_output=True,
                                    text=True, timeout=45, shell=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("TestIndependentOperationAndScopeBinding", result.stdout)
            self.assertIn("TestIndependentConcurrentReceiptAndDirectBypass", result.stdout)
            self.assertIn("TestIndependentParserAndHeaderAmbiguities", result.stdout)


if __name__ == "__main__":
    unittest.main()
