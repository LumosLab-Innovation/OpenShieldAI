"""Owned synthetic HTTP experiment: public information is never operation authority."""

import http.client
import json
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from openshield.authority import Authority, AuthorityError
from openshield.exposure import exposure_audit
from openshield.gateway import strict_json


PRIVATE_MARKER = "SYNTHETIC_PRIVATE_RULE_V1"
PAGE = '<!doctype html><html lang="en"><meta charset="utf-8"><title>Synthetic quote lab</title><h1>Quote lab — synthetic data</h1><label for="session">Ephemeral lab session from the test controller</label><input id="session" type="password" autocomplete="off"><button id="quote">Quote one item</button><output id="result" aria-live="polite"></output><script src="/app.js"></script></html>'
THIN_CLIENT = '''"use strict";
document.querySelector("#quote").onclick = async () => {
  const input = {object: "quote-a", quantity: 1};
  const headers = {"Content-Type": "application/json", "Authorization": "Bearer " + document.querySelector("#session").value};
  const grant = await fetch("/api/grants", {method: "POST", headers, body: JSON.stringify(input)});
  const value = await grant.json();
  if (!grant.ok) { document.querySelector("#result").textContent = "Access denied"; return; }
  const quote = await fetch("/api/quote", {method: "POST", headers: {...headers, "X-Lab-Capability": value.capability}, body: JSON.stringify(input)});
  document.querySelector("#result").textContent = quote.ok ? String((await quote.json()).totalCents) : "Access denied";
};
'''
LEAKY_CLIENT = '''"use strict";
// SYNTHETIC_PRIVATE_RULE_V1: private formula mistakenly shipped to the browser.
function privatePrice(quantity) { return quantity * 137 + 29; }
document.querySelector("#quote").onclick = async () => {
  // A UI gate cannot authorize the server operation.
  if (!document.querySelector("#session").value) { document.querySelector("#result").textContent = "Access denied"; return; }
  const reply = await fetch("/api/quote", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({object: "quote-a", quantity: 1})});
  document.querySelector("#result").textContent = String((await reply.json()).totalCents);
};
//# sourceMappingURL=app.js.map
'''


def write_artifacts(directory):
    """Create new fixture directories, refusing to overwrite an existing release."""
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=False)
    before, after = root / "before", root / "after"
    for path, protected in ((before, False), (after, True)):
        path.mkdir()
        for name, content in _exports(protected).items():
            if name != "/":
                (path / name[1:]).write_bytes(content)
    return before, after


def _exports(protected):
    value = {"/": PAGE.encode(), "/index.html": PAGE.encode(),
             "/app.js": (THIN_CLIENT if protected else LEAKY_CLIENT).encode()}
    if not protected:
        value["/app.js.map"] = json.dumps({"version": 3, "file": "app.js", "sources": ["private/pricing.js"], "sourcesContent": [LEAKY_CLIENT], "names": [], "mappings": ""}).encode()
    return value


def _payload(value):
    if (not isinstance(value, dict) or set(value) != {"object", "quantity"}
            or not isinstance(value["object"], str) or value["object"] not in {"quote-a", "quote-b"}
            or type(value["quantity"]) is not int or not 1 <= value["quantity"] <= 100):
        raise ValueError("Invalid synthetic operation")
    return value["object"], value["quantity"]


def _private_price(quantity):
    return quantity * 137 + 29


class AntiReaLab:
    """Loopback only. Test controller supplies identities; HTTP cannot mint sessions.

    shortcut: SQLite and controller identities are an owned lab; production needs
    accepted identity, protected storage, TLS and recovery policy before adoption.
    """

    def __init__(self, protected=True, clock=time.time, quota=4, grant_ttl=30, state_path=None):
        if type(protected) is not bool or type(quota) is not int or not 1 <= quota <= 100:
            raise ValueError("Invalid lab configuration")
        if type(grant_ttl) not in (int, float) or not 0 < grant_ttl <= 60:
            raise ValueError("Invalid grant lifetime")
        self.protected, self.clock, self.quota, self.grant_ttl = protected, clock, quota, grant_ttl
        self._temp_state = tempfile.TemporaryDirectory(prefix="openshield-authority-") if state_path is None else None
        try:
            self.authority = Authority(Path(self._temp_state.name) / "authority.sqlite3" if self._temp_state else state_path,
                                       clock=clock, quota=quota, grant_ttl=grant_ttl)
        except Exception:
            if self._temp_state:
                self._temp_state.cleanup()
            raise

    def issue_session(self, subject="alice"):
        return self.authority.issue_session(subject)

    def revoke_session(self, token):
        """Test-controller action only; no HTTP route can revoke or mint identities."""
        return self.authority.revoke_session(token)

    @property
    def audit(self):
        return self.authority.audit

    def __enter__(self):
        lab = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def reply(self, status, value, content_type="application/json"):
                body = json.dumps(value, allow_nan=False).encode() if content_type == "application/json" else value
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
                self.end_headers()
                self.wfile.write(body)

            def host_valid(self):
                return self.headers.get("Host") == f"127.0.0.1:{lab.server.server_port}"

            def do_GET(self):
                if not self.host_valid():
                    return self.reply(400, {"error": "invalid_request"})
                # Exact allowlist, not a filesystem server or a catch-all SPA fallback.
                exports = _exports(lab.protected)
                path = urlsplit(self.path).path
                if path not in exports:
                    return self.reply(404, {"error": "not_found"})
                content_type = "text/javascript" if path.endswith(".js") else "application/json" if path.endswith(".map") else "text/html"
                return self.reply(200, exports[path], content_type + "; charset=utf-8")

            def do_POST(self):
                self.connection.settimeout(2)
                if not self.host_valid() or self.headers.get("Transfer-Encoding") is not None:
                    return self.reply(400, {"error": "invalid_request"})
                try:
                    lengths = self.headers.get_all("Content-Length", [])
                    if len(lengths) != 1 or not lengths[0].isdigit() or not 0 < int(lengths[0]) <= 512:
                        raise ValueError()
                    if self.headers.get("Content-Type") != "application/json":
                        raise ValueError()
                    value = strict_json(self.rfile.read(int(lengths[0])).decode("utf-8"))
                    obj, quantity = _payload(value)
                except (ValueError, OSError, UnicodeError):
                    return self.reply(400, {"error": "invalid_request"})
                if self.path not in {"/api/grants", "/api/quote"}:
                    return self.reply(404, {"error": "not_found"})
                if not lab.protected and self.path == "/api/quote":
                    return self.reply(200, {"totalCents": _private_price(quantity)})
                auth = self.headers.get_all("Authorization", [])
                caps = self.headers.get_all("X-Lab-Capability", [])
                if len(auth) != 1 or not auth[0].startswith("Bearer ") or len(caps) > 1:
                    return self.reply(403, {"error": "denied"})
                session = auth[0][7:]
                capability = caps[0] if caps else ""
                try:
                    status, body = lab.authority.operate(self.path, session, capability, obj, quantity)
                except AuthorityError:
                    return self.reply(503, {"error": "authority_unavailable"})
                return self.reply(status, body)

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
        if self._temp_state:
            self._temp_state.cleanup()

    def request(self, method, path, payload=None, session=None, capability=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        headers = {"Content-Type": "application/json"}
        if session:
            headers["Authorization"] = "Bearer " + session
        if capability:
            headers["X-Lab-Capability"] = capability
        try:
            connection.request(method, path, json.dumps(payload, allow_nan=False) if payload is not None else None, headers)
            response = connection.getresponse()
            data = response.read(8192)
            return response.status, json.loads(data) if response.getheader("Content-Type") == "application/json" else data
        finally:
            connection.close()


def verify():
    """Real HTTP trials with safe aggregate evidence; no model or REA process is invoked."""
    checks = {}
    with tempfile.TemporaryDirectory() as directory:
        before, after = write_artifacts(Path(directory) / "releases")
        audits = {"before": exposure_audit(before, authorized=True), "after": exposure_audit(after, authorized=True)}
        checks["release_gate_blocks_before_passes_after"] = audits["before"]["status"] == "blocked" and audits["after"]["status"] == "pass"
        checks["synthetic_private_marker_absent_from_all_after_files"] = all(PRIVATE_MARKER.encode() not in path.read_bytes() and b"137" not in path.read_bytes() for path in after.iterdir())
        tick = [100.0]
        with AntiReaLab(protected=False) as leaky, AntiReaLab(clock=lambda: tick[0], quota=4) as defended:
            alice, bob = defended.issue_session(), defended.issue_session("bob")
            operation = {"object": "quote-a", "quantity": 1}
            checks["baseline_direct_unauthorized_call_succeeds"] = leaky.request("POST", "/api/quote", operation)[0] == 200
            checks["defended_direct_unauthorized_call_denied"] = defended.request("POST", "/api/quote", operation)[0] == 403
            checks["wrong_owner_denied"] = defended.request("POST", "/api/grants", operation, bob)[0] == 403
            _, grant = defended.request("POST", "/api/grants", operation, alice)
            cap = grant["capability"]
            checks["quantity_tamper_denied"] = defended.request("POST", "/api/quote", {**operation, "quantity": 2}, alice, cap)[0] == 403
            checks["session_rebind_denied"] = defended.request("POST", "/api/quote", operation, defended.issue_session(), cap)[0] == 403
            with ThreadPoolExecutor(max_workers=8) as pool:
                statuses = list(pool.map(lambda _: defended.request("POST", "/api/quote", operation, alice, cap)[0], range(8)))
            checks["concurrent_single_use"] = statuses.count(200) == 1 and statuses.count(403) == 7
            totals = [_private_price(1)]
            for quantity in (2, 3):
                body = {**operation, "quantity": quantity}
                _, grant = defended.request("POST", "/api/grants", body, alice)
                status, reply = defended.request("POST", "/api/quote", body, alice, grant["capability"])
                baseline_reply = leaky.request("POST", "/api/quote", body)[1]
                checks[f"legitimate_output_preserved_q{quantity}"] = status == 200 and reply == baseline_reply
                totals.append(reply["totalCents"])
            # A granted query oracle can reveal this simple function despite zero shipped formula.
            slope, intercept = totals[1] - totals[0], 2 * totals[0] - totals[1]
            checks["authorized_outputs_still_reveal_linear_formula"] = slope * 3 + intercept == totals[2]
            _, expired = defended.request("POST", "/api/grants", operation, alice)
            tick[0] += 31
            checks["expired_capability_denied"] = defended.request("POST", "/api/quote", operation, alice, expired["capability"])[0] == 403
            fresh_session = defended.issue_session()
            _, last = defended.request("POST", "/api/grants", operation, fresh_session)
            checks["fourth_authorized_query_allowed"] = defended.request("POST", "/api/quote", operation, fresh_session, last["capability"])[0] == 200
            checks["fresh_session_cannot_reset_principal_quota"] = defended.request("POST", "/api/grants", operation, defended.issue_session())[0] == 429
            checks["public_client_remains_readable"] = b"/api/quote" in defended.request("GET", "/app.js")[1]
            checks["private_paths_and_error_responses_do_not_export_formula"] = all(defended.request("GET", path)[0] == 404 and PRIVATE_MARKER not in str(defended.request("GET", path)[1]) for path in ("/app.js.map", "/private/pricing.js", "/%2e%2e/anti_rea.py", "/.env", "/missing.js"))
            audit = dict(defended.audit)
    return {"schemaVersion": "anti_rea_lab_v1", "synthetic": True, "transport": "real_loopback_http",
            "checks": checks, "status": "pass" if all(checks.values()) else "failed",
            "exposure": audits, "authorityAudit": audit,
            "aiBenefit": {"status": "not_measured"},
            "limits": ["Owned synthetic example only", "No target code or REA invoked by this trial",
                       "Release pass is a bounded policy result, not a secret or anti-reversing verdict",
                       "Formula is public in this repository; trial measures delivered bytes and HTTP authority",
                       "Controller identities and local SQLite are not accepted production authentication or protected storage",
                       "Authorized outputs can reveal algorithms; stolen live sessions/XSS remain risks"]}
