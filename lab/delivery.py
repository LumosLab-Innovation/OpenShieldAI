"""Owned HTTP representations that falsify file-only anti-REA release claims."""

import gzip
import json
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from lab.anti_rea import LEAKY_CLIENT, _exports, write_artifacts
from openshield.delivery import delivery_audit


MODES = {"clean", "gzip", "map_header", "stale_gzip", "retired_map", "retired_gzip", "retired_fallback",
         "redirect", "gzip_bomb", "truncated_gzip", "multi_gzip", "brotli", "root_mismatch"}


class DeliveryLab:
    def __init__(self, mode="clean"):
        if mode not in MODES:
            raise ValueError("Unknown synthetic mode")
        self.mode = mode
        self.redirect_target_hits = 0

    def __enter__(self):
        lab = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                self.connection.settimeout(2)
                exports = _exports(True)
                coding = self.headers.get("Accept-Encoding")
                body = exports.get(self.path, b'{"error":"not_found"}')
                status, encoding, extra = (200 if self.path in exports else 404), None, {}
                if self.path == "/redirect-target":
                    lab.redirect_target_hits += 1
                if self.path == "/retired/app.js.map":
                    if lab.mode in {"retired_map", "retired_fallback"} or lab.mode == "retired_gzip" and coding == "gzip":
                        status = 200
                        body = _exports(False)["/app.js.map"] if lab.mode != "retired_fallback" else exports["/"]
                if self.path == "/" and lab.mode == "root_mismatch":
                    body = b"<h1>SYNTHETIC_UNREVIEWED_ENTRY</h1>"
                if self.path == "/app.js":
                    if lab.mode == "map_header":
                        extra["SourceMap"] = "/retired/app.js.map"
                    if lab.mode == "redirect":
                        status, body, extra = 302, b"", {"Location": "/redirect-target"}
                    if lab.mode == "brotli":
                        encoding = "br"
                    if coding == "gzip":
                        if lab.mode == "stale_gzip":
                            body, encoding = gzip.compress(LEAKY_CLIENT.encode()), "gzip"
                        elif lab.mode == "gzip_bomb":
                            body, encoding = gzip.compress(b"x" * (2 * 1024 * 1024 + 1)), "gzip"
                        elif lab.mode == "truncated_gzip":
                            body, encoding = gzip.compress(body)[:-4], "gzip"
                        elif lab.mode == "multi_gzip":
                            body, encoding = gzip.compress(body) + gzip.compress(b"SYNTHETIC_PRIVATE_RULE_V1"), "gzip"
                if lab.mode == "gzip" and coding == "gzip":
                    body, encoding = gzip.compress(body), "gzip"
                self.send_response(status)
                self.send_header("Content-Type", "application/javascript" if self.path.endswith(".js") else "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                if encoding:
                    self.send_header("Content-Encoding", encoding)
                for name, value in extra.items():
                    self.send_header(name, value)
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (ConnectionError, OSError):
                    pass

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


def verify():
    cases = []
    expected = {"clean": "pass", "gzip": "pass", "map_header": "blocked", "stale_gzip": "blocked",
                "retired_map": "blocked", "retired_gzip": "blocked", "retired_fallback": "blocked",
                "root_mismatch": "blocked", "redirect": "partial", "gzip_bomb": "partial",
                "truncated_gzip": "partial", "multi_gzip": "partial", "brotli": "partial"}
    with tempfile.TemporaryDirectory() as directory:
        _, reference = write_artifacts(Path(directory) / "releases")
        for mode, status in expected.items():
            with DeliveryLab(mode) as lab:
                result = delivery_audit(reference, lab.url, authorized=True, retired_paths=("/retired/app.js.map",))
                cases.append({"case": mode, "expectedStatus": status, "passed": result["status"] == status
                              and lab.redirect_target_hits == 0, "result": result})
    return {"schemaVersion": "delivery_lab_v1", "synthetic": True,
            "status": "pass" if all(case["passed"] for case in cases) else "failed", "cases": cases,
            "aiBenefit": {"status": "not_measured"},
            "limits": ["Real loopback HTTP with owned static fixtures only",
                       "Audit is a promotion gate when wired into the operator release process; it does not intercept served bytes",
                       "Declared paths cannot prove absence of undisclosed URLs, caches or historic downloads",
                       "A reachable retired route is a policy violation, not proof its body contains private code"]}


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2))
