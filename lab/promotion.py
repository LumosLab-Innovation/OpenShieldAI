"""Owned origin, preview and caching-edge HTTP experiment; no production deployment."""

from contextlib import ExitStack
import gzip
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
from urllib.parse import urlsplit

from lab.anti_rea import PRIVATE_MARKER, _exports, write_artifacts
from openshield.delivery import delivery_audit
from openshield.promotion import MAX_BYTES, PUBLIC_PATHS, RETIRED_PATHS, PromotionError, PromotionGate


def request(url, path, encoding="identity", method="GET"):
    parsed = urlsplit(url)
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1"
            or parsed.netloc != f"127.0.0.1:{parsed.port}" or parsed.path or parsed.query or parsed.fragment):
        raise ValueError("Owned loopback server required")
    connection = http.client.HTTPConnection("127.0.0.1", parsed.port, timeout=2)
    try:
        connection.request(method, path, headers={"Accept-Encoding": encoding, "Connection": "close"})
        response = connection.getresponse()
        body = response.read(MAX_BYTES + 1)
        if len(body) > MAX_BYTES:
            raise ValueError("Owned response exceeds bound")
        compressed = response.getheader("Content-Encoding") == "gzip"
        return response.status, body, compressed
    finally:
        connection.close()


class _Server:
    def __init__(self, read):
        self.read = read

    def __enter__(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                self.connection.settimeout(2)
                encoding = self.headers.get("Accept-Encoding", "identity")
                if self.path not in PUBLIC_PATHS + RETIRED_PATHS or encoding not in {"identity", "gzip"}:
                    status, body, compressed = 404, b"", False
                else:
                    status, body, compressed = server.read(self.path, encoding)
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Type", "application/javascript" if self.path.endswith(".js") else "text/html")
                self.send_header("Vary", "Accept-Encoding")
                self.send_header("Cache-Control", "public, max-age=3600" if status == 200 else "no-store")
                if compressed:
                    self.send_header("Content-Encoding", "gzip")
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (ConnectionError, OSError):
                    pass

            def do_POST(self):
                self.send_response(405)
                self.send_header("Content-Length", "0")
                self.end_headers()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=.05), daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


class PromotionLab:
    """Separate real HTTP ports, shared process/controller; synthetic fixed path scope."""

    def __init__(self, clock=None):
        self.gate = PromotionGate(_exports(False), **({"clock": clock} if clock else {}))

    def __enter__(self):
        self._servers = ExitStack()
        try:
            self.origin_url = self._servers.enter_context(_Server(self.gate.origin)).url
            self.edge_url = self._servers.enter_context(_Server(self._edge)).url
        except BaseException:
            self._servers.close()
            raise
        return self

    def __exit__(self, *_args):
        self._servers.close()

    def _edge(self, path, encoding):
        epoch, response = self.gate.cached(path, encoding)
        if response is not None:
            return response
        try:
            response = request(self.origin_url, path, encoding)
        except (OSError, http.client.HTTPException, ValueError):
            return 503, b"", False
        return self.gate.cache_response(epoch, path, encoding, response)

    @staticmethod
    def preview(directory):
        def read(path, encoding):
            name = "index.html" if path == "/" else path[1:]
            try:
                with (Path(directory) / name).open("rb") as source:
                    body = source.read(MAX_BYTES + 1)
                if len(body) > MAX_BYTES:
                    return 503, b"", False
            except OSError:
                return 404, b"", False
            return 200, gzip.compress(body, mtime=0) if encoding == "gzip" else body, encoding == "gzip"
        return _Server(read)


def _observed(url):
    counts = {"requests": 0, "privateCanaryDeliveries": 0, "requiredGetSuccesses": 0, "retiredDenied": 0}
    for path in PUBLIC_PATHS + RETIRED_PATHS:
        for encoding in ("identity", "gzip"):
            status, wire, compressed = request(url, path, encoding)
            body = gzip.decompress(wire) if compressed else wire
            counts["requests"] += 1
            counts["privateCanaryDeliveries"] += int(PRIVATE_MARKER.encode() in body)
            counts["requiredGetSuccesses"] += int(path in PUBLIC_PATHS and status == 200 and body == _exports(True)[path])
            counts["retiredDenied"] += int(path in RETIRED_PATHS and status in {404, 410})
    return counts


def verify():
    checks, phases = [], {}

    def check(code, condition):
        checks.append({"code": code, "passed": bool(condition)})

    def denied(action):
        try:
            action()
        except PromotionError:
            return True
        return False

    with tempfile.TemporaryDirectory(prefix="openshield-promotion-") as directory:
        before, candidate = write_artifacts(Path(directory) / "releases")
        with PromotionLab() as lab, lab.preview(candidate) as preview, lab.preview(before) as bad_preview:
            gate = lab.gate
            phases["before"] = _observed(lab.edge_url)
            saved_status, downloaded, compressed = request(lab.edge_url, "/app.js.map", "gzip")
            offline_copy = gzip.decompress(downloaded) if compressed else downloaded
            check("NEGATIVE_CONTROL_DELIVERS_FOUR_PRIVATE_REPRESENTATIONS", phases["before"]["privateCanaryDeliveries"] == 4)
            initial = gate.state
            check("FAILED_VALIDATION_CANNOT_PROMOTE", denied(lambda: gate.stage(before, bad_preview.url, authorized=True)))
            check("FAILED_VALIDATION_PRESERVES_ACTIVE_STATE", gate.state == initial)
            check("EXPLICIT_LOCAL_AUTHORIZATION_REQUIRED", denied(lambda: gate.stage(candidate, preview.url)))
            check("PUBLIC_HTTP_CANNOT_APPROVE_OR_PROMOTE", request(lab.edge_url, "/approve", method="POST")[0] == 405)
            check("FORGED_GRANT_CANNOT_PROMOTE", denied(lambda: gate.promote("forged")))
            staged = gate.stage(candidate, preview.url, authorized=True)
            approval = gate.approve_promotion(staged["candidateId"], staged["expectedGeneration"])
            original = (candidate / "app.js").read_bytes()
            (candidate / "app.js").write_bytes(original + b"\n// SYNTHETIC_UNREVIEWED_CHANGE\n")
            check("CHANGED_APPROVED_TREE_REJECTED", denied(lambda: gate.promote(approval)))
            check("CHANGED_TREE_PRESERVES_ACTIVE_STATE", gate.state == initial)
            check("DENIED_GRANT_CANNOT_BE_REUSED", denied(lambda: gate.promote(approval)))
            (candidate / "app.js").write_bytes(original)
            staged = gate.stage(candidate, preview.url, authorized=True)
            approval = gate.approve_promotion(staged["candidateId"], staged["expectedGeneration"])
            result = gate.promote(approval)
            check("EXACT_APPROVED_SNAPSHOT_PROMOTED", result["artifactSha256"] == staged["artifactSha256"] and result["generation"] == 1)
            check("PROMOTION_APPROVAL_ONE_USE", denied(lambda: gate.promote(approval)))
            phases["origin_after_promotion"] = _observed(lab.origin_url)
            phases["edge_without_explicit_purge"] = _observed(lab.edge_url)
            check("NEW_ORIGIN_HAS_NO_PRIVATE_CANARY", phases["origin_after_promotion"]["privateCanaryDeliveries"] == 0)
            check("ORIGIN_PROMOTION_ALONE_LEAVES_FOUR_CACHED_LEAKS", phases["edge_without_explicit_purge"]["privateCanaryDeliveries"] == 4)
            check("CLEAN_ORIGIN_PRESERVES_SIX_REQUIRED_GETS", phases["origin_after_promotion"]["requiredGetSuccesses"] == 6)
            check("STALE_EDGE_FAILS_REAL_DELIVERY_GATE", delivery_audit(candidate, lab.edge_url, authorized=True, retired_paths=RETIRED_PATHS)["status"] == "blocked")
            check("FORGED_RETIREMENT_CANNOT_PURGE", denied(lambda: gate.retire("forged")))
            retirement = gate.approve_retirement(gate.state["generation"])
            receipt = gate.retire(retirement)
            check("PURGE_REMOVES_EIGHT_CACHED_REPRESENTATIONS", receipt["purgedRepresentations"] == 8)
            check("RETIREMENT_APPROVAL_ONE_USE", denied(lambda: gate.retire(retirement)))
            phases["edge_after_retirement"] = _observed(lab.edge_url)
            phases["origin_after_retirement"] = _observed(lab.origin_url)
            for source in ("edge_after_retirement", "origin_after_retirement"):
                check(source.upper() + "_NO_PRIVATE_CANARY", phases[source]["privateCanaryDeliveries"] == 0)
                check(source.upper() + "_SIX_REQUIRED_GETS", phases[source]["requiredGetSuccesses"] == 6)
                check(source.upper() + "_BOTH_MAP_ENCODINGS_DENIED", phases[source]["retiredDenied"] == 2)
            check("POST_RETIREMENT_REAL_DELIVERY_GATE_PASSES", delivery_audit(candidate, lab.edge_url, authorized=True, retired_paths=RETIRED_PATHS)["status"] == "pass")
            check("HISTORICAL_DOWNLOAD_STILL_CONTAINS_PRIVATE_BYTES", saved_status == 200 and PRIVATE_MARKER.encode() in offline_copy)
            check("OLD_GENERATION_CANNOT_AUTHORIZE_ROLLBACK", denied(lambda: gate.approve_promotion(staged["candidateId"], 0)))
    outcomes = {item["code"]: item["passed"] for item in checks}
    return {"schemaVersion": "promotion_lab_v1", "status": "passed" if all(item["passed"] for item in checks) else "failed",
            "dataClass": "synthetic", "checks": checks, "phases": phases, "modelCalls": 0, "productionActions": False,
            "derivedFacts": {"legacyExposureObserved": phases["before"]["privateCanaryDeliveries"] > 0,
                             "candidateDigestBound": outcomes["EXACT_APPROVED_SNAPSHOT_PROMOTED"] and outcomes["CHANGED_APPROVED_TREE_REJECTED"],
                             "originChangedButCacheStillExposed": outcomes["NEW_ORIGIN_HAS_NO_PRIVATE_CANARY"] and outcomes["ORIGIN_PROMOTION_ALONE_LEAVES_FOUR_CACHED_LEAKS"],
                             "explicitPurgeVerified": outcomes["POST_RETIREMENT_REAL_DELIVERY_GATE_PASSES"] and outcomes["EDGE_AFTER_RETIREMENT_SIX_REQUIRED_GETS"],
                             "historicalDownloadRetainsPrivateBytes": outcomes["HISTORICAL_DOWNLOAD_STILL_CONTAINS_PRIVATE_BYTES"]},
            "limitations": ["Owned loopback static fixtures with three server roles in one process; not a production adapter",
                            "Fixed root/index/app/map paths and identity/gzip only; no CDN, query alias, hidden route or browser coverage",
                            "Controller identity and approvals are trusted local test actions; no cryptographic provenance or durable deployment ledger",
                            "Explicit purge limits future delivery through this controlled edge; historical downloaded copies remain disclosed",
                            "Already started responses may finish; the purge epoch prevents old responses from refilling the cache",
                            "Required GET bytes are verified; JavaScript UI behavior is not executed",
                            "AI benefit is not measured by this deterministic effect experiment"]}


if __name__ == "__main__":
    report = verify()
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["status"] == "passed" else 1)
