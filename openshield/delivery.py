"""Compare a reviewed local web export with explicitly authorized loopback delivery."""

import hashlib
import http.client
import os
import re
import socket
import stat
import threading
import time
import zlib
from pathlib import Path
from urllib.parse import quote, urlsplit

from .exposure import _identity, _linked, exposure_audit


DEFAULT_LIMITS = {"files": 256, "entries": 512, "depth": 16, "fileBytes": 2 * 1024 * 1024,
                  "totalBytes": 16 * 1024 * 1024, "seconds": 10, "observations": 256}


class _Gap(Exception):
    def __init__(self, code):
        self.code = code


def _inventory(root, limits, tick):
    """Bounded stable reads; its manifest must equal the independent local-policy audit."""
    manifest, entries, total = {}, 0, 0

    def walk(directory, depth):
        nonlocal entries, total
        tick()
        if depth > limits["depth"]:
            raise _Gap("REFERENCE_LIMIT")
        with os.scandir(directory) as children:
            for child in children:
                tick()
                entries += 1
                if entries > limits["entries"]:
                    raise _Gap("REFERENCE_LIMIT")
                path = Path(child.path)
                before = path.lstat()
                if _linked(before):
                    raise _Gap("REFERENCE_CHANGED_OR_UNSAFE")
                if stat.S_ISDIR(before.st_mode):
                    walk(path, depth + 1)
                    continue
                if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                    raise _Gap("REFERENCE_CHANGED_OR_UNSAFE")
                if len(manifest) >= limits["files"] or before.st_size > limits["fileBytes"]:
                    raise _Gap("REFERENCE_LIMIT")
                descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
                try:
                    if _identity(os.fstat(descriptor)) != _identity(before):
                        raise _Gap("REFERENCE_CHANGED_OR_UNSAFE")
                    digest, size = hashlib.sha256(), 0
                    while True:
                        tick()
                        block = os.read(descriptor, min(65536, limits["fileBytes"] + 1 - size))
                        if not block:
                            break
                        size += len(block)
                        total += len(block)
                        if size > limits["fileBytes"] or total > limits["totalBytes"]:
                            raise _Gap("REFERENCE_LIMIT")
                        digest.update(block)
                    if size != before.st_size or _identity(os.fstat(descriptor)) != _identity(before):
                        raise _Gap("REFERENCE_CHANGED_OR_UNSAFE")
                finally:
                    os.close(descriptor)
                manifest[path.relative_to(root).as_posix()] = digest.hexdigest()
    walk(root, 0)
    commitment = hashlib.sha256()
    for name, digest in sorted(manifest.items()):
        commitment.update(name.encode("utf-8") + b"\0" + digest.encode("ascii") + b"\0")
    return manifest, commitment.hexdigest()


def _get(port, path, encoding, limits, tick, remaining, counters):
    tick()
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=min(2, remaining()))
    timer = None
    try:
        connection.connect()
        raw_socket = connection.sock

        def interrupt():
            try:
                raw_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            raw_socket.close()

        timer = threading.Timer(min(2, remaining()), interrupt)
        timer.start()
        counters["requested"] += 1
        connection.request("GET", path, headers={"Accept-Encoding": encoding, "Connection": "close"})
        response = connection.getresponse()
        headers = response.getheaders()
        if sum(len(name) + len(value) for name, value in headers) > 16384:
            raise _Gap("RESPONSE_HEADERS_LIMIT")
        lengths = response.msg.get_all("Content-Length", [])
        transfers = response.msg.get_all("Transfer-Encoding", [])
        if (len(lengths) > 1 or len(transfers) > 1 or lengths and transfers
                or lengths and (not lengths[0].isdigit() or int(lengths[0]) > limits["fileBytes"])
                or transfers and transfers[0].lower() != "chunked"):
            raise _Gap("RESPONSE_FRAMING_UNSUPPORTED")
        codings = response.msg.get_all("Content-Encoding", [])
        if len(codings) > 1:
            raise _Gap("CONTENT_ENCODING_UNSUPPORTED")
        coding = codings[0].strip().lower() if codings else "identity"
        if coding not in {"gzip", "identity"}:
            raise _Gap("CONTENT_ENCODING_UNSUPPORTED")
        body = bytearray()
        while True:
            tick()
            block = response.read1(min(65536, limits["fileBytes"] + 1 - len(body)))
            if not block:
                break
            body.extend(block)
            counters["wireBytes"] += len(block)
            if len(body) > limits["fileBytes"] or counters["wireBytes"] > limits["totalBytes"]:
                raise _Gap("RESPONSE_BYTES_LIMIT")
        if lengths and len(body) != int(lengths[0]):
            raise _Gap("RESPONSE_TRUNCATED")
        if coding == "gzip":
            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
            body = decoder.decompress(body, limits["fileBytes"] + 1)
            if len(body) > limits["fileBytes"] or decoder.unconsumed_tail:
                raise _Gap("DECODED_BYTES_LIMIT")
            if not decoder.eof or decoder.unused_data:
                raise _Gap("GZIP_INCOMPLETE_OR_EXTRA_MEMBER")
        counters["decodedBytes"] += len(body)
        if counters["decodedBytes"] > limits["totalBytes"]:
            raise _Gap("DECODED_BYTES_LIMIT")
        tick()
        return response.status, headers, bytes(body)
    except (OSError, http.client.HTTPException, zlib.error, ValueError):
        raise _Gap("HTTP_UNAVAILABLE_OR_INVALID") from None
    finally:
        if timer is not None:
            timer.cancel()
        connection.close()


def delivery_audit(directory, base_url, authorized=False, retired_paths=(), limits=None):
    selected = dict(DEFAULT_LIMITS)
    result = {"schemaVersion": "delivery_exposure_v1", "status": "partial", "complete": False,
              "referenceSha256": None, "counts": {"referenceFiles": 0, "requested": 0, "wireBytes": 0,
              "decodedBytes": 0, "retiredProbes": 0, "observations": 0, "gaps": 0,
              "observationDetailsOmitted": 0, "gapDetailsOmitted": 0}, "observations": [], "gaps": [], "limits": selected,
              "targetCodeExecuted": False, "networkRequestsMade": False, "isFinding": False,
              "coverage": "DECLARED_REFERENCE_PATHS_AND_RETIRED_PATHS_ONLY",
              "limitations": ["REFERENCE_REQUIRES_OWNER_REVIEW_NOT_AUTHENTICATED_BY_HASH",
                              "NO_UNKNOWN_ROUTE_CDN_CACHE_OR_HISTORY_DISCOVERY", "NO_GENERAL_SECRET_DETECTION",
                              "LOOPBACK_STATIC_PREVIEW_ONLY", "GET_MAY_HAVE_EFFECTS_ON_A_MISCONFIGURED_SERVER",
                              "AUDIT_DOES_NOT_REMOVE_ALREADY_DISCLOSED_BYTES"]}

    def gap(code, asset=None):
        result["counts"]["gaps"] += 1
        if len(result["gaps"]) < selected["observations"]:
            result["gaps"].append({"code": code, **({"assetId": asset} if asset else {})})
        else:
            result["counts"]["gapDetailsOmitted"] += 1

    def observed(code, asset):
        result["counts"]["observations"] += 1
        if len(result["observations"]) < selected["observations"]:
            result["observations"].append({"code": code, "assetId": asset})
        else:
            result["counts"]["observationDetailsOmitted"] += 1

    if authorized is not True:
        result["status"] = "blocked"
        gap("AUTHORIZATION_REQUIRED")
        return result
    if limits is not None:
        if not isinstance(limits, dict) or any(key not in selected or type(value) not in (int, float)
                or not 0 < value <= selected[key] or key != "seconds" and type(value) is not int for key, value in limits.items()):
            result["status"] = "blocked"
            gap("LIMITS_INVALID")
            return result
        selected.update(limits)
    started = time.monotonic()

    def remaining():
        return max(.001, selected["seconds"] - (time.monotonic() - started))

    def tick():
        if time.monotonic() - started >= selected["seconds"]:
            raise _Gap("JOB_DEADLINE")

    try:
        if not isinstance(base_url, str):
            raise _Gap("EXPLICIT_LOOPBACK_STATIC_PREVIEW_REQUIRED")
        url = urlsplit(base_url)
        if (url.scheme != "http" or url.hostname != "127.0.0.1"
                or url.netloc != f"127.0.0.1:{url.port}" or not url.port or url.path not in {"", "/"}
                or url.query or url.fragment or url.username or url.password
                or base_url not in {f"http://127.0.0.1:{url.port}", f"http://127.0.0.1:{url.port}/"}):
            raise _Gap("EXPLICIT_LOOPBACK_STATIC_PREVIEW_REQUIRED")
        if (not isinstance(retired_paths, (tuple, list)) or len(retired_paths) > 16
                or any(not isinstance(path, str) or not re.fullmatch(r"/[A-Za-z0-9_./-]{1,200}", path)
                       or any(part in {"", ".", ".."} for part in path[1:].split("/")) for path in retired_paths)
                or len(set(retired_paths)) != len(retired_paths)):
            raise _Gap("INVALID_RETIRED_PATHS")
        local = exposure_audit(directory, authorized=True, limits={**selected, "seconds": remaining()})
        if local["status"] != "pass" or not local["complete"]:
            if local["status"] == "blocked":
                observed("REFERENCE_POLICY_REJECTED", "reference")
            raise _Gap("REFERENCE_NOT_ACCEPTED")
        root = Path(os.path.abspath(os.fspath(directory)))
        manifest, reference = _inventory(root, selected, tick)
        if reference != local["artifactSha256"]:
            raise _Gap("REFERENCE_CHANGED_OR_UNSAFE")
        result["referenceSha256"] = reference
        result["counts"]["referenceFiles"] = len(manifest)
        targets = {"/" + quote(name, safe="/"): digest for name, digest in manifest.items()}
        if "index.html" in manifest:
            targets["/"] = manifest["index.html"]
        if set(retired_paths) & set(targets):
            raise _Gap("RETIRED_PATH_IS_REFERENCE_ASSET")
        for path, digest in sorted(targets.items()):
            asset = "asset_" + hashlib.sha256(path.encode()).hexdigest()[:24]
            for encoding in ("identity", "gzip"):
                try:
                    status, headers, body = _get(url.port, path, encoding, selected, tick, remaining, result["counts"])
                    result["networkRequestsMade"] = True
                    if any(name.lower() in {"sourcemap", "x-sourcemap"} for name, _ in headers):
                        observed("SOURCE_MAP_RESPONSE_HEADER", asset)
                    if 300 <= status < 400:
                        raise _Gap("REDIRECT_DENIED")
                    if status != 200:
                        raise _Gap("REFERENCE_ASSET_UNAVAILABLE")
                    if hashlib.sha256(body).hexdigest() != digest:
                        observed("DELIVERED_BYTES_DIFFER_FROM_REFERENCE", asset)
                except _Gap as error:
                    gap(error.code, asset)
        for path in retired_paths:
            asset = "retired_" + hashlib.sha256(path.encode()).hexdigest()[:24]
            for encoding in ("identity", "gzip"):
                result["counts"]["retiredProbes"] += 1
                try:
                    status, headers, _ = _get(url.port, path, encoding, selected, tick, remaining, result["counts"])
                    result["networkRequestsMade"] = True
                    if any(name.lower() in {"sourcemap", "x-sourcemap"} for name, _ in headers):
                        observed("SOURCE_MAP_RESPONSE_HEADER", asset)
                    if status not in {404, 410}:
                        observed("RETIRED_PATH_POLICY_VIOLATION", asset)
                except _Gap as error:
                    gap(error.code, asset)
        tick()
        final = exposure_audit(directory, authorized=True, limits={**selected, "seconds": remaining()})
        if final["status"] != "pass" or final["artifactSha256"] != reference:
            raise _Gap("REFERENCE_CHANGED_OR_UNSAFE")
        result["complete"] = result["counts"]["gaps"] == 0
    except _Gap as error:
        gap(error.code)
    except (OSError, ValueError, TypeError, UnicodeError):
        gap("INVALID_OR_UNAVAILABLE_INPUT")
    result["networkRequestsMade"] = result["counts"]["requested"] > 0
    result["status"] = "blocked" if result["counts"]["observations"] else "pass" if result["complete"] else "partial"
    return result
