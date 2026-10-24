"""Exact, controller-approved release transitions for the owned loopback experiment.

shortcut: authority and cache state are process-local; a production adapter needs
accepted identity, durable reconciliation and target-side conditional writes.
"""

from dataclasses import dataclass
import gzip
import hashlib
import os
from pathlib import Path
import secrets
import stat
import threading
import time

from .delivery import delivery_audit
from .exposure import _identity, _linked, exposure_audit


PUBLIC_PATHS = ("/", "/app.js", "/index.html")
RETIRED_PATHS = ("/app.js.map",)
MAX_BYTES = 65536


class PromotionError(Exception):
    """Safe code only: callers must not expose source paths or response bodies."""


def _digest(files):
    digest = hashlib.sha256()
    for path, body in sorted(files):
        if path == "/":
            continue
        digest.update(path[1:].encode("ascii") + b"\0" + hashlib.sha256(body).hexdigest().encode() + b"\0")
    return digest.hexdigest()


def _snapshot(directory):
    audit = exposure_audit(directory, authorized=True, limits={"files": 2, "entries": 2,
                            "fileBytes": MAX_BYTES, "totalBytes": MAX_BYTES, "seconds": 2})
    if audit["status"] != "pass":
        raise PromotionError("CANDIDATE_POLICY_REJECTED")
    root, files = Path(os.path.abspath(os.fspath(directory))), []
    for name in ("app.js", "index.html"):
        path = root / name
        before = path.lstat()
        if _linked(before) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise PromotionError("CANDIDATE_CHANGED")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            if _identity(os.fstat(descriptor)) != _identity(before):
                raise PromotionError("CANDIDATE_CHANGED")
            body = bytearray()
            while len(body) <= MAX_BYTES:
                block = os.read(descriptor, min(65536, MAX_BYTES + 1 - len(body)))
                if not block:
                    break
                body.extend(block)
            if len(body) > MAX_BYTES or _identity(os.fstat(descriptor)) != _identity(before):
                raise PromotionError("CANDIDATE_CHANGED")
            files.append(("/" + name, bytes(body)))
        finally:
            os.close(descriptor)
    if _digest(files) != audit["artifactSha256"]:
        raise PromotionError("CANDIDATE_CHANGED")
    final = exposure_audit(directory, authorized=True, limits={"seconds": 2})
    if final["status"] != "pass" or final["artifactSha256"] != audit["artifactSha256"]:
        raise PromotionError("CANDIDATE_CHANGED")
    files.append(("/", dict(files)["/index.html"]))
    return tuple(sorted(files)), audit["artifactSha256"]


@dataclass(frozen=True)
class _Candidate:
    directory: str
    files: tuple
    digest: str
    generation: int
    previous: str


class PromotionGate:
    """Fixed synthetic static paths; no network, provider, shell or HTTP approval API.

    The trusted test controller bootstraps the already exposed legacy snapshot.
    Candidate releases, unlike that negative control, must pass both audits.
    """

    def __init__(self, legacy_exports, clock=time.monotonic):
        if (type(legacy_exports) is not dict or set(legacy_exports) != set(PUBLIC_PATHS + RETIRED_PATHS)
                or any(type(value) is not bytes for value in legacy_exports.values())
                or sum(map(len, legacy_exports.values())) > MAX_BYTES):
            raise ValueError("Invalid owned legacy fixture")
        self._files = dict(legacy_exports)
        self._digest = _digest(self._files.items())
        self._generation = self._cache_epoch = 0
        self._retired, self._cache, self._candidates, self._grants = set(), {}, {}, {}
        self._lock, self._clock = threading.Lock(), clock

    @property
    def state(self):
        with self._lock:
            return {"generation": self._generation, "artifactSha256": self._digest,
                    "cachedRepresentations": len(self._cache), "retiredPaths": len(self._retired)}

    def stage(self, directory, preview_url, authorized=False):
        if authorized is not True:
            raise PromotionError("AUTHORIZATION_REQUIRED")
        with self._lock:
            if len(self._candidates) >= 8:
                raise PromotionError("CANDIDATE_LIMIT")
            generation, previous = self._generation, self._digest
        result = delivery_audit(directory, preview_url, authorized=True, retired_paths=RETIRED_PATHS,
                                limits={"files": 2, "entries": 2, "fileBytes": MAX_BYTES,
                                        "totalBytes": 4 * MAX_BYTES, "seconds": 3})
        if result["status"] != "pass":
            raise PromotionError("CANDIDATE_DELIVERY_REJECTED")
        try:
            files, digest = _snapshot(directory)
        except (OSError, ValueError, TypeError):
            raise PromotionError("CANDIDATE_CHANGED") from None
        if digest != result["referenceSha256"]:
            raise PromotionError("CANDIDATE_CHANGED")
        with self._lock:
            if generation != self._generation or previous != self._digest or len(self._candidates) >= 8:
                raise PromotionError("STATE_CHANGED")
            handle = "candidate_" + secrets.token_hex(16)
            self._candidates[handle] = _Candidate(os.path.abspath(os.fspath(directory)), files, digest, generation, previous)
            return {"candidateId": handle, "artifactSha256": digest, "expectedGeneration": generation}

    def approve_promotion(self, candidate_id, expected_generation):
        """Trusted controller action. Model output and public requests cannot call this."""
        with self._lock:
            candidate = self._candidates.get(candidate_id)
            if (candidate is None or type(expected_generation) is not int
                    or candidate.generation != expected_generation or self._generation != expected_generation
                    or candidate.previous != self._digest):
                raise PromotionError("STATE_CHANGED")
            return self._grant("promote", candidate)

    def approve_retirement(self, expected_generation):
        """Approve exact known map tombstones plus purging every fixed cache key."""
        with self._lock:
            if (type(expected_generation) is not int or expected_generation != self._generation
                    or set(self._files) != set(PUBLIC_PATHS) or self._retired):
                raise PromotionError("STATE_CHANGED")
            return self._grant("retire", (self._generation, self._digest, RETIRED_PATHS, PUBLIC_PATHS))

    def _grant(self, action, binding):
        if len(self._grants) >= 16:
            raise PromotionError("GRANT_LIMIT")
        handle = secrets.token_urlsafe(32)
        self._grants[handle] = (action, binding, self._clock() + 10)
        return handle

    def _consume(self, handle, action):
        with self._lock:
            value = self._grants.pop(handle, None) if type(handle) is str else None
            if value is None or value[0] != action or not self._clock() < value[2]:
                raise PromotionError("GRANT_DENIED")
            return value[1], value[2]

    def promote(self, handle):
        candidate, expires = self._consume(handle, "promote")
        try:
            _, current_digest = _snapshot(candidate.directory)
        except (OSError, ValueError, TypeError, PromotionError):
            raise PromotionError("CANDIDATE_CHANGED") from None
        if current_digest != candidate.digest:
            raise PromotionError("CANDIDATE_CHANGED")
        with self._lock:
            if (self._generation != candidate.generation or self._digest != candidate.previous
                    or not self._clock() < expires):
                raise PromotionError("STATE_CHANGED")
            # Install approved immutable bytes; never reopen a path after validation.
            self._files, self._digest = dict(candidate.files), candidate.digest
            self._generation += 1
            return {"status": "promoted", **self._state_locked()}

    def retire(self, handle):
        (generation, digest, retired, _), expires = self._consume(handle, "retire")
        with self._lock:
            if (generation != self._generation or digest != self._digest or self._retired
                    or not self._clock() < expires):
                raise PromotionError("STATE_CHANGED")
            purged = len(self._cache)
            self._retired.update(retired)
            self._cache.clear()
            self._cache_epoch += 1
            self._generation += 1
            return {"status": "retired", "purgedRepresentations": purged, **self._state_locked()}

    def _state_locked(self):
        return {"generation": self._generation, "artifactSha256": self._digest}

    def origin(self, path, encoding):
        with self._lock:
            if path in self._retired:
                return 410, b"", False
            body = self._files.get(path)
            if body is None:
                return 404, b"", False
            return 200, gzip.compress(body, mtime=0) if encoding == "gzip" else body, encoding == "gzip"

    def cached(self, path, encoding):
        with self._lock:
            return self._cache_epoch, (410, b"", False) if path in self._retired else self._cache.get((path, encoding))

    def cache_response(self, epoch, path, encoding, response):
        """Reject fills started before explicit purge, including in-flight old origin replies."""
        with self._lock:
            if path in self._retired:
                return 410, b"", False
            if epoch != self._cache_epoch:
                return 503, b"", False
            if (path not in PUBLIC_PATHS + RETIRED_PATHS or encoding not in {"identity", "gzip"}
                    or len(response[1]) > MAX_BYTES):
                return 503, b"", False
            if response[0] == 200:
                self._cache[(path, encoding)] = response
            return response
