"""Fixed local Go analysis worker. No tool path or operation comes from evidence."""

import hashlib
import os
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path

from .core import canonical, exact_fields, identifier, timestamp, validate_event
from .gateway import strict_json


ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "artifacts/runtime-go" / ("shield-correlate.exe" if os.name == "nt" else "shield-correlate")
GAPS = {"source_missing", "source_unavailable", "source_events_dropped", "future_event", "empty_window",
        "same_timestamp_order_unknown", "candidate_limit", "evidence_limit", "upstream_stale_evidence",
        "upstream_visibility_gap", "upstream_source_clock_skew", "upstream_no_independent_observer"}
LIMITS = {"synthetic_lab_only", "authorization_not_authentication", "candidate_not_compromise",
          "source_authentication_unverified", "fixed_threshold_uncalibrated", "bounded_window", "no_actuator"}
CODES = {"repeated_access_denials", "denied_access_then_allow"}


def nanoseconds(value):
    parsed = timestamp(value)
    fraction = value[:-1].partition(".")[2]
    if len(fraction) > 9 or (fraction and (not fraction.isascii() or not fraction.isdigit())):
        raise ValueError("Unsupported timestamp precision")
    delta = parsed.replace(microsecond=0) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + int(fraction.ljust(9, "0"))


class CorrelationError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def request_for(case, scope, as_of):
    events = []
    for row in case["timeline"]:
        if row["kind"] not in {"auth_decision", "source_health"}:
            continue
        event = {key: value for key, value in row.items() if key not in {"ingestedAt", "sourceTrust", "sourceRole"}}
        validate_event(event)
        events.append(event)
    return {"schemaVersion": "correlation_request_v1", "projectId": case["projectId"],
            "caseId": case["caseId"], "assetId": case["assetId"],
            "runId": "go_" + case["watermark"][:24], "scopeVersion": scope["scopeVersion"],
            "asOf": as_of, "sourceIds": scope["sourceIds"], "upstreamGaps": case["gaps"], "events": events}


def validate_result(result, request, payload):
    exact_fields(result, {"schemaVersion", "status", "ruleVersion", "runId", "projectId", "caseId", "assetId",
                          "scopeVersion", "inputSha256", "asOf", "windowSeconds", "counts", "candidates",
                          "coverage", "limitations", "isFinding"})
    if (result["schemaVersion"] != "correlation_result_v1" or result["status"] not in {"succeeded", "partial"}
            or result["isFinding"] is not False or result["ruleVersion"] != "access_window_v1"
            or type(result["windowSeconds"]) is not int or result["windowSeconds"] != 60
            or result["inputSha256"] != hashlib.sha256(payload).hexdigest()):
        raise ValueError("Invalid worker contract")
    for field in ("runId", "projectId", "caseId", "assetId", "scopeVersion", "asOf"):
        if result[field] != request[field]:
            raise ValueError("Worker scope mismatch")
    exact_fields(result["counts"], {"inputEvents", "uniqueEvents", "duplicateEvents", "windowEvents", "oldEvents", "futureEvents"})
    counts = result["counts"]
    if any(type(value) is not int or not 0 <= value <= 1000 for value in counts.values()):
        raise ValueError("Invalid count")
    if (counts["inputEvents"] != len(request["events"]) or counts["uniqueEvents"] + counts["duplicateEvents"] != counts["inputEvents"]
            or counts["windowEvents"] + counts["oldEvents"] + counts["futureEvents"] != counts["uniqueEvents"]):
        raise ValueError("Invalid accounting")
    coverage = result["coverage"]
    exact_fields(coverage, {"complete", "gaps", "sourcesObserved"})
    if coverage["complete"] is not False:
        raise ValueError("Unsupported complete coverage")
    for items, allowed in ((coverage["gaps"], GAPS), (coverage["sourcesObserved"], set(request["sourceIds"])),
                           (result["limitations"], LIMITS)):
        if (not isinstance(items, list) or any(not isinstance(item, str) or item not in allowed for item in items)
                or len(set(items)) != len(items)):
            raise ValueError("Invalid enum list")
    if set(result["limitations"]) != LIMITS or (result["status"] == "partial") != bool(coverage["gaps"]):
        raise ValueError("Missing worker limitations")
    known = {row["id"]: row for row in request["events"]}
    end = nanoseconds(request["asOf"])
    times = {key: nanoseconds(row["observedAt"]) for key, row in known.items()}
    window = {key: row for key, row in known.items() if end - 60_000_000_000 < times[key] <= end}
    future = sum(at > end for at in times.values())
    if (counts["uniqueEvents"] != len(known) or counts["windowEvents"] != len(window)
            or counts["futureEvents"] != future):
        raise ValueError("Worker window accounting mismatch")
    sources = {row["sourceId"] for row in window.values()}
    mandatory = {"upstream_" + gap for gap in request["upstreamGaps"]}
    if sources != set(request["sourceIds"]):
        mandatory.add("source_missing")
    if not window:
        mandatory.add("empty_window")
    if future:
        mandatory.add("future_event")
    for key, row in known.items():
        if row["kind"] == "source_health" and times[key] <= end:
            if not row["facts"]["available"]:
                mandatory.add("source_unavailable")
            if row["facts"]["dropped"]:
                mandatory.add("source_events_dropped")
    ties = {}
    for key, row in window.items():
        if row["kind"] == "auth_decision":
            pair = (row["facts"]["subjectLabel"], row["facts"]["objectLabel"], times[key])
            ties.setdefault(pair, set()).add(row["facts"]["decision"])
    if any(len(decisions) > 1 for decisions in ties.values()):
        mandatory.add("same_timestamp_order_unknown")
    if not mandatory <= set(coverage["gaps"]) or set(coverage["sourcesObserved"]) != sources:
        raise ValueError("Worker dropped visibility gaps")
    candidates = result["candidates"]
    if not isinstance(candidates, list) or len(candidates) > 64:
        raise ValueError("Candidate cap exceeded")
    for item in candidates:
        exact_fields(item, {"code", "subjectLabel", "objectLabel", "evidenceIds", "observedCount", "evidenceTruncated", "isFinding"})
        if item["code"] not in CODES or item["isFinding"] is not False:
            raise ValueError("Invalid candidate")
        identifier(item["subjectLabel"]); identifier(item["objectLabel"])
        refs = item["evidenceIds"]
        if (not isinstance(refs, list) or not 1 <= len(refs) <= 20 or any(not isinstance(ref, str) or ref not in known for ref in refs)
                or len(set(refs)) != len(refs) or type(item["observedCount"]) is not int
                or not len(refs) <= item["observedCount"] <= 1000
                or type(item["evidenceTruncated"]) is not bool or item["evidenceTruncated"] != (item["observedCount"] > len(refs))):
            raise ValueError("Invalid candidate evidence")
        for ref in refs:
            row = window.get(ref)
            if row is None:
                raise ValueError("Out-of-window evidence")
            if (row["kind"] != "auth_decision" or row["facts"]["subjectLabel"] != item["subjectLabel"]
                    or row["facts"]["objectLabel"] != item["objectLabel"]):
                raise ValueError("Candidate evidence mismatch")
        matching_denies = {key for key, row in window.items() if row["kind"] == "auth_decision"
                           and row["facts"]["subjectLabel"] == item["subjectLabel"]
                           and row["facts"]["objectLabel"] == item["objectLabel"] and row["facts"]["decision"] == "deny"}
        if item["code"] == "repeated_access_denials":
            support = matching_denies
            if len(support) < 5:
                raise ValueError("Below-threshold candidate")
        else:
            allow = refs[-1]
            if window[allow]["facts"]["decision"] != "allow":
                raise ValueError("Missing allowed-decision evidence")
            support = {key for key in matching_denies if times[key] < times[allow]} | {allow}
            if len(support) < 4:
                raise ValueError("Unordered or below-threshold sequence")
        if (item["observedCount"] != len(support) or not set(refs) <= support
                or (not item["evidenceTruncated"] and set(refs) != support)):
            raise ValueError("Unsupported candidate count or references")
        if item["evidenceTruncated"] and "evidence_limit" not in coverage["gaps"]:
            raise ValueError("Missing truncation gap")
    return result


def run(request):
    payload = canonical(request).encode()
    if len(payload) > 1_048_576:
        raise CorrelationError("INPUT_LIMIT")
    if not BINARY.is_file() or BINARY.is_symlink():
        raise CorrelationError("GO_WORKER_UNAVAILABLE")
    env = {key: os.environ[key] for key in ("SystemRoot", "WINDIR") if key in os.environ}
    env["GOMEMLIMIT"] = "64MiB"
    process = None
    try:
        process = subprocess.Popen([str(BINARY)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, cwd=ROOT, env=env, shell=False)
        data = []

        def read():
            data.append(process.stdout.read(65_537))
            if len(data[0]) > 65_536:
                process.kill()

        reader = threading.Thread(target=read, daemon=True)
        timer = threading.Timer(2, process.kill)
        timer.start(); reader.start()
        try:
            process.stdin.write(payload)
            process.stdin.close()
            process.wait(timeout=2.1)
            reader.join(timeout=.2)
        finally:
            timer.cancel()
        if reader.is_alive() or not data or len(data[0]) > 65_536:
            raise CorrelationError("OUTPUT_LIMIT_OR_DEADLINE")
        if process.returncode:
            raise CorrelationError("GO_WORKER_FAILED")
        result = strict_json(data[0].decode("utf-8"))
        return validate_result(result, request, payload)
    except (OSError, subprocess.SubprocessError):
        raise CorrelationError("GO_WORKER_FAILED") from None
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise CorrelationError("INVALID_WORKER_RESULT") from None
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill(); process.wait(timeout=1)
            for stream in (process.stdin, process.stdout):
                if stream is not None:
                    stream.close()


def correlate(store, project_id, case_id):
    case = store.case(project_id, case_id)
    scope = store.enrollment(project_id, case["assetId"])
    return run(request_for(case, scope, store._utc_now()))
