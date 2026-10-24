"""Frozen synthetic evaluation; ground truth never enters the model context."""

import hashlib
from contextlib import closing
import json
import platform
import tempfile
import time
from pathlib import Path

from .core import ACTIONS, Store, Supervisor, timestamp, utc_now


ROOT = Path(__file__).resolve().parents[1]


class _EvaluationGateway:
    """Keep the operator's spend ceiling across isolated per-case databases."""

    def __init__(self, gateway):
        self.gateway = gateway
        self.config, self.route_hash = gateway.config, gateway.route_hash
        self.reserved_tokens = 0

    @property
    def last_metadata(self):
        return self.gateway.last_metadata

    def analyze(self, case, *, before_attempt, deadline):
        from .gateway import GatewayError

        def reserve(tokens):
            if self.reserved_tokens + tokens > self.config.global_token_limit:
                raise GatewayError("BUDGET_EXHAUSTED")
            before_attempt(tokens)
            self.reserved_tokens += tokens
        return self.gateway.analyze(case, before_attempt=reserve, deadline=deadline)


def fingerprint(path):
    return hashlib.sha256(Path(path).read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def compare(corpus_path, gateway=None, *, progress=None):
    path = Path(corpus_path)
    if path.stat().st_size > 1_000_000:
        raise ValueError("Corpus exceeds limit")
    corpus_text = path.read_text(encoding="utf-8")
    corpus_hash = hashlib.sha256(corpus_text.encode("utf-8")).hexdigest()
    corpus = json.loads(corpus_text)
    if corpus.get("schemaVersion") != "heldout_corpus_v1" or corpus.get("synthetic") is not True:
        raise ValueError("Only the registered synthetic corpus is supported")
    replay_clock = timestamp(corpus["registration"]["replayClockUTC"])
    allowed_actions = corpus["registration"].get("allowedActions", ["set_site_ingress_mode", "restore_isolated"])
    if (not isinstance(allowed_actions, list) or any(not isinstance(item, str) for item in allowed_actions)
            or len(allowed_actions) != len(set(allowed_actions)) or not set(allowed_actions) <= ACTIONS):
        raise ValueError("Invalid registered action authority")
    manifest = {
        "corpusSha256": corpus_hash,
        "coreSha256": fingerprint(ROOT / "openshield/core.py"),
        "gatewaySha256": fingerprint(ROOT / "openshield/gateway.py"),
        "evaluationSha256": fingerprint(ROOT / "openshield/evaluation.py"),
        "evaluationClass": corpus["registration"].get("evaluationClass", "registered_synthetic_replay"),
        "allowedActions": allowed_actions,
        "sourceHashFormat": "SHA-256 of UTF-8 text with LF newlines",
        "python": platform.python_version(), "platform": platform.platform(),
        "hostRunAt": utc_now(), "replayClockUTC": corpus["registration"]["replayClockUTC"],
        "labelsSentToModel": False,
        "promptTuningDisclosure": "Not automatically verified; see the registered first-run independent review.",
        "aiRoute": ({"provider": gateway.config.provider, "modelAlias": gateway.config.model,
                     "routeHash": gateway.route_hash, "globalReservedTokenCeiling": gateway.config.global_token_limit,
                     "upstreamIdentityVerified": False} if gateway is not None else None),
    }
    results = {"schemaVersion": "comparison_v1", "synthetic": True, "manifest": manifest, "arms": {}}
    evaluation_gateway = _EvaluationGateway(gateway) if gateway is not None else None
    for mode in ("baseline", "ai"):
        if mode == "ai" and gateway is None:
            results["arms"][mode] = {"status": "blocked_provider_unconfigured", "metrics": None,
                                    "reason": "CLIProxyAPI endpoint/model not configured; no simulated AI score."}
            continue
        rows = []
        started = time.monotonic()
        for scenario in corpus["cases"]:
            with tempfile.TemporaryDirectory(prefix="openshield-eval-") as tmp, closing(
                    Store(Path(tmp) / "state.sqlite3", clock=lambda: replay_clock)) as store:
                store.enroll("p_eval", "a_eval", "evaluator", source_ids=("lab", "observer"),
                             source_roles={"lab": "telemetry", "observer": "observer"},
                             allowed_actions=allowed_actions)
                before = time.monotonic()
                rejected = False
                decision = None
                try:
                    store.ingest_batch(scenario["input"]["events"])
                except ValueError:
                    rejected = True
                if not rejected:
                    supervisor = Supervisor(store, gateway=evaluation_gateway if mode == "ai" else None, mode=mode)
                    decisions = supervisor.tick()
                    decision = decisions[-1] if decisions else None
                elapsed = time.monotonic() - before
                truth = scenario["truth"]
                assessment = decision["assessment"] if decision else None
                ai_status = decision.get("aiStatus") if decision else None
                eligible = truth["ingest"] == "accept"
                # An outage is an unsuccessful AI run, not a baseline win credited to AI.
                available = mode == "baseline" or ai_status == "succeeded"
                expected = truth["incident"]
                correct = (assessment == "suspicious" if expected == "supported" else
                           assessment == "insufficient_evidence" if expected == "unknown" else
                           assessment in ("benign", "insufficient_evidence") if expected == "not_supported" else None)
                codes = sorted({item["code"] for item in decision.get("hypotheses", [])}) if decision else []
                action_acceptable = (bool(decision and available and decision.get("nextAction") in truth["acceptableNextActions"])
                                     if "acceptableNextActions" in truth else None)
                required_supported = (bool(decision and available and set(truth["requiredHypotheses"]) <= set(codes))
                                      if "requiredHypotheses" in truth else None)
                rows.append({"id": scenario["id"], "group": scenario["group"],
                             "expectedIncident": expected, "expectedIngest": truth["ingest"],
                             "rejected": rejected, "assessment": assessment, "aiStatus": ai_status,
                             "aiFailureCode": decision.get("aiFailureCode") if decision else None,
                             "persistedEventsAfterReject": sum(len(case["evidenceIds"]) for case in store.cases()) if rejected else None,
                             "eligible": eligible, "available": available,
                             "correct": bool(correct and not rejected and available) if eligible else rejected,
                             "nextAction": decision.get("nextAction") if decision else None,
                             "hypothesisCodes": codes,
                             "proposalAcceptable": action_acceptable,
                             "requiredHypothesesPresent": required_supported,
                             "modelProvenance": decision.get("modelProvenance") if decision else None,
                             "routeHash": decision.get("routeHash") if decision else None,
                             "sourceGaps": store.cases()[0]["gaps"] if not rejected and store.cases() else [],
                             "calls": decision.get("calls", 0) if decision else 0,
                             "tokens": decision.get("tokens", 0) if decision else 0,
                             "elapsedSeconds": elapsed})
                if progress is not None:
                    progress({"arm": mode, "caseIndex": len(rows), "totalCases": len(corpus["cases"]),
                              "aiStatus": ai_status, "calls": rows[-1]["calls"]})
        eligible = [row for row in rows if row["eligible"]]
        positives = [row for row in eligible if row["expectedIncident"] == "supported"]
        negatives = [row for row in eligible if row["expectedIncident"] == "not_supported"]
        unknown = [row for row in eligible if row["expectedIncident"] == "unknown"]
        results["arms"][mode] = {"status": "completed", "metrics": {
            "cases": len(rows), "comparisonCases": len(eligible),
            "policyAcceptableDecisions": sum(row["correct"] for row in eligible),
            "supportedCases": len(positives),
            "truePositives": sum(row["assessment"] == "suspicious" and row["available"] for row in positives),
            "falsePositives": sum(row["assessment"] == "suspicious" for row in negatives),
            "negativeCases": len(negatives), "unknownCases": len(unknown),
            "decisiveBenign": sum(row["assessment"] == "benign" for row in negatives),
            "negativeAbstentions": sum(row["assessment"] == "insufficient_evidence" for row in negatives),
            "correctUnknown": sum(row["correct"] for row in unknown),
            "abstentions": sum(row["assessment"] == "insufficient_evidence" for row in eligible),
            "boundaryRejects": sum(row["correct"] for row in rows if not row["eligible"]),
            "providerUnavailableCases": sum(not row["available"] for row in eligible),
            "proposalScoredCases": sum(row["proposalAcceptable"] is not None for row in eligible),
            "acceptableProposals": sum(row["proposalAcceptable"] is True for row in eligible),
            "hypothesisScoredCases": sum(row["requiredHypothesesPresent"] is not None for row in eligible),
            "requiredHypothesisMatches": sum(row["requiredHypothesesPresent"] is True for row in eligible),
            "calls": sum(row["calls"] for row in rows), "tokens": sum(row["tokens"] for row in rows),
            "wallSeconds": time.monotonic() - started,
        }, "decisionMatrix": {expected: {assessment: sum(row["expectedIncident"] == expected and row["assessment"] == assessment for row in eligible)
                                           for assessment in ("suspicious", "benign", "insufficient_evidence", None)}
                                 for expected in ("supported", "not_supported", "unknown")}, "cases": rows}
    results["limitations"] = [
        "Synthetic corpus with its declared registration class; no production efficacy or analyst-time claim.",
        "Some inputs already encode observer-resolved facts; this is not proof of raw-telemetry AI insight.",
        "The same enrollment, evidence and action authority are used by both arms.",
        "A conservative abstention on a benign case is counted acceptable and reported separately.",
        "No human/operator trial; no AI advantage can be inferred from an unavailable provider.",
        "Proposal/hypothesis checks use explicit curator expectations, not general semantic verification.",
        "Both arms share observed effects; this comparison does not credit deterministic prevention to AI.",
    ]
    if fingerprint(path) != corpus_hash:
        raise ValueError("Registered corpus changed during comparison")
    return results
