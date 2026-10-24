"""Offline post-hoc comparator against retained real AI; never calls a provider."""

import argparse
from contextlib import closing
import hashlib
import json
from pathlib import Path
import platform
import tempfile
import time

from openshield.baseline_v2 import baseline_v2
from openshield.core import Store, timestamp, utc_now
from openshield.evaluation import fingerprint


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "docs/lab/evidence/next-wave-corpus.json"
RETAINED = ROOT / "docs/lab/evidence/next-wave.json"


def _load(path):
    if Path(path).stat().st_size > 1_000_000:
        raise ValueError("Synthetic comparison input exceeds limit")
    text = Path(path).read_text(encoding="utf-8")
    return json.loads(text), hashlib.sha256(text.encode()).hexdigest()


def compare(corpus_path=CORPUS, retained_path=RETAINED):
    corpus, corpus_hash = _load(corpus_path)
    retained, retained_hash = _load(retained_path)
    if not (corpus.get("schemaVersion") == "heldout_corpus_v1" and corpus.get("synthetic") is True
            and corpus["registration"]["evaluationClass"] == "public_engineering_regression_not_heldout"
            and corpus["registration"]["allowedActions"] == []
            and retained.get("schemaVersion") == "next_wave_lab_v1"
            and retained.get("realAICompletedAllCases") is True
            and retained["registeredCorpusSha256"] == corpus_hash
            and retained["comparison"]["manifest"]["corpusSha256"] == corpus_hash):
        raise ValueError("Matched public corpus and completed retained real AI record required")
    scenarios = corpus["cases"]
    ids = [case["id"] for case in scenarios]
    if not 1 <= len(ids) <= 1000 or len(set(ids)) != len(ids):
        raise ValueError("Bounded unique cases required")
    references = retained["comparison"]["arms"]
    for mode in ("baseline", "ai"):
        arm = references[mode]
        rows = {row["id"]: row for row in arm["cases"]}
        if (arm["status"] != "completed" or len(rows) != len(ids) or set(rows) != set(ids)
                or arm["metrics"]["providerUnavailableCases"] != 0):
            raise ValueError("Retained complete arms must match corpus cases")
        for scenario in scenarios:
            row, truth = rows[scenario["id"]], scenario["truth"]
            if (truth["ingest"] != "accept" or row["expectedIngest"] != truth["ingest"]
                    or row["expectedIncident"] != truth["incident"]
                    or row["rejected"] or not row["available"]):
                raise ValueError("Retained scoring population must match the accepted corpus")
    clock = timestamp(corpus["registration"]["replayClockUTC"])
    rows = []
    started = time.monotonic()
    for scenario in scenarios:
        with tempfile.TemporaryDirectory(prefix="openshield-v2-eval-") as directory, closing(
                Store(Path(directory) / "state.sqlite3", clock=lambda: clock)) as store:
            store.enroll("p_eval", "a_eval", "evaluator", source_ids=("lab", "observer"),
                         source_roles={"lab": "telemetry", "observer": "observer"}, allowed_actions=[])
            store.ingest_batch(scenario["input"]["events"])
            # Only the Store snapshot crosses the decision boundary, not scenario/truth.
            snapshot = store.case("p_eval", scenario["id"])
            analysis = baseline_v2(snapshot)
        truth, assessment = scenario["truth"], analysis["assessment"]
        expected = truth["incident"]
        if expected not in {"supported", "not_supported", "unknown"}:
            raise ValueError("Registered incident class required")
        correct = (assessment == "suspicious" if expected == "supported" else
                   assessment == "insufficient_evidence" if expected == "unknown" else
                   assessment in {"benign", "insufficient_evidence"})
        codes = sorted({item["code"] for item in analysis["hypotheses"]})
        rows.append({"id": scenario["id"], "expectedIncident": expected, "assessment": assessment,
                     "policyAcceptable": correct, "nextAction": analysis["nextAction"], "hypothesisCodes": codes,
                     "proposalAcceptable": analysis["nextAction"] in truth["acceptableNextActions"],
                     "requiredHypothesesPresent": set(truth["requiredHypotheses"]) <= set(codes),
                     "sourceGaps": snapshot["gaps"], "calls": 0, "tokens": 0})
    wall = time.monotonic() - started
    metrics = {"cases": len(rows), "comparisonCases": len(rows),
               "policyAcceptableDecisions": sum(row["policyAcceptable"] for row in rows),
               "supportedCases": sum(row["expectedIncident"] == "supported" for row in rows),
               "truePositives": sum(row["expectedIncident"] == "supported" and row["assessment"] == "suspicious" for row in rows),
               "negativeCases": sum(row["expectedIncident"] == "not_supported" for row in rows),
               "falsePositives": sum(row["expectedIncident"] == "not_supported" and row["assessment"] == "suspicious" for row in rows),
               "decisiveBenign": sum(row["expectedIncident"] == "not_supported" and row["assessment"] == "benign" for row in rows),
               "negativeAbstentions": sum(row["expectedIncident"] == "not_supported" and row["assessment"] == "insufficient_evidence" for row in rows),
               "unknownCases": sum(row["expectedIncident"] == "unknown" for row in rows),
               "correctUnknown": sum(row["expectedIncident"] == "unknown" and row["policyAcceptable"] for row in rows),
               "acceptableProposals": sum(row["proposalAcceptable"] for row in rows),
               "proposalScoredCases": len(rows),
               "requiredHypothesisMatches": sum(row["requiredHypothesesPresent"] for row in rows),
               "hypothesisScoredCases": len(rows), "providerUnavailableCases": 0, "calls": 0, "tokens": 0,
               "wallSeconds": wall}
    if fingerprint(corpus_path) != corpus_hash or fingerprint(retained_path) != retained_hash:
        raise ValueError("Frozen input changed during comparison")
    return {"schemaVersion": "baseline_v2_comparison_v1", "dataClass": "synthetic", "productionActions": False,
            "modelCalls": 0, "evaluationClass": "post_hoc_public_engineering_regression_not_heldout",
            "manifest": {"corpusSha256": corpus_hash, "retainedRealRunSha256": retained_hash,
                         "sourceHashes": {name: fingerprint(ROOT / name) for name in (
                             "openshield/core.py", "openshield/baseline_v2.py", "lab/baseline_v2_comparison.py")},
                         "allowedActions": [], "labelsSentToDecision": False, "hostRunAt": utc_now(),
                         "python": platform.python_version(), "platform": platform.platform()},
            "arms": {"baseline_v1_retained": {"metrics": references["baseline"]["metrics"]},
                     "baseline_v2": {"metrics": metrics, "cases": rows},
                     "ai_retained": {"metrics": references["ai"]["metrics"]}},
            "limitations": ["Two generic lookup rules were added after inspecting this public corpus and the real AI results; no independent held-out validation.",
                            "The frozen baseline v1 and actual AI artifacts were not modified or rerun; retained times/usage are historical.",
                            "The v2 direct-function harness includes isolated Store setup/intake but no resident Supervisor persistence; its wall time is not a matched speedup measurement.",
                            "V2 receives the same accepted snapshot and zero actuators, has the same catalog available and requests no extra observations.",
                            "Required-code presence and acceptable next-step membership are curator checks, not semantic accuracy or production effectiveness.",
                            "No human/operator-time or new attack-effect comparison was performed; enforcement is unchanged."]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "output/baseline-v2.json")
    args = parser.parse_args(argv)
    if args.output.resolve() in {CORPUS.resolve(), RETAINED.resolve()}:
        raise ValueError("Output cannot replace frozen comparison inputs")
    report = compare()
    from openshield.cli import output
    output(report, args.output)


if __name__ == "__main__":
    main()
