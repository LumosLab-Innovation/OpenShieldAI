"""Execute the registered synthetic corpus and scoped Go performance measurements."""

import argparse
import hashlib
import json
import math
import os
import platform
import statistics
import subprocess
import time
from pathlib import Path

from openshield.cli import output
from openshield.core import canonical
from openshield.correlation import BINARY, ROOT, run


def verify():
    corpus_path = ROOT / "tests/fixtures/access_correlation_cases.json"
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
    records, table, pairs = [], {}, {}
    for case in corpus["cases"]:
        result = run(case["input"])
        truth = case["truth"]
        passed = (sorted({item["code"] for item in result["candidates"]}) == sorted(truth["expectedCandidateCodes"])
                  and set(truth["expectedGaps"]) <= set(result["coverage"]["gaps"])
                  and result["isFinding"] is False and result["coverage"]["complete"] is False)
        label = truth["businessGroundTruth"]
        table.setdefault(label, {"candidate": 0, "noCandidate": 0})["candidate" if result["candidates"] else "noCandidate"] += 1
        key = hashlib.sha256(canonical(case["input"]).encode()).hexdigest()
        pairs.setdefault(key, []).append({"id": case["id"], "truth": label})
        records.append({"id": case["id"], "passed": passed, "result": result})

    timed = json.loads(canonical(corpus["cases"][0]["input"]))
    sample = timed["events"][0]
    timed["events"] = [{**sample, "id": f"event_{index}", "facts": {**sample["facts"], "decision": "deny",
                        "subjectLabel": f"subject_{index // 10}"}} for index in range(1000)]
    run(timed)
    timings = []
    for _ in range(30):
        start = time.perf_counter()
        run(timed)
        timings.append((time.perf_counter() - start) * 1000)

    env = {**os.environ, "GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off"}
    command = ["go", "test", "-run", "^$", "-bench", "^BenchmarkAnalyze1000$", "-benchmem", "-count=3", "-benchtime=200ms"]
    benchmark = subprocess.run(command, cwd=ROOT / "runtime-go", env=env, capture_output=True, text=True, timeout=45, check=True)
    lines = [line for line in benchmark.stdout.splitlines() if line.startswith("BenchmarkAnalyze1000")]
    version = subprocess.run(["go", "version"], env=env, capture_output=True, text=True, timeout=5, check=True).stdout.strip()
    sources = ["runtime-go/go.mod", "runtime-go/correlation.go", "runtime-go/correlation_test.go",
               "runtime-go/cmd/shield-correlate/main.go", "openshield/correlation.py", "openshield/core.py", "openshield/cli.py",
               "scripts/check_go_runtime.py"]
    return {"schemaVersion": "go_correlation_trial_v1", "synthetic": True,
            "status": "pass" if all(item["passed"] for item in records) else "failed",
            "ruleVersion": "access_window_v1", "toolchain": version,
            "host": {"os": platform.system(), "architecture": platform.machine(),
                     "cpu": platform.processor(), "logicalCPUs": os.cpu_count()},
            "binarySha256": hashlib.sha256(BINARY.read_bytes()).hexdigest(),
            "sourceFingerprintEncoding": "UTF-8 with LF newlines",
            "sourceSha256": {name: hashlib.sha256((ROOT / name).read_text(encoding="utf-8").encode()).hexdigest() for name in sources},
            "corpusSha256": hashlib.sha256(corpus_path.read_text(encoding="utf-8").encode()).hexdigest(),
            "corpusResults": records, "authoredBusinessTable": table,
            "identicalInputDifferentTruth": [{"inputSha256": key, "cases": cases} for key, cases in pairs.items() if len({case["truth"] for case in cases}) > 1],
            "latency": {"scope": "Fresh Go process + Python strict reply validation; 1000 synthetic events; warm OS cache; serial local trials",
                        "samples": len(timings), "samplesMs": timings, "medianMs": round(statistics.median(timings), 3),
                        "p95Ms": round(sorted(timings)[math.ceil(.95 * len(timings)) - 1], 3),
                        "minMs": round(min(timings), 3), "maxMs": round(max(timings), 3)},
            "goMicrobenchmark": {"scope": "Analyze validates/parses/correlates and checks output size; excludes process launch, pipe transport, Python and real services",
                                 "lines": lines}, "aiBenefit": {"status": "not_measured"},
            "limitations": ["Selected synthetic regression cases; rule consistency is not representative attack accuracy",
                            "Authored intent labels remain outside worker input and are not observed proof of harm",
                            "Identical observations can correspond to opposite business truth",
                            "No equivalent Python implementation comparison or Go/Rust speedup claim",
                            "Local latency excludes real collection, queueing, model, operator and actuator time",
                            "No production source authentication, hard OS memory sandbox or live control effect accepted"]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="output/go-correlation-results.json")
    args = parser.parse_args()
    result = verify()
    output(result, args.output)
    output({"status": result["status"], "cases": len(result["corpusResults"]), "latency": result["latency"],
            "authoredBusinessTable": result["authoredBusinessTable"], "artifact": args.output})
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
