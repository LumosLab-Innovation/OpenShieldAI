"""Selected owned effect experiments and a separate equal-input triage comparison."""

import hashlib
import json
import os
from pathlib import Path
import subprocess

from openshield.core import canonical
from openshield.evaluation import compare, fingerprint
from openshield.gateway import Gateway


ROOT = Path(__file__).resolve().parents[1]


def _flow():
    binary = ROOT / "artifacts/runtime-go" / ("shield-flow-lab.exe" if os.name == "nt" else "shield-flow-lab")
    process = subprocess.run([str(binary)], cwd=ROOT, capture_output=True, timeout=20, check=False)
    if process.returncode or process.stderr or len(process.stdout) > 65536:
        raise RuntimeError("Fixed flow lab failed")
    report = json.loads(process.stdout)
    if not (report["schemaVersion"] == "flow_lab_v1" and report["status"] == "passed"
            and report["modelCalls"] == 0 and report["productionActions"] is False
            and report["checks"] and all(item["passed"] is True for item in report["checks"])
            and report["negativeControlEffects"] == {"reads": 4, "charges": 3, "chargedUnits": 3}
            and report["protectedForbiddenEffects"] == {"reads": 0, "charges": 0, "chargedUnits": 0}
            and report["protectedAllowedEffects"] == {"reads": 2, "charges": 2, "chargedUnits": 2}
            and report["negativeControlOutsideDeliveries"] == 2
            and report["protectedOutsideRequests"] == 0 and report["protectedOutsideDeliveries"] == 0
            and report["protectedAllowedDeliveries"] == 1 and report["idempotentConcurrentCommits"] == 1):
        raise RuntimeError("Flow effect assertions failed")
    return report, hashlib.sha256(binary.read_bytes()).hexdigest()


def verify(*, with_ai=False, progress=None):
    from lab.next_wave_corpus import build_corpus
    from lab.promotion import verify as promotion_trial
    from lab.recovery_readiness import verify as recovery_trial
    from openshield.cli import output

    if type(with_ai) is not bool:
        raise ValueError("Explicit AI selection required")
    flow, binary_hash = _flow()
    promotion, recovery = promotion_trial(), recovery_trial()
    for report in (promotion, recovery):
        if not (report["status"] == "passed" and report["modelCalls"] == 0
                and report["productionActions"] is False and report["checks"]
                and all(item["passed"] is True for item in report["checks"])):
            raise RuntimeError("Owned experiment failed")
    effects = {"flow": flow, "promotion": promotion, "recovery": recovery}
    corpus = build_corpus(flow, promotion, recovery)
    corpus_path = ROOT / "output/next-wave-corpus.json"
    # Capture the exact generated input/truth split before any inference request.
    output(corpus, corpus_path)
    frozen_hash = fingerprint(corpus_path)
    gateway = Gateway.from_env() if with_ai else None
    comparison = compare(corpus_path, gateway, progress=progress)
    if fingerprint(corpus_path) != frozen_hash:
        raise RuntimeError("Registered corpus changed during comparison")
    available = (comparison["arms"]["ai"].get("metrics") or {}).get("providerUnavailableCases")
    ai_complete = gateway is not None and available == 0
    sources = ["lab/next_wave.py", "lab/next_wave_corpus.py", "lab/promotion.py", "openshield/promotion.py",
               "lab/recovery_readiness.py", "openshield/core.py", "openshield/gateway.py", "openshield/evaluation.py"]
    return {"schemaVersion": "next_wave_lab_v1", "status": "completed" if not with_ai or ai_complete else "partial",
            "dataClass": "synthetic", "effectsStatus": "passed", "effects": effects,
            "effectCheckCounts": {name: len(report["checks"]) for name, report in effects.items()},
            "effectManifestSha256": hashlib.sha256(canonical(effects).encode()).hexdigest(),
            "goBinarySha256": binary_hash, "sourceHashes": {name: fingerprint(ROOT / name) for name in sources},
            "registeredCorpusSha256": frozen_hash, "comparison": comparison,
            "realAIRequested": with_ai, "realAICompletedAllCases": ai_complete, "productionActions": False,
            "limitations": ["Selected public engineering regressions, not held-out efficacy or portfolio-wide protection",
                            "Inference sees minimized facts only; missing distinctions remain unknowable",
                            "Effect controls and authority are identical with and without AI; AI cannot approve or execute",
                            "Triage and typed proposals are scored separately from actual prevention/recovery effects",
                            "No blinded operator-time trial or production AI advantage is established"]}
