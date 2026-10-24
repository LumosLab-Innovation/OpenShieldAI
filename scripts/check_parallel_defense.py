"""Run the owned HTTP defense experiments; no model or production endpoint."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lab.anti_rea import verify as anti_rea_trial
from lab.delivery import verify as delivery_trial
from lab.durable_authority import verify as durable_trial
from openshield.cli import output


def verify():
    binary = ROOT / "artifacts/runtime-go" / ("shield-tool-lab.exe" if os.name == "nt" else "shield-tool-lab")
    # Only the repository's explicitly built fixture is executable, with no caller/model arguments.
    process = subprocess.run([str(binary)], cwd=ROOT, capture_output=True, timeout=20, check=False)
    if process.returncode or process.stderr or len(process.stdout) > 65536:
        raise RuntimeError("Fixed Go lab failed")
    tool = json.loads(process.stdout)
    if not (tool["schemaVersion"] == "tool_guard_trial_v1" and tool["status"] == "passed"
            and tool["modelCalls"] == 0 and tool["productionActions"] is False
            and tool["checks"] and all(check["passed"] is True for check in tool["checks"])
            and tool["negativeControlEffects"] == {"reads": 0, "marks": 1, "deliveries": 1}
            and tool["negativeControlOutsideRecipientDeliveries"] == 1
            and tool["protectedForbiddenEffects"] == {"reads": 0, "marks": 0, "deliveries": 0}
            and tool["protectedAllowedEffects"] == {"reads": 9, "marks": 1, "deliveries": 1}
            and tool["concurrentAccepted"] == 1):
        raise RuntimeError("Fixed Go lab effect assertions failed")
    arms = {"toolAuthority": tool, "antiRea": anti_rea_trial(),
            "durableAuthority": durable_trial(), "delivery": delivery_trial()}
    passed = (all(arms[name]["status"] == "pass" for name in ("antiRea", "durableAuthority", "delivery"))
              and all(arms["antiRea"]["checks"].values())
              and all(arms["durableAuthority"]["checks"].values())
              and all(case["passed"] for case in arms["delivery"]["cases"]))
    sources = [ROOT / name for name in ("openshield/authority.py", "openshield/exposure.py", "openshield/delivery.py",
               "openshield/cli.py", "lab/anti_rea.py", "lab/delivery.py", "lab/durable_authority.py",
               "scripts/check_parallel_defense.py", "runtime-go/go.mod")]
    sources += list((ROOT / "runtime-go/toolguard").glob("*.go"))
    sources += list((ROOT / "runtime-go/cmd/shield-tool-lab").glob("*.go"))
    digest = hashlib.sha256()
    for path in sorted(sources):
        digest.update(path.relative_to(ROOT).as_posix().encode() + b"\0")
        digest.update(path.read_text(encoding="utf-8").encode("utf-8") + b"\0")
    return {"schemaVersion": "parallel_defense_v1", "status": "pass" if passed else "failed",
            "dataClass": "synthetic", "transport": "real_loopback_http", "modelCalls": 0,
            "productionActions": False, "sourceTreeSha256": digest.hexdigest(),
            "goBinarySha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "checks": {"toolAuthority": len(tool["checks"]), "antiRea": len(arms["antiRea"]["checks"]),
                       "durableAuthority": len(arms["durableAuthority"]["checks"]),
                       "delivery": len(arms["delivery"]["cases"])},
            "arms": arms, "aiBenefit": {"status": "not_measured"},
            "limitations": ["Named assertions and fixtures, not independent attack success-rate estimates",
                            "No authenticated production identity, model efficacy or full website coverage",
                            "Durable quote authority and ephemeral Go tool authority are different experiments",
                            "Trusted administrator snapshot rollback can restore old authority state",
                            "Authorized outputs remain an algorithm-inference channel"]}


def main():
    try:
        report = verify()
        output(report, ROOT / "output/parallel-defense.json")
        output({"status": report["status"], "checks": report["checks"],
                "artifact": "output/parallel-defense.json", "modelCalls": 0, "productionActions": False})
        return 0 if report["status"] == "pass" else 1
    except (OSError, ValueError, RuntimeError, AssertionError, KeyError, TypeError, subprocess.TimeoutExpired):
        output({"status": "failed", "code": "OWNED_LAB_FAILED_OR_BINARY_NOT_BUILT"})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
