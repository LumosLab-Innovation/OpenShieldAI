"""Local synthetic runtime and explicitly selected isolated lab commands."""

import argparse
import getpass
import hashlib
import json
import os
import re
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .actions import ActionDenied, ActionService
from .core import Store, Supervisor
from .gateway import Gateway, GatewayError, strict_json


def operator_id():
    return "os_" + hashlib.sha256(getpass.getuser().encode()).hexdigest()[:24]


def output(value, path=None):
    text = json.dumps(value, indent=2, ensure_ascii=True)
    if path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        # Replace the report entry; never write through an existing link to input data.
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=target.parent,
                                             prefix=".shield-report-", delete=False) as report:
                temporary = Path(report.name)
                report.write(text + "\n")
            os.replace(temporary, target)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    else:
        print(text)


def read_events(path):
    file = Path(path)
    if file.stat().st_size > 1_000_000:
        raise ValueError("Input exceeds 1MB")
    text = file.read_text(encoding="utf-8")
    events = strict_json(text) if text.lstrip().startswith("[") else [strict_json(line) for line in text.splitlines() if line.strip()]
    if not isinstance(events, list) or not 1 <= len(events) <= 1000:
        raise ValueError("Expected one to 1000 event records")
    return events


def audit_output_path(directory, destination):
    if not destination:
        return
    # Reject remote/device syntax before resolving a caller-supplied reference.
    if (not directory.strip() or "\0" in directory or directory.startswith(("\\\\", "//"))
            or re.match(r"^[a-z][a-z\d+.-]*:", directory, re.I)
            and not re.match(r"^[a-z]:[\\/]", directory, re.I)):
        raise ValueError("Local release directory required")
    if Path(destination).resolve().is_relative_to(Path(directory).resolve()):
        raise ValueError("Audit output must be outside the release")


def parser():
    root = argparse.ArgumentParser(prog="python -m openshield", description="Synthetic lab runtime; no production support.")
    root.add_argument("--state", default="incident-data/runtime.sqlite3", help="Operator-owned SQLite path")
    commands = root.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Enroll the fixed synthetic lab asset")
    init.add_argument("--enable-lab-actions", action="store_true")
    ingest = commands.add_parser("ingest", help="Atomic bounded synthetic event import")
    ingest.add_argument("file")
    for name in ("tick", "serve"):
        tick = commands.add_parser(name)
        tick.add_argument("--mode", choices=("baseline", "ai"), default="ai")
        if name == "serve":
            tick.add_argument("--duration", type=float, default=60)
            tick.add_argument("--interval", type=float, default=10)
    commands.add_parser("status")
    compare = commands.add_parser("benchmark", help="Frozen held-out comparison; unconfigured AI stays unmeasured")
    compare.add_argument("--corpus", default="tests/fixtures/heldout_cases.json")
    compare.add_argument("--with-ai", action="store_true", help="Explicitly enable configured CLIProxyAPI calls")
    compare.add_argument("--output", default="output/comparison.json")
    lab = commands.add_parser("lab", help="Operator-controlled isolated experiment infrastructure")
    lab.add_argument("operation", choices=("build", "start", "verify", "approved", "stop"))
    lab.add_argument("--output", default="output/lab-results.json")
    exposure = commands.add_parser("release-audit", help="Read-only local release exposure policy; no target execution")
    exposure.add_argument("directory")
    exposure.add_argument("--authorized", action="store_true", required=True)
    exposure.add_argument("--output")
    anti_rea = commands.add_parser("anti-rea-lab", help="Owned synthetic HTTP authority and exposure experiment")
    anti_rea.add_argument("--output", default="output/anti-rea-results.json")
    delivery = commands.add_parser("delivery-audit", help="Compare reviewed files with authorized loopback static HTTP delivery")
    delivery.add_argument("directory")
    delivery.add_argument("--base-url", required=True)
    delivery.add_argument("--authorized", action="store_true", required=True)
    delivery.add_argument("--retired-path", action="append", default=[])
    delivery.add_argument("--output")
    delivery_lab = commands.add_parser("delivery-lab", help="Owned HTTP representation and retired-asset experiment")
    delivery_lab.add_argument("--output", default="output/delivery-results.json")
    correlate = commands.add_parser("correlate", help="Bounded read-only Go access-decision correlation")
    correlate.add_argument("case_id")
    correlate.add_argument("--project", default="lab")
    correlate.add_argument("--output")
    propose = commands.add_parser("propose", help="Print an exact fixed-lab ingress change for review")
    propose.add_argument("case_id")
    propose.add_argument("--mode", choices=("maintenance", "on"), default="maintenance")
    propose.add_argument("--accept-lab-interruption", action="store_true", required=True)
    approve = commands.add_parser("approve", help="Approve the reviewed exact digest as the current OS operator")
    approve.add_argument("proposal_id")
    approve.add_argument("digest")
    execute = commands.add_parser("execute", help="Dispatch one exact approval to the fixed lab")
    execute.add_argument("proposal_id")
    execute.add_argument("approval_id")
    execute.add_argument("--enable-lab-actions", action="store_true", required=True)
    reconcile = commands.add_parser("reconcile", help="Read uncertain target state without authorizing another dispatch")
    reconcile.add_argument("proposal_id")
    commands.add_parser("kill")
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    if args.command == "release-audit":
        from .exposure import exposure_audit
        audit_output_path(args.directory, args.output)
        result = exposure_audit(args.directory, authorized=args.authorized)
        output(result, args.output)
        return 0 if result["status"] == "pass" and result["complete"] else 1
    if args.command == "delivery-audit":
        from .delivery import delivery_audit
        audit_output_path(args.directory, args.output)
        result = delivery_audit(args.directory, args.base_url, authorized=args.authorized,
                                retired_paths=args.retired_path)
        output(result, args.output)
        return 0 if result["status"] == "pass" and result["complete"] else 1
    if args.command == "delivery-lab":
        from lab.delivery import verify
        result = verify()
        output(result, args.output)
        output({"status": result["status"], "cases": len(result["cases"]), "artifact": args.output})
        return 0 if result["status"] == "pass" else 1
    if args.command == "anti-rea-lab":
        from lab.anti_rea import verify
        result = verify()
        output(result, args.output)
        output({"status": result["status"], "checks": result["checks"], "artifact": args.output})
        return 0 if result["status"] == "pass" else 1
    if args.command == "benchmark":
        from .evaluation import compare
        gateway = Gateway.from_env() if args.with_ai else None
        result = compare(args.corpus, gateway)
        output(result, args.output)
        output({"artifact": args.output, "arms": {name: {"status": arm["status"], "metrics": arm["metrics"]}
                                                 for name, arm in result["arms"].items()}})
        return 0
    if args.command == "lab":
        from lab.control import Lab
        lab = Lab()
        if args.operation == "approved":
            from .lab_trial import approved_response
            result = approved_response(lab)
            output(result, args.output)
            output({"artifact": args.output, "status": result["status"]})
        elif args.operation == "verify":
            from .lab_trial import approved_response, check_report
            result = {"synthetic": True, "prevention": lab.prevention_trial(),
                      "activeResponse": lab.response_trial(), "recovery": lab.recovery_trial(),
                      "approvedRuntimeResponse": approved_response(lab),
                      "aiBenefit": {"status": "not_measured", "requires": "Configured CLIProxyAPI and identical trials"}}
            result["checks"] = check_report(result)
            output(result, args.output)
            output({"artifact": args.output, "checks": result["checks"]})
            return 0 if all(result["checks"].values()) else 1
        else:
            output(getattr(lab, args.operation)())
        return 0
    state = Path(args.state)
    if args.command == "correlate" and args.output:
        protected = {Path(str(state) + suffix).resolve() for suffix in
                     ("", "-journal", "-wal", "-shm", ".actions", ".actions-journal", ".actions-wal", ".actions-shm")}
        if Path(args.output).resolve() in protected:
            raise ValueError("Report output cannot replace runtime state")
    state.parent.mkdir(parents=True, exist_ok=True)
    store = Store(state)
    try:
        if args.command == "init":
            output(store.enroll("lab", "lab_web", operator_id(), source_ids=("lab", "observer"),
                               source_roles={"lab": "telemetry", "observer": "observer"},
                               allowed_actions=("set_site_ingress_mode",) if args.enable_lab_actions else ()))
        elif args.command == "ingest":
            output({"accepted": store.ingest_batch(read_events(args.file))})
        elif args.command in ("tick", "serve"):
            if args.command == "serve" and not (0 < args.duration <= 3600 and .1 <= args.interval <= 60):
                raise ValueError("Service duration/interval outside lab bounds")
            supervisor = Supervisor(store, gateway=Gateway.from_env() if args.mode == "ai" else None, mode=args.mode)
            deadline = time.monotonic() + (args.duration if args.command == "serve" else 0)
            while True:
                output({"results": supervisor.tick(), "health": store.health()})
                remaining = deadline - time.monotonic()
                if args.command != "serve" or remaining <= 0:
                    break
                time.sleep(min(args.interval, remaining))
        elif args.command == "status":
            output({"cases": store.cases(), "health": store.health(), "profile": "synthetic_local_only"})
        elif args.command == "correlate":
            from .correlation import correlate
            output(correlate(store, args.project, args.case_id), args.output)
        else:
            actions = ActionService(str(state) + ".actions", store, operator=operator_id(),
                                    allow_lab_mutations=args.command in ("propose", "approve", "execute"))
            try:
                if args.command == "propose":
                    from lab.control import Lab
                    current = datetime.now(timezone.utc)
                    output(actions.propose("lab", args.case_id, "lab_web", Lab().config()["etag"],
                                           review_due_at=(current + timedelta(minutes=10)).isoformat(),
                                           expires_at=(current + timedelta(minutes=5)).isoformat(),
                                           mode=args.mode, accepted_low_impact=True))
                elif args.command == "approve":
                    output(actions.approve(args.proposal_id, args.digest, operator=operator_id()))
                elif args.command == "execute":
                    from lab.control import Lab
                    output(actions.execute(args.proposal_id, args.approval_id, Lab()))
                elif args.command == "reconcile":
                    from lab.control import Lab
                    output(actions.reconcile(args.proposal_id, Lab()))
                elif args.command == "kill":
                    actions.kill()
                    output({"status": "dispatch_disabled", "inFlight": "requires_reconciliation"})
            finally:
                actions.close()
    finally:
        store.close()
    return 0


def entrypoint():
    from .correlation import CorrelationError
    try:
        return main()
    except (ActionDenied, GatewayError, CorrelationError) as error:
        output({"status": "failed", "code": str(error)})
        return 1
    except (ValueError, OSError, RuntimeError) as error:
        # Error strings from a tool/file can contain secrets; do not echo them.
        output({"status": "failed", "code": type(error).__name__, "detail": "Invalid input/configuration or unavailable lab tool; inspect the documented prerequisites."})
        return 1
    except KeyboardInterrupt:
        return 130
