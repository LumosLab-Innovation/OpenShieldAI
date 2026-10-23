"""Actual runtime-to-Caddy exercise with a visibly scripted lab approver."""

import uuid
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .actions import ActionService
from .core import Store, Supervisor, utc_now


def check_report(report):
    """Grade actual observations; command success alone is never the oracle."""
    prevention = report["prevention"]
    rows = prevention["rows"]
    prevention_ok = bool(rows) and all(
        row["status"] == (403 if row["mode"] == "on" and row["synthetic_harm"] else 200)
        and row["reached_delta"] == (0 if row["mode"] == "on" and row["synthetic_harm"] else 1)
        and row["harm_delta"] == int(row["synthetic_harm"] and row["mode"] != "on") for row in rows)
    response, recovery = report["activeResponse"], report["recovery"]
    checks = {
        "planted_prevention_and_legitimate_requests": prevention_ok,
        "tested_source_log_minimization": prevention["source_log_marker_absent"],
        "tested_origin_and_observer_boundary": prevention["origin_has_no_published_port"] and prevention["observer_route_public_status"] == 404,
        "conditional_new_ingress_stop": response["applied"]["status"] == 200 and response["stale_update_status"] == 412
              and not response["during"]["new_requests_reach_app"] and response["during"]["management_ok"]
              and response["during"]["legitimate_status"] == 503 and response["post_response_harm_delta"] == 0,
        "existing_work_limit_measured": response["in_flight_finished"] and response["background_continued"],
        "restart_and_reopening_measured": not response["after_proxy_restart"]["new_requests_reach_app"]
              and response["reopened"]["new_requests_reach_app"],
        "actual_loss_then_usable_isolated_restore": recovery["data_loss_independently_observed"]
              and recovery["broken_app_transaction_status"] == 409 and recovery["clean"]["status"] == "verified"
              and recovery["restore_uses_empty_isolated_target"],
        "recovery_negative_controls": all(recovery[name]["status"] == "failed" for name in
              ("missing_key", "wrong_key", "corrupt", "contaminated", "application_inconsistent")),
        "runtime_approval_bridge": report["approvedRuntimeResponse"]["status"] == "verified_for_new_ingress_only",
    }
    return checks


def approved_response(lab):
    lab.set_mode("on")  # Privileged experiment setup, outside the response broker.
    baseline = lab.probe()
    if not baseline["new_requests_reach_app"] or not baseline["management_ok"]:
        raise RuntimeError("Lab baseline unavailable")
    rows, stimulus_errors, stop = [], [], threading.Event()

    def ongoing_fixture():
        while not stop.is_set():
            try:
                rows.append(lab.request("/fixture-operation?input=ordinary"))
            except Exception:
                stimulus_errors.append("STIMULUS_FAILED")
                return
            stop.wait(.1)

    directory = Path(__file__).resolve().parents[1] / "artifacts" / "runtime-trials" / uuid.uuid4().hex
    directory.mkdir(parents=True)
    store = Store(Path(directory) / "cases.db")
    store.enroll("lab", "lab_web", "lab_controller", source_ids=("lab", "observer"),
                 source_roles={"lab": "telemetry", "observer": "observer"},
                 allowed_actions=("set_site_ingress_mode",))
    actions = ActionService(Path(directory) / "actions.db", store, operator="lab_controller", allow_lab_mutations=True)

    def event(eid, kind, facts, source="lab"):
        return {"schemaVersion": "lab_event_v1", "id": eid, "projectId": "lab", "caseId": "active_case",
                "assetId": "lab_web", "sourceId": source, "observedAt": utc_now(),
                "kind": kind, "facts": facts, "dataClass": "synthetic"}

    def exact_approval(mode):
        moment = datetime.now(timezone.utc)
        proposal = actions.propose("lab", "active_case", "lab_web", lab.config()["etag"],
                                   review_due_at=(moment + timedelta(minutes=10)).isoformat(),
                                   expires_at=(moment + timedelta(minutes=5)).isoformat(), mode=mode,
                                   accepted_low_impact=True)
        approval = actions.approve(proposal["id"], proposal["digest"], operator="lab_controller")
        return proposal, approval

    thread = threading.Thread(target=ongoing_fixture, daemon=True)
    try:
        before = lab.state()["counts"]
        start = time.perf_counter()
        lab.request("/fixture-operation?input=ordinary")
        thread.start()
        observed = lab.state()["counts"]
        collected = time.perf_counter()
        harm = observed["harm"] - before["harm"]
        if harm < 1:
            raise RuntimeError("Planted unprotected effect was not observed")
        store.ingest(event("observed_effect", "app_operation", {"authorized": False, "count": harm}, "observer"))
        supervisor = Supervisor(store, mode="baseline")
        decision = supervisor.tick()[0]
        if decision["nextAction"] != "set_site_ingress_mode":
            raise RuntimeError("No evidence-backed maintenance proposal")
        planned = time.perf_counter()
        # Scripted wait is recorded, never reported as a human trial.
        time.sleep(.25)
        proposal, approval = exact_approval("maintenance")
        approved = time.perf_counter()
        receipt = actions.execute(proposal["id"], approval["id"], lab)
        applied = time.perf_counter()
        independent = lab.probe()
        verified = time.perf_counter()
        achieved = (receipt["status"] == "succeeded" and not independent["new_requests_reach_app"]
                    and independent["management_ok"] and independent["legitimate_status"] == 503)
        if not achieved:
            raise RuntimeError("Runtime action did not achieve independently observed new-ingress stop")
        store.ingest(event("observed_stop", "verification", {"objective": "new_ingress_stopped",
                           "result": "verified", "independent": True}, "observer"))
        stop.set()
        thread.join(timeout=10)
        if thread.is_alive() or stimulus_errors:
            raise RuntimeError("Concurrent stimulus did not complete")
        after = lab.state()["counts"]
        reopening, reopening_approval = exact_approval("on")
        compensation = actions.execute(reopening["id"], reopening_approval["id"], lab)
        restored = lab.probe()
        if compensation["status"] != "succeeded" or not restored["new_requests_reach_app"] or restored["legitimate_status"] != 200:
            raise RuntimeError("Separately approved compensation failed")
        actions.verify_audit()
        return {"status": "verified_for_new_ingress_only", "decision": decision,
                "auditStateRef": str(directory.relative_to(Path(__file__).resolve().parents[1])).replace("\\", "/"),
                "receipt": receipt, "independentPostcheck": independent,
                "compensationReceipt": compensation, "compensationPostcheck": restored,
                "approval": "scripted lab_controller exact-digest fixture; not a human trial",
                "timingSeconds": {"sourceStimulusToCollection": collected-start,
                                  "collectionToPlan": planned-collected, "planToScriptedApproval": approved-planned,
                                  "approvalToReceipt": applied-approved, "receiptToVerification": verified-applied,
                                  "sourceStimulusToVerifiedEffect": verified-start, "scriptedWait": .25,
                                  "actualHumanWait": None},
                "additionalPlantedHarmDuringResponse": after["harm"]-observed["harm"],
                "continuedFixtureRequests": len(rows),
                "limitations": ["Controlled planted operation; not a real exploit or malware test.",
                                "No AI endpoint used; no machine/human triage advantage measured.",
                                "Existing host processes, sessions, egress and disclosure remain outside this objective."]}
    finally:
        stop.set()
        if thread.is_alive():
            thread.join(timeout=10)
        actions.close()
        store.close()
