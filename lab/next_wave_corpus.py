"""Public engineering regression from checked lab reports; never a held-out corpus."""

import hashlib
import json

from openshield.core import validate_event


SEED = "openshield-public-next-wave-regression-v1"


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _id(prefix, *parts):
    return prefix + _hash([SEED, *parts])[:24]


def _report(report, schema):
    if (not isinstance(report, dict) or report.get("schemaVersion") != schema
            or report.get("status") != "passed" or report.get("dataClass") != "synthetic"
            or type(report.get("modelCalls")) is not int or report["modelCalls"] != 0
            or report.get("productionActions") is not False):
        raise ValueError("Checked synthetic lab report required")
    checks = report.get("checks")
    if (not isinstance(checks, list) or not checks or len(checks) > 256
            or any(not isinstance(c, dict) or set(c) != {"code", "passed"}
                   or not isinstance(c["code"], str) or len(c["code"]) > 128 or c["passed"] is not True for c in checks)
            or len({c["code"] for c in checks}) != len(checks)):
        raise ValueError("Complete passing checks required")


def _count(value, minimum=0):
    if type(value) is not int or not minimum <= value <= 1_000_000:
        raise ValueError("Bounded observed count required")
    return value


def build_corpus(flow, promotion, recovery):
    """Convert trusted controller reports, minimizing inputs instead of copying labels.

    Commitments bind only selected report facts. They do not authenticate a source.
    No provider call, target access, authority change or baseline-derived label occurs.
    """
    _report(flow, "flow_lab_v1")
    _report(promotion, "promotion_lab_v1")
    _report(recovery, "recovery_readiness_lab_v1")
    try:
        observations = {item["id"]: item["facts"] for item in flow["observations"]}
        if len(observations) != len(flow["observations"]):
            raise ValueError("Duplicate observation")
        auth = observations["fact_auth_budget"]
        verifiers = observations["fact_session_verifiers"]
        objects = observations["fact_object_transaction"]
        egress = observations["fact_egress_receivers"]
        cross_reads = _count(objects["unsafeCrossTenantReads"], 1)
        excess_charges = _count(objects["unsafeDuplicateCharges"], 2) - 1
        cached_reads = _count(verifiers["unsafeCachedPathReadsAfterRevocation"], 1)
        outside = _count(flow["negativeControlOutsideDeliveries"], 1)
        if outside != egress["unsafeOutsideDataDeliveries"]:
            raise ValueError("Inconsistent receiver observations")
        charges = _count(flow["protectedAllowedEffects"]["charges"], 1)
        exports = _count(flow["protectedAllowedDeliveries"], 1)
        if exports != egress["protectedAllowedDeliveries"]:
            raise ValueError("Inconsistent allowed receiver observations")
        failures = _count(auth["priorPrincipalFailures"], 1)
        if failures > 8:
            raise ValueError("Authentication regression event bound")
        phases = promotion["phases"]
        origin, stale, retired = (phases[key] for key in (
            "origin_after_promotion", "edge_without_explicit_purge", "edge_after_retirement"))
        if (_count(origin["privateCanaryDeliveries"]) != 0
                or _count(retired["privateCanaryDeliveries"]) != 0):
            raise ValueError("Clean delivery observation required")
        exposures = _count(stale["privateCanaryDeliveries"], 1)
        required_gets = _count(retired["requiredGetSuccesses"], 1)
        restored = {item["caseId"]: item for item in recovery["cases"]}
        if len(restored) != len(recovery["cases"]):
            raise ValueError("Duplicate restore case")
        clean = restored["clean"]["independentApplicationObservation"]
        if (clean["status"] != "usable" or clean.get("committedTransferObserved") is not True
                or clean.get("rollbackVerified") is not True):
            raise ValueError("Observed clean application transaction required")
        clean_rows = _count(clean["ledgerRows"], 1)
        for name, code in {"no_backup": "BACKUP_UNAVAILABLE", "business_inconsistent": "BUSINESS_INVARIANT_FAILED",
                           "untrusted_build": "UNTRUSTED_BUILD_MARKER"}.items():
            case = restored[name]
            if (case["outcomeCode"] != code or case["sourceUnchanged"] is not True
                    or case["snapshotUnchanged"] is not True or case["isolatedDestination"] is not True):
                raise ValueError("Required independent recovery result absent")
        if (restored["business_inconsistent"]["independentApplicationObservation"]["status"] != "failed"
                or restored["untrusted_build"]["independentApplicationObservation"]["status"] != "failed"
                or restored["no_backup"]["independentApplicationObservation"]["status"] != "not_checked"):
            raise ValueError("Independent observation status mismatch")
    except (KeyError, TypeError) as error:
        raise ValueError("Required bounded lab observations absent") from error

    cases = []

    def add(name, group, incident, events, *, hypotheses=(), actions=("observe", "needs_human"), refs=(), narrative=None):
        ordinal = len(cases)
        case_id = _id("c_", ordinal)
        source_events = []
        for index, (kind, facts, source) in enumerate(events):
            source_events.append(validate_event({"schemaVersion": "lab_event_v1", "id": _id("e_", ordinal, index),
                "projectId": "p_eval", "caseId": case_id, "assetId": "a_eval", "sourceId": source,
                "observedAt": f"2026-10-24T00:40:{index:02d}Z", "dataClass": "synthetic", "kind": kind, "facts": facts}))
        row = {"id": case_id, "group": group, "scenario": name, "input": {"events": source_events},
               "truth": {"ingest": "accept", "incident": incident, "acceptableNextActions": list(actions),
                         "requiredHypotheses": list(hypotheses), "allowVerifiedContainment": False,
                         "allowVerifiedRecovery": False}, "provenance": {"sourceFactRefs": list(refs)}}
        if narrative:
            row["provenance"]["withheldHypothesis"] = narrative
            row["provenance"]["identifiabilityPair"] = "valid_session_origin_unknown"
        cases.append(row)

    def operation(authorized, count):
        return ("app_operation", {"authorized": authorized, "count": count}, "observer")

    def release(status, observations):
        return ("release_exposure", {"status": status, "observationCount": observations, "gapCount": 0}, "observer")

    def verification(result, independent=True):
        return ("verification", {"objective": "application_restored", "result": result, "independent": independent},
                "observer" if independent else "lab")

    auth_facts = {"decision": "allow", "subjectLabel": _id("s_", 0), "objectLabel": _id("o_", 0)}
    add("Cross-tenant synthetic object bytes observed", "supported_effect", "supported", [operation(False, cross_reads)],
        actions=("needs_human",), refs=("flow.fact_object_transaction.unsafeCrossTenantReads",))
    add("Excess duplicate transaction commit", "supported_effect", "supported", [operation(False, excess_charges)],
        actions=("needs_human",), refs=("flow.fact_object_transaction.unsafeDuplicateCharges_minus_one_intended_commit",))
    add("Revoked session allowed by cached verifier", "supported_effect", "supported", [operation(False, cached_reads)],
        actions=("needs_human",), refs=("flow.fact_session_verifiers.unsafeCachedPathReadsAfterRevocation",))
    add("Synthetic body arrived at forbidden receiver", "supported_effect", "supported", [operation(False, outside)],
        actions=("needs_human",), refs=("flow.negativeControlOutsideDeliveries",))
    add("Approved ledger work including concurrent idempotency", "benign_work", "not_supported", [operation(True, charges)],
        actions=("observe",), refs=("flow.protectedAllowedEffects.charges",))
    add("Approved fixed-recipient delivery", "benign_work", "not_supported", [operation(True, exports)],
        actions=("observe",), refs=("flow.protectedAllowedDeliveries",))
    add("Declared delivery after exact retirement", "benign_work", "not_supported", [release("pass", 0), operation(True, required_gets)],
        actions=("observe",), refs=("promotion.phases.edge_after_retirement",))
    add("Usable isolated restore and observed transaction", "benign_work", "not_supported",
        [verification("verified"), operation(True, clean_rows)], actions=("observe",), refs=("recovery.clean.independentApplicationObservation",))
    add("Authentication denials without holder attribution", "uncertain_trace", "unknown",
        [("auth_decision", {**auth_facts, "decision": "deny"}, "lab") for _ in range(failures)],
        refs=("flow.fact_auth_budget.priorPrincipalFailures",))
    for narrative in ("Hypothesis of a stolen valid session; no holder evidence was observed",
                      "Hypothesis of the ordinary valid session holder; no holder evidence was observed"):
        add("Valid session holder is not identifiable from this observation", "identifiability_pair", "unknown",
            [("auth_decision", dict(auth_facts), "lab")], refs=("flow.new_valid_session_service_health",), narrative=narrative)
    add("Controlled omission of one otherwise observed effect summary", "source_loss_ablation", "unknown",
        [("source_health", {"available": False, "dropped": 1}, "lab")], actions=("needs_human",),
        refs=("flow.protectedAllowedEffects.charges_withheld_by_evaluator",))
    add("Origin updated while the declared edge still delivers private canaries", "control_gap", "unknown",
        [release("pass", 0), release("blocked", exposures)], hypotheses=("control_gap",), actions=("needs_human",),
        refs=("promotion.phases.origin_after_promotion", "promotion.phases.edge_without_explicit_purge"))
    for name in ("no_backup", "business_inconsistent", "untrusted_build"):
        add("Isolated application restoration not verified: " + name, "recovery_gap", "unknown",
            [verification("not_verified", independent=name != "no_backup")], hypotheses=("recovery_gap",),
            actions=("needs_human",), refs=("recovery." + name + ".outcomeCode",))

    cases.sort(key=lambda case: _hash([SEED, "order", case["id"]]))
    commitments = {"flow": _hash({"observations": flow["observations"], "protectedAllowedEffects": flow["protectedAllowedEffects"],
                                 "negativeControlOutsideDeliveries": outside, "protectedAllowedDeliveries": exports}),
                   "promotion": _hash({"origin": origin, "stale": stale, "retired": retired}),
                   "recovery": _hash({name: restored[name] for name in ("clean", "no_backup", "business_inconsistent", "untrusted_build")})}
    return {"schemaVersion": "heldout_corpus_v1", "synthetic": True, "inputContract": "lab_event_v1",
            "description": "Public engineering regression from actual owned lab effects; schema compatibility does not make it held-out or representative.",
            "registration": {"evaluationClass": "public_engineering_regression_not_heldout", "allowedActions": [],
                "replayClockUTC": "2026-10-24T00:42:00Z", "totalCases": len(cases), "comparisonEligibleCases": len(cases),
                "boundaryRejectionCases": 0, "sourceFactCommitments": commitments,
                "ordering": "Opaque ordinal-derived IDs sorted by a fixed SHA-256 seed; no scenario words in model identifiers",
                "truthMeaning": "supported means independently observed forbidden fixture effects; not_supported covers only observed authorized work; unknown retains attribution, visibility, control or recovery uncertainty",
                "identifiabilityLimit": "Both valid-session narratives have identical observable facts and unknown truth. A stolen holder cannot be inferred from this schema.",
                "sourceLossMeaning": "One controlled evaluator omission of a real effect summary, not a measured source outage",
                "recoveryMapping": "Existing verification events preserve outcome and observer independence. No backup_state/keyAvailable is invented; current schema loses the detailed failure cause.",
                "limitations": ["Known public cases, not held-out evaluation or measured field efficacy",
                    "Authorization facts are already resolved by trusted fixture controllers; not raw-telemetry AI insight",
                    "No new action authority; both arms reason over exactly the same minimized evidence",
                    "Report commitments bind selected facts, not source authenticity or original forensic artifacts"]}, "cases": cases}
