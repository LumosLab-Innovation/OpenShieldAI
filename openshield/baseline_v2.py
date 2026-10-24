"""Post-hoc rules/lookup comparator; not the runtime's frozen v1 baseline."""

from .core import baseline, validate_analysis


def baseline_v2(case):
    """Reason only over an accepted snapshot; never consume evaluator labels.

    Failed/inconclusive restore observations mean readiness needs review, not
    proven compromise. Visibility failures need human review without inventing
    an attribution. No new reads, mutation capabilities or benign rules exist.
    """
    result = baseline(case)
    unresolved = [event["id"] for event in case["timeline"]
                  if event["kind"] == "verification"
                  and event["facts"]["objective"] == "application_restored"
                  and event["facts"]["result"] != "verified"]
    if unresolved:
        recovery = next((item for item in result["hypotheses"] if item["code"] == "recovery_gap"), None)
        if recovery:
            recovery["evidenceIds"] = sorted(set(recovery["evidenceIds"] + unresolved))
        else:
            result["hypotheses"].append({"code": "recovery_gap", "evidenceIds": unresolved})
    if case["gaps"] or any(item["code"] == "recovery_gap" for item in result["hypotheses"]):
        result["nextAction"] = "needs_human"
    return validate_analysis({"schemaVersion": "analysis_v1", **result}, case)
