"""Aggregate evidence for the owned persistent-authority HTTP experiment."""

import tempfile
from pathlib import Path

from lab.anti_rea import AntiReaLab


def verify():
    """Exercise persistent authority through real loopback HTTP, without exporting tokens."""
    checks, totals = {}, []
    now = [100.0]
    operation = {"object": "quote-a", "quantity": 1}

    def grant(lab, session, payload):
        status, body = lab.request("POST", "/api/grants", payload, session)
        return status, body.get("capability", "")

    with tempfile.TemporaryDirectory(prefix="openshield-durable-trial-") as directory:
        state = Path(directory) / "authority.sqlite3"
        with AntiReaLab(state_path=state, clock=lambda: now[0]) as first:
            alice, bob = first.issue_session(), first.issue_session("bob")
            status, consumed = grant(first, alice, operation)
            accepted, answer = first.request("POST", "/api/quote", operation, alice, consumed)
            checks["initial_authorized_operation_accepted"] = status == 201 and accepted == 200
            totals.append(answer.get("totalCents"))
            second_payload = {**operation, "quantity": 2}
            _, second_cap = grant(first, alice, second_payload)
            status, answer = first.request("POST", "/api/quote", second_payload, alice, second_cap)
            checks["second_authorized_operation_accepted"] = status == 200
            totals.append(answer.get("totalCents"))
            third_payload = {**operation, "quantity": 3}
            _, pending = grant(first, alice, third_payload)
            bob_payload = {"object": "quote-b", "quantity": 1}
            _, revoked_cap = grant(first, bob, bob_payload)
            revoked = first.revoke_session(bob)

        with AntiReaLab(state_path=state, clock=lambda: now[0]) as second:
            checks["consumed_capability_rejected_after_restart"] = second.request("POST", "/api/quote", operation, alice, consumed)[0] == 403
            status, answer = second.request("POST", "/api/quote", third_payload, alice, pending)
            checks["unspent_capability_survives_restart"] = status == 200
            totals.append(answer.get("totalCents"))
            checks["revoked_session_and_capability_stay_revoked_after_restart"] = revoked and second.request("POST", "/api/quote", bob_payload, bob, revoked_cap)[0] == 403
            checks["authorized_outputs_still_allow_linear_inference"] = (
                all(type(value) is int for value in totals)
                and totals[1] + (totals[1] - totals[0]) == totals[2])
            fresh_alice = second.issue_session()
            _, fourth_cap = grant(second, fresh_alice, operation)

        with AntiReaLab(state_path=state, clock=lambda: now[0]) as third:
            checks["last_principal_budget_slot_survives_two_restarts"] = third.request("POST", "/api/quote", operation, fresh_alice, fourth_cap)[0] == 200
            checks["fresh_session_cannot_reset_exhausted_principal_budget"] = grant(third, third.issue_session(), operation)[0] == 429
            fresh_bob = third.issue_session("bob")
            now[0] = 101.0
            _, rollback_cap = grant(third, fresh_bob, bob_payload)
            now[0] = 100.0
            checks["clock_rollback_fails_closed"] = third.request("POST", "/api/quote", bob_payload, fresh_bob, rollback_cap) == (503, {"error": "authority_unavailable"})
            now[0] = 101.0
            checks["rollback_denial_does_not_consume_capability_or_budget"] = third.request("POST", "/api/quote", bob_payload, fresh_bob, rollback_cap)[0] == 200
            _, expiry_cap = grant(third, fresh_bob, bob_payload)
            now[0] = 131.0
            checks["capability_rejected_at_exact_expiry"] = third.request("POST", "/api/quote", bob_payload, fresh_bob, expiry_cap)[0] == 403
            audit = third.audit

    return {"schemaVersion": "durable_authority_lab_v1", "synthetic": True,
            "transport": "real_loopback_http", "status": "pass" if all(checks.values()) else "failed",
            "checks": checks, "serverInstances": 3, "authorityAudit": audit,
            "modelCalls": 0, "productionActions": False,
            "limits": ["Owned synthetic identities and local SQLite only",
                       "No accepted production authentication, transport or storage-protection claim",
                       "Administrator deletion or rollback of a valid state snapshot can reset authority",
                       "Authorized query outputs can still reveal a simple hidden algorithm",
                       "Atomic spend does not establish exactly-once external effects"]}
