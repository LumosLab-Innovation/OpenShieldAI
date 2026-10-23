"""Independent boundary tests. FakeLab never counts as deployed control evidence."""

import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from openshield.actions import ActionDenied, ActionService
from openshield.core import Store, Supervisor, baseline, utc_now, validate_analysis, validate_event


def deadline(seconds):
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def event(event_id="e1", kind="app_operation", facts=None, **changes):
    return {"schemaVersion": "lab_event_v1", "id": event_id, "projectId": "lab",
            "caseId": "case1", "assetId": "lab_web", "sourceId": "lab", "observedAt": utc_now(),
            "kind": kind, "facts": facts if facts is not None else {"authorized": False, "count": 1},
            "dataClass": "synthetic", **changes}


class FakeLab:
    """UNIT TEST DOUBLE: only records attempted calls; it controls no service."""

    lab_id, project_id, asset_id = "openshield-lab", "lab", "lab_web"

    def __init__(self, response=200, lost_reply=False):
        self.calls, self.response, self.lost_reply = [], response, lost_reply

    def set_mode(self, mode, *, expected_etag):
        self.calls.append((mode, expected_etag))
        if self.lost_reply:
            raise TimeoutError("synthetic transport failure")
        return {"status": self.response}

    def config(self):
        return {"etag": '"r2"'}


class AdversarialReview(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.store = Store(self.root / "cases.db")
        self.store.enroll("lab", "lab_web", "reviewer", allowed_actions=("set_site_ingress_mode",),
                          source_ids=("lab", "observer"),
                          source_roles={"lab": "telemetry", "observer": "observer"})
        self.store.ingest(event())
        self.actions = ActionService(self.root / "actions.db", self.store,
                                     operator="reviewer", allow_lab_mutations=True)

    def tearDown(self):
        self.actions.close()
        self.store.close()
        self.directory.cleanup()

    def proposal(self, **changes):
        options = {"review_due_at": deadline(600), "expires_at": deadline(120),
                   "accepted_low_impact": True, **changes}
        return self.actions.propose("lab", "case1", "lab_web", '"r1"', **options)

    def approved(self):
        proposal = self.proposal()
        approval = self.actions.approve(proposal["id"], proposal["digest"], operator="reviewer")
        return proposal, approval

    def test_modified_digest_and_wrong_operator_cannot_approve(self):
        proposal = self.proposal()
        with self.assertRaises(ActionDenied):
            self.actions.approve(proposal["id"], "0" * 64, operator="reviewer")
        with self.assertRaises(ActionDenied):
            self.actions.approve(proposal["id"], proposal["digest"], operator="model")

    def test_expired_approval_cannot_dispatch(self):
        proposal, approval = self.approved()
        lab = FakeLab()
        with patch("openshield.actions.now", return_value=datetime.now(timezone.utc).timestamp() + 180):
            with self.assertRaises(ActionDenied):
                self.actions.execute(proposal["id"], approval["id"], lab)
        self.assertEqual(lab.calls, [])

    def test_consumed_approval_cannot_replay_and_receipt_is_not_verification(self):
        proposal, approval = self.approved()
        lab = FakeLab()
        receipt = self.actions.execute(proposal["id"], approval["id"], lab)
        self.assertEqual(receipt["status"], "succeeded")
        self.assertEqual(receipt["verification"], "pending_independent_observer")
        with self.assertRaises(ActionDenied):
            self.actions.execute(proposal["id"], approval["id"], lab)
        self.assertEqual(len(lab.calls), 1)

    def test_new_evidence_invalidates_exact_approval(self):
        proposal, approval = self.approved()
        self.store.ingest(event("e2"))
        lab = FakeLab()
        with self.assertRaises(ActionDenied):
            self.actions.execute(proposal["id"], approval["id"], lab)
        self.assertEqual(lab.calls, [])

    def test_stale_or_gapped_evidence_cannot_authorize_new_mutation(self):
        for suffix, item in (("stale", event("e2", observedAt=deadline(-600))),
                             ("clock", event("e3", observedAt=deadline(60))),
                             ("gap", event("e4", kind="source_health", facts={"available": False, "dropped": 7}))):
            with self.subTest(condition=suffix):
                item["caseId"] = suffix
                self.store.ingest(item)
                with self.assertRaises(ActionDenied):
                    self.actions.propose("lab", suffix, "lab_web", '"r1"', review_due_at=deadline(600),
                                         expires_at=deadline(120), accepted_low_impact=True)

    def test_other_enrolled_asset_cannot_reach_fixed_lab_actuator(self):
        self.store.enroll("lab", "other", "reviewer", allowed_actions=("set_site_ingress_mode",))
        self.store.ingest(event("e2", caseId="case2", assetId="other"))
        with self.assertRaises(ActionDenied):
            self.actions.propose("lab", "case2", "other", '"r1"', review_due_at=deadline(600),
                                 expires_at=deadline(120), accepted_low_impact=True)

    def test_adapter_identity_cannot_change_after_approval(self):
        proposal, approval = self.approved()
        lab = FakeLab()
        lab.asset_id = "other"
        with self.assertRaises(ActionDenied):
            self.actions.execute(proposal["id"], approval["id"], lab)
        self.assertEqual(lab.calls, [])

    def test_high_impact_and_disabled_execution_have_no_grant(self):
        with self.assertRaises(ActionDenied):
            self.proposal(accepted_low_impact=False)
        self.actions.enabled = False
        with self.assertRaises(ActionDenied):
            self.proposal()

    def test_target_conflict_never_retries_or_claims_success(self):
        proposal, approval = self.approved()
        lab = FakeLab(response=412)
        receipt = self.actions.execute(proposal["id"], approval["id"], lab)
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["errorCode"], "TARGET_STATE_CHANGED")
        with self.assertRaises(ActionDenied):
            self.actions.execute(proposal["id"], approval["id"], lab)
        self.assertEqual(len(lab.calls), 1)

    def test_lost_reply_requires_reconciliation_not_blind_retry(self):
        proposal, approval = self.approved()
        lab = FakeLab(lost_reply=True)
        receipt = self.actions.execute(proposal["id"], approval["id"], lab)
        self.assertEqual(receipt["status"], "unknown_outcome")
        reconciled = self.actions.reconcile(proposal["id"], lab)
        self.assertFalse(reconciled["retryAuthorized"])
        self.assertEqual(reconciled["verification"], "pending_independent_observer")
        with self.assertRaises(ActionDenied):
            self.actions.execute(proposal["id"], approval["id"], lab)
        self.assertEqual(len(lab.calls), 1)

    def test_kill_revokes_pending_dispatch(self):
        proposal, approval = self.approved()
        self.actions.kill()
        lab = FakeLab()
        with self.assertRaises(ActionDenied):
            self.actions.execute(proposal["id"], approval["id"], lab)
        self.assertEqual(lab.calls, [])

    def test_tampered_audit_blocks_dispatch(self):
        proposal, approval = self.approved()
        self.actions.db.execute("UPDATE action_audit SET digest='tampered' WHERE seq=1")
        self.actions.db.commit()
        lab = FakeLab()
        with self.assertRaises(ActionDenied):
            self.actions.execute(proposal["id"], approval["id"], lab)
        self.assertEqual(lab.calls, [])

    def test_unknown_fields_and_typed_boolean_tricks_are_rejected(self):
        for bad in (event(approval={"allow": True}), event(facts={"authorized": "false", "count": 1}),
                    event(facts={"authorized": False, "count": True}),
                    event(facts={"authorized": False, "count": -1}),
                    event(kind="shell_command", facts={"command": "disabled-by-schema"})):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                validate_event(bad)

    def test_credential_shaped_labels_never_enter_model_context(self):
        canary = "sk-proj-SYNTHETIC_REVIEW_CANARY"
        with self.assertRaises(ValueError):
            validate_event(event(kind="auth_decision", facts={"decision": "allow",
                           "subjectLabel": canary, "objectLabel": "object1"}))

    def test_telemetry_role_cannot_self_assert_independent_verification(self):
        with self.assertRaises(ValueError):
            self.store.ingest(event("e2", kind="verification", facts={"objective": "new_ingress_stopped",
                                    "result": "verified", "independent": True}))

    def test_cross_project_source_asset_and_case_swaps_are_denied(self):
        for changes in ({"projectId": "other"}, {"assetId": "other"}, {"sourceId": "other"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.store.ingest(event("e2", **changes))
        self.store.enroll("lab", "other", "reviewer")
        with self.assertRaises(ValueError):
            self.store.ingest(event("e3", assetId="other"))

    def test_duplicate_is_idempotent_but_conflicting_duplicate_is_rejected(self):
        original = self.store.case("lab", "case1")["timeline"][0]
        original = {key: value for key, value in original.items() if key not in {"ingestedAt", "sourceTrust", "sourceRole"}}
        self.assertFalse(self.store.ingest(original))
        changed = copy.deepcopy(original)
        changed["facts"]["count"] = 2
        with self.assertRaises(ValueError):
            self.store.ingest(changed)
        self.assertEqual(self.store.case("lab", "case1")["version"], 1)

    def test_invalid_batch_cannot_leave_partial_evidence(self):
        with self.assertRaises(ValueError):
            self.store.ingest_batch([event("e2"), event("e3", sourceId="unenrolled")])
        self.assertEqual(self.store.case("lab", "case1")["version"], 1)

    def test_expired_enrollment_rejects_input_and_missing_capability_rejects_action(self):
        self.store.enroll("lab", "expired", "reviewer", expires_at=deadline(-60))
        with self.assertRaises(ValueError):
            self.store.ingest(event("e2", caseId="case2", assetId="expired"))
        self.store.enroll("other", "lab_web", "reviewer")
        self.store.ingest(event("e3", projectId="other", caseId="case3"))
        case = self.store.case("other", "case3")
        analysis = {"schemaVersion": "analysis_v1", **baseline(case), "nextAction": "set_site_ingress_mode"}
        with self.assertRaises(ValueError):
            validate_analysis(analysis, case)

    def test_unknown_model_evidence_and_actions_are_rejected(self):
        case = self.store.case("lab", "case1")
        analysis = {"schemaVersion": "analysis_v1", **baseline(case)}
        for change in ({"evidenceIds": ["cross_case"]}, {"nextAction": "run_shell"},
                       {"readRequests": [{"catalogId": "arbitrary_query", "limit": 1}]},
                       {"approval": True}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_analysis({**analysis, **change}, case)

    def test_unconfigured_provider_is_not_fake_ai_or_cleared_by_idle_tick(self):
        supervisor = Supervisor(self.store, mode="ai")
        result = supervisor.tick()[0]
        self.assertEqual(result["aiStatus"], "degraded_unconfigured")
        self.assertEqual(result["calls"], 0)
        self.assertIn("model_unavailable", result["limitations"])
        self.assertEqual(supervisor.tick(), [])
        self.assertEqual(self.store.health()["supervisor"]["state"], "degraded_model")

    def test_restart_keeps_unchanged_evidence_deduplicated(self):
        Supervisor(self.store, mode="baseline").tick()
        self.actions.close()
        self.store.close()
        self.store = Store(self.root / "cases.db")
        self.actions = ActionService(self.root / "actions.db", self.store,
                                     operator="reviewer", allow_lab_mutations=True)
        self.assertEqual(Supervisor(self.store, mode="baseline").tick(), [])


class HeldoutManifestReview(unittest.TestCase):
    def test_registered_corpus_preserves_input_truth_separation_and_ingest_expectations(self):
        manifest = json.loads((Path(__file__).parent / "fixtures" / "heldout_cases.json").read_text())
        self.assertEqual(len(manifest["cases"]), 48)
        self.assertEqual(len({case["id"] for case in manifest["cases"]}), 48)
        replay_clock = datetime.fromisoformat(manifest["registration"]["replayClockUTC"].replace("Z", "+00:00"))
        for case in manifest["cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(set(case["input"]), {"events"})
                self.assertTrue(all("truth" not in event and "group" not in event for event in case["input"]["events"]))
                store = Store(":memory:", clock=lambda: replay_clock)
                self.addCleanup(store.close)
                store.enroll("p_eval", "a_eval", "evaluator", source_ids=("lab", "observer"),
                             source_roles={"lab": "telemetry", "observer": "observer"})
                if case["truth"]["ingest"] == "reject":
                    with self.assertRaises(ValueError):
                        for item in case["input"]["events"]:
                            store.ingest(item)
                    self.assertEqual(store.db.execute("SELECT COUNT(*) FROM shield_events").fetchone()[0], 0)
                else:
                    for item in case["input"]["events"]:
                        self.assertTrue(store.ingest(item))


class EvaluationBudgetReview(unittest.TestCase):
    def test_fresh_case_database_cannot_reset_shared_evaluation_spend(self):
        from openshield.evaluation import _EvaluationGateway
        from openshield.gateway import GatewayError

        class BudgetCanary:
            """UNIT TEST DOUBLE: no provider, inference or usable AI result."""
            config = SimpleNamespace(global_token_limit=10)
            route_hash = "unit-budget-canary"
            attempts = 0

            def analyze(self, case, *, before_attempt, deadline):
                before_attempt(9)
                self.attempts += 1
                raise GatewayError("TRANSIENT_PROVIDER_FAILURE")

        fake = BudgetCanary()
        wrapper = _EvaluationGateway(fake)
        first_case, second_case = [], []
        with self.assertRaises(GatewayError) as first:
            wrapper.analyze({}, before_attempt=first_case.append, deadline=100)
        self.assertEqual(first.exception.code, "TRANSIENT_PROVIDER_FAILURE")
        with self.assertRaises(GatewayError) as second:
            wrapper.analyze({}, before_attempt=second_case.append, deadline=100)
        self.assertEqual(second.exception.code, "BUDGET_EXHAUSTED")
        self.assertEqual(wrapper.reserved_tokens, 9)
        self.assertEqual(first_case, [9])
        self.assertEqual(second_case, [])
        self.assertEqual(fake.attempts, 1)
