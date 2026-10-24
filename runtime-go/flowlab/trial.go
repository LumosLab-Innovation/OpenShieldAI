package flowlab

import (
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type Check struct {
	Code   string `json:"code"`
	Passed bool   `json:"passed"`
}
type Observation struct {
	ID    string         `json:"id"`
	Case  string         `json:"caseId"`
	Facts map[string]int `json:"facts"`
}
type Report struct {
	Schema                     string        `json:"schemaVersion"`
	Status                     string        `json:"status"`
	ErrorCode                  string        `json:"errorCode,omitempty"`
	DataClass                  string        `json:"dataClass"`
	Checks                     []Check       `json:"checks"`
	NegativeControl            Effects       `json:"negativeControlEffects"`
	ProtectedForbidden         Effects       `json:"protectedForbiddenEffects"`
	ProtectedAllowed           Effects       `json:"protectedAllowedEffects"`
	NegativeOutsideDeliveries  int           `json:"negativeControlOutsideDeliveries"`
	ProtectedOutsideDeliveries int           `json:"protectedOutsideDeliveries"`
	ProtectedOutsideRequests   int           `json:"protectedOutsideRequests"`
	AllowedDeliveries          int           `json:"protectedAllowedDeliveries"`
	IdempotentCommits          int           `json:"idempotentConcurrentCommits"`
	Observations               []Observation `json:"observations"`
	ModelCalls                 int           `json:"modelCalls"`
	ProductionActions          bool          `json:"productionActions"`
	Limitations                []string      `json:"limitations"`
}

func count(ok bool) int {
	if ok {
		return 1
	}
	return 0
}

// RunTrial compares unsafe and protected application boundaries using actual HTTP.
func RunTrial() (report Report, trialErr error) {
	report = Report{Schema: "flow_lab_v1", Status: "passed", DataClass: "synthetic", Checks: []Check{}, Observations: []Observation{}, Limitations: []string{
		"Owned fixed loopback fixtures only; proofClass is a synthetic authenticator result, never a real password or identity provider.",
		"Ephemeral single-process session, grant, throttle and idempotency state; no restart, distributed consistency, TLS or production authentication claim.",
		"Three-failure per-principal lockout lasts sixty fixture seconds; a correct login is denied during lockout, and valid stolen credentials before failures remain usable.",
		"Revocation covers only the two declared resource paths and requests rechecked before effect; already committed effects, external verifiers and outstanding network transfers are not undone.",
		"Fixed synthetic receiver mediation only; no arbitrary URL fetching, DNS-rebinding, general DLP, alternate-process egress or earlier-disclosure coverage.",
		"Ledger and receivers are separate in-process observers, not external trusted monitors; no crash-safe exactly-once guarantee for external effects.",
		"Read quota is principal-wide eight reads in the fixture lifetime, not learned intent; denial can disrupt legitimate bulk work.",
		"Fixture lifetime bounds: sixteen sessions, eight per principal, sixty-four outstanding grants, thirty-two transaction keys, twenty-four admitted login checks and four in-flight requests.",
		"Known bounded engineering cases, not held-out attack prevalence, classifier accuracy, real AI benefit or workload performance.",
	}}
	defer func() {
		if trialErr != nil {
			report.Status = "failed"
			report.ErrorCode = "TRIAL_FAILED"
		}
	}()
	check := func(code string, ok bool) {
		report.Checks = append(report.Checks, Check{code, ok})
		if !ok {
			report.Status = "failed"
		}
	}
	call := func(l *lab, path, s, g string, op operation) (response, error) { return l.post(path, s, g, encode(op)) }
	forbidden := func(l *lab, path, s, g string, op operation) (response, error) {
		before := l.ledger.snapshot()
		result, err := call(l, path, s, g, op)
		after := l.ledger.snapshot()
		report.ProtectedForbidden.Reads += after.Reads - before.Reads
		report.ProtectedForbidden.Charges += after.Charges - before.Charges
		report.ProtectedForbidden.ChargedUnits += after.ChargedUnits - before.ChargedUnits
		return result, err
	}
	read := sample("read")
	control, protected := newLab(false), newLab(true)
	defer control.close()
	defer protected.close()
	cs, err := control.session("principal_alpha")
	if err != nil {
		return report, err
	}
	ps, err := protected.session("principal_alpha")
	if err != nil {
		return report, err
	}

	// I1: rotate a source label out of the question: counters belong to the principal.
	for _, l := range []*lab{control, protected} {
		for range 3 {
			res, e := l.post("/login", "", "", []byte(`{"principalId":"principal_alpha","proofClass":"rejected_fixture"}`))
			if e != nil {
				return report, e
			}
			check("auth_failed_fixture_"+map[bool]string{true: "protected", false: "unsafe"}[l.protected]+"_"+string(rune('0'+l.authChecks())), res.status == 401)
		}
	}
	unsafeLogin, err := control.post("/login", "", "", []byte(`{"principalId":"principal_alpha","proofClass":"accepted_fixture"}`))
	if err != nil {
		return report, err
	}
	checksBeforeBlocked := protected.authChecks()
	blockedLogin, err := protected.post("/login", "", "", []byte(`{"principalId":"principal_alpha","proofClass":"accepted_fixture"}`))
	if err != nil {
		return report, err
	}
	check("auth_budget_unsafe_issues_session", unsafeLogin.status == 200 && unsafeLogin.token != "")
	check("auth_budget_denies_before_authenticator", blockedLogin.status == 429 && blockedLogin.token == "" && protected.authChecks() == 3)
	furtherChecks := protected.authChecks() - checksBeforeBlocked
	res, err := call(control, "/v1/resource", unsafeLogin.token, "", read)
	if err != nil {
		return report, err
	}
	check("auth_budget_unsafe_protected_read_observed", res.status == 200 && control.ledger.snapshot().Reads == 1)
	otherLogin, err := protected.post("/login", "", "", []byte(`{"principalId":"principal_beta","proofClass":"accepted_fixture"}`))
	if err != nil {
		return report, err
	}
	check("auth_budget_unrelated_principal_works", otherLogin.status == 200 && otherLogin.token != "")
	protected.advance(61 * time.Second)
	recovered, err := protected.post("/login", "", "", []byte(`{"principalId":"principal_alpha","proofClass":"accepted_fixture"}`))
	if err != nil {
		return report, err
	}
	check("auth_window_correct_login_recovers", recovered.status == 200 && recovered.token != "")
	// Time advancement expires earlier sessions; replace them through the controller.
	ps, err = protected.session("principal_alpha")
	if err != nil {
		return report, err
	}
	report.Observations = append(report.Observations, Observation{"fact_auth_budget", "I1", map[string]int{"priorPrincipalFailures": checksBeforeBlocked, "furtherCredentialChecks": furtherChecks, "correctProofRejectedDuringLockout": count(blockedLogin.status == 429), "unrelatedPrincipalLoginAccepted": count(otherLogin.status == 200), "afterWindowLoginAccepted": count(recovered.status == 200)}})

	// I2: warm the second verifier's unsafe cache, then revoke through trusted authority.
	for _, l := range []*lab{control, protected} {
		token := cs
		if l.protected {
			token = ps
		}
		res, e := call(l, "/v2/resource", token, "", read)
		if e != nil {
			return report, e
		}
		check("verifier_warm_"+map[bool]string{true: "protected", false: "unsafe"}[l.protected], res.status == 200)
		l.revoke(token)
	}
	base := protected.ledger.snapshot()
	revokedDenied := 0
	for _, path := range []string{"/v1/resource", "/v2/resource"} {
		res, e := forbidden(protected, path, ps, "", read)
		if e != nil {
			return report, e
		}
		check("revoked_denied_"+path, res.status == 403 && res.objectValue == "" && protected.ledger.snapshot() == base)
		revokedDenied += count(res.status == 403 && res.objectValue == "")
	}
	unsafeBeforeCache := control.ledger.snapshot()
	res, err = call(control, "/v2/resource", cs, "", read)
	if err != nil {
		return report, err
	}
	check("unsafe_cached_verifier_reads_after_revocation", res.status == 200 && control.ledger.snapshot().Reads == 3)
	unsafeCacheReads := control.ledger.snapshot().Reads - unsafeBeforeCache.Reads
	res, err = call(control, "/v1/resource", cs, "", read)
	if err != nil {
		return report, err
	}
	check("unsafe_primary_verifier_denies_revocation", res.status == 403)
	ps, err = protected.session("principal_alpha")
	if err != nil {
		return report, err
	}
	res, err = call(protected, "/v1/resource", ps, "", read)
	if err != nil {
		return report, err
	}
	check("new_valid_session_service_health", res.status == 200 && res.objectValue == "synthetic_alpha")
	report.Observations = append(report.Observations, Observation{"fact_session_verifiers", "I2", map[string]int{"declaredVerifierPaths": 2, "revokedProtectedPathsDenied": revokedDenied, "unsafeCachedPathReadsAfterRevocation": unsafeCacheReads, "newValidSessionReadAccepted": count(res.status == 200 && res.objectValue == "synthetic_alpha")}})

	// W3: object IDs are public; ownership, not obscurity, mediates every path.
	cs, err = control.session("principal_alpha")
	if err != nil {
		return report, err
	}
	wrong := read
	wrong.Object = "object_beta"
	res, err = call(control, "/v1/resource", cs, "", wrong)
	if err != nil {
		return report, err
	}
	check("unsafe_cross_tenant_read_observed", res.status == 200 && res.objectValue == "synthetic_beta")
	unsafeCrossReads := count(res.status == 200 && res.objectValue == "synthetic_beta")
	base = protected.ledger.snapshot()
	for _, path := range []string{"/v1/resource", "/v2/resource"} {
		res, e := forbidden(protected, path, ps, "", wrong)
		if e != nil {
			return report, e
		}
		check("object_authority_"+path, res.status == 403 && res.objectValue == "" && protected.ledger.snapshot() == base)
	}
	protectedCrossReads := protected.ledger.snapshot().Reads - base.Reads
	charge := sample("charge")
	charge.Key = "tx_alpha"
	charge.Units = 1
	for range 2 {
		res, e := call(control, "/v1/resource", cs, "", charge)
		if e != nil {
			return report, e
		}
		if res.status != 200 {
			return report, errors.New("NEGATIVE_CONTROL_FAILED")
		}
	}
	check("unsafe_duplicate_charges_observed", control.ledger.rowCount(charge.Key) == 2)
	_, err = protected.issue(ps, charge, false)
	check("charge_requires_controller_approval", err != nil)
	res, err = forbidden(protected, "/v1/resource", ps, "", charge)
	if err != nil {
		return report, err
	}
	check("charge_direct_invocation_denied", res.status == 403 && protected.ledger.snapshot() == base)
	grant, err := protected.issue(ps, charge, true)
	if err != nil {
		return report, err
	}
	changed := charge
	changed.Units = 2
	res, err = forbidden(protected, "/v1/resource", ps, grant, changed)
	if err != nil {
		return report, err
	}
	check("charge_exact_units_binding", res.status == 403 && protected.ledger.snapshot() == base)
	res, err = call(protected, "/v1/resource", ps, grant, charge)
	if err != nil {
		return report, err
	}
	check("approved_charge_actual_ledger_row", res.status == 200 && protected.ledger.rowCount(charge.Key) == 1)
	res, err = forbidden(protected, "/v2/resource", ps, grant, charge)
	if err != nil {
		return report, err
	}
	check("charge_capability_replay_denied", res.status == 403 && protected.ledger.rowCount(charge.Key) == 1)
	grant, err = protected.issue(ps, changed, true)
	if err != nil {
		return report, err
	}
	res, err = forbidden(protected, "/v1/resource", ps, grant, changed)
	if err != nil {
		return report, err
	}
	check("idempotency_payload_conflict_denied", res.status == 409 && protected.ledger.rowCount(charge.Key) == 1)
	conflictDenied := count(res.status == 409)
	grant, err = protected.issue(ps, charge, true)
	if err != nil {
		return report, err
	}
	res, err = call(protected, "/v1/resource", ps, grant, charge)
	if err != nil {
		return report, err
	}
	check("lost_response_reconciles_without_second_charge", res.status == 200 && protected.ledger.rowCount(charge.Key) == 1)
	race := charge
	race.Key = "tx_race"
	var wg sync.WaitGroup
	var accepted, failures atomic.Int32
	grants := make([]string, 16)
	for i := range grants {
		grants[i], err = protected.issue(ps, race, true)
		if err != nil {
			return report, err
		}
	}
	for _, g := range grants {
		wg.Add(1)
		go func(g string) {
			defer wg.Done()
			res, e := call(protected, "/v2/resource", ps, g, race)
			if e != nil || res.status != 200 && res.status != 429 {
				failures.Add(1)
			}
			if res.status == 200 {
				accepted.Add(1)
			}
		}(g)
	}
	wg.Wait()
	report.IdempotentCommits = protected.ledger.rowCount(race.Key)
	check("concurrent_distinct_grants_one_transaction", accepted.Load() >= 1 && failures.Load() == 0 && report.IdempotentCommits == 1)
	report.Observations = append(report.Observations, Observation{"fact_object_transaction", "W3", map[string]int{"crossTenantProtectedReads": protectedCrossReads, "unsafeCrossTenantReads": unsafeCrossReads, "unsafeDuplicateCharges": control.ledger.rowCount(charge.Key), "protectedConcurrentCommits": report.IdempotentCommits, "conflictingPayloadRejected": conflictDenied}})

	// Revoke an already accepted request before its final authoritative effect check.
	for _, l := range []*lab{control, protected} {
		token, e := l.session("principal_beta")
		if e != nil {
			return report, e
		}
		op := charge
		op.Object = "object_beta"
		op.Key = "tx_inflight"
		g, e := l.issue(token, op, true)
		if e != nil {
			return report, e
		}
		hook := &pauseHook{make(chan struct{}), make(chan struct{})}
		l.mu.Lock()
		l.pause = hook
		l.mu.Unlock()
		done := make(chan response, 1)
		failed := make(chan error, 1)
		before := l.ledger.snapshot()
		go func() {
			var result response
			var e error
			if l.protected {
				result, e = forbidden(l, "/v1/resource", token, g, op)
			} else {
				result, e = call(l, "/v1/resource", token, g, op)
			}
			done <- result
			failed <- e
		}()
		select {
		case <-hook.entered:
		case <-time.After(time.Second):
			return report, errors.New("INFLIGHT_NOT_OBSERVED")
		}
		l.revoke(token)
		close(hook.release)
		result := <-done
		if e := <-failed; e != nil {
			return report, e
		}
		if l.protected {
			check("revoked_inflight_rechecked_before_commit", result.status == 403 && l.ledger.rowCount(op.Key) == 0 && l.ledger.snapshot() == before)
		} else {
			check("unsafe_inflight_effect_after_revocation", result.status == 200 && l.ledger.rowCount(op.Key) == 1)
		}
	}

	// W4/D4: fixed-recipient mediation with a real separate forbidden receiver.
	export := sample("export")
	export.Recipient = "inbox_outside"
	res, err = call(control, "/v1/resource", cs, "", export)
	if err != nil {
		return report, err
	}
	check("unsafe_outside_receiver_observes_data", res.status == 200)
	base = protected.ledger.snapshot()
	res, err = forbidden(protected, "/v1/resource", ps, "", export)
	if err != nil {
		return report, err
	}
	check("unregistered_recipient_denied", res.status == 403)
	export.Recipient = "inbox_alpha"
	grant, err = protected.issue(ps, export, true)
	if err != nil {
		return report, err
	}
	res, err = call(protected, "/v1/resource", ps, grant, export)
	if err != nil {
		return report, err
	}
	a, o, q := protected.receivers.snapshot()
	check("approved_export_actual_receiver", res.status == 200 && a == 1 && o == 0 && q == 0)
	res, err = forbidden(protected, "/v1/resource", ps, grant, export)
	if err != nil {
		return report, err
	}
	a, o, q = protected.receivers.snapshot()
	check("export_replay_has_no_delivery", res.status == 403 && a == 1 && o == 0 && q == 0)
	for _, l := range []*lab{control, protected} {
		l.receivers.mu.Lock()
		l.receivers.redirect = true
		l.receivers.mu.Unlock()
	}
	res, err = call(control, "/v1/resource", cs, "", export)
	if err != nil {
		return report, err
	}
	check("unsafe_redirect_exfiltrates_synthetic_data", res.status == 200)
	grant, err = protected.issue(ps, export, true)
	if err != nil {
		return report, err
	}
	res, err = forbidden(protected, "/v1/resource", ps, grant, export)
	if err != nil {
		return report, err
	}
	a, o, q = protected.receivers.snapshot()
	check("redirect_refused_before_forbidden_request", res.status == 502 && a == 1 && o == 0 && q == 0)
	redirectRejected := count(res.status == 502)
	res, err = forbidden(protected, "/v1/resource", ps, grant, export)
	if err != nil {
		return report, err
	}
	check("ambiguous_external_delivery_not_retried", res.status == 403)
	check("export_does_not_mutate_business_ledger", protected.ledger.snapshot() == base)
	report.AllowedDeliveries, report.ProtectedOutsideDeliveries, report.ProtectedOutsideRequests = protected.receivers.snapshot()
	_, report.NegativeOutsideDeliveries, _ = control.receivers.snapshot()
	check("independent_forbidden_receiver_zero", report.ProtectedOutsideDeliveries == 0 && report.ProtectedOutsideRequests == 0 && report.NegativeOutsideDeliveries == 2)
	report.Observations = append(report.Observations, Observation{"fact_egress_receivers", "W4_D4", map[string]int{"unsafeOutsideDataDeliveries": report.NegativeOutsideDeliveries, "protectedOutsideRequests": report.ProtectedOutsideRequests, "protectedAllowedDeliveries": report.AllowedDeliveries, "redirectRejected": redirectRejected}})

	// Principal budgets cannot be reset merely by obtaining a fresh browser session.
	quota := newLab(true)
	defer quota.close()
	qs, err := quota.session("principal_alpha")
	if err != nil {
		return report, err
	}
	for range 8 {
		res, e := call(quota, "/v1/resource", qs, "", read)
		if e != nil {
			return report, e
		}
		if res.status != 200 {
			return report, errors.New("QUOTA_POSITIVE_FAILED")
		}
	}
	qs, err = quota.session("principal_alpha")
	if err != nil {
		return report, err
	}
	res, err = call(quota, "/v2/resource", qs, "", read)
	if err != nil {
		return report, err
	}
	check("fresh_session_cannot_reset_principal_read_budget", res.status == 429 && quota.ledger.snapshot().Reads == 8)
	for range 6 {
		if _, err = quota.session("principal_alpha"); err != nil {
			return report, err
		}
	}
	_, err = quota.session("principal_alpha")
	check("session_issuance_capacity_bounded", err != nil)
	// Four paused requests occupy the entire admission budget; the fifth cannot read.
	busy := newLab(true)
	defer busy.close()
	bs, err := busy.session("principal_alpha")
	if err != nil {
		return report, err
	}
	hooks := make([]*pauseHook, 4)
	completions := make(chan bool, 4)
	for i := range hooks {
		hooks[i] = &pauseHook{make(chan struct{}), make(chan struct{})}
		busy.mu.Lock()
		busy.pause = hooks[i]
		busy.mu.Unlock()
		go func() {
			result, e := call(busy, "/v1/resource", bs, "", read)
			completions <- e == nil && result.status == 200 && result.objectValue == "synthetic_alpha"
		}()
		select {
		case <-hooks[i].entered:
		case <-time.After(time.Second):
			return report, errors.New("WORKER_NOT_OBSERVED")
		}
	}
	res, err = call(busy, "/v2/resource", bs, "", read)
	if err != nil {
		return report, err
	}
	check("request_worker_overload_has_no_read", res.status == 429 && busy.ledger.snapshot() == (Effects{}))
	for _, hook := range hooks {
		close(hook.release)
	}
	completed := true
	for range hooks {
		completed = <-completions && completed
	}
	check("inflight_requests_resume_within_budget", completed && busy.ledger.snapshot().Reads == 4)
	report.NegativeControl = control.ledger.snapshot()
	check("negative_control_ledger_observed", report.NegativeControl == (Effects{Reads: 4, Charges: 3, ChargedUnits: 3}))
	report.ProtectedAllowed = protected.ledger.snapshot()
	report.ProtectedAllowed.Reads -= report.ProtectedForbidden.Reads
	report.ProtectedAllowed.Charges -= report.ProtectedForbidden.Charges
	report.ProtectedAllowed.ChargedUnits -= report.ProtectedForbidden.ChargedUnits
	check("protected_legitimate_effects_preserved", report.ProtectedAllowed == (Effects{Reads: 2, Charges: 2, ChargedUnits: 2}))
	check("protected_forbidden_effects_zero", report.ProtectedForbidden == (Effects{}))
	sort.Slice(report.Checks, func(i, j int) bool { return report.Checks[i].Code < report.Checks[j].Code })
	if report.Status != "passed" {
		return report, errors.New("TRIAL_ASSERTION_FAILED")
	}
	return report, nil
}
