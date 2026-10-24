package toolguard

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Check struct {
	Code   string `json:"code"`
	Passed bool   `json:"passed"`
}
type Report struct {
	Schema                      string   `json:"schemaVersion"`
	Status                      string   `json:"status"`
	DataClass                   string   `json:"dataClass"`
	Checks                      []Check  `json:"checks"`
	NegativeControl             Counters `json:"negativeControlEffects"`
	NegativeRecipientDeliveries int      `json:"negativeControlOutsideRecipientDeliveries"`
	ProtectedForbidden          Counters `json:"protectedForbiddenEffects"`
	ProtectedAllowed            Counters `json:"protectedAllowedEffects"`
	ConcurrentAccepted          int      `json:"concurrentAccepted"`
	ModelCalls                  int      `json:"modelCalls"`
	ProductionActions           bool     `json:"productionActions"`
	Limitations                 []string `json:"limitations"`
}

// RunTrial sends actual loopback HTTP requests and checks separate effect state.
// shortcut: ephemeral authority is lab-only; durable multi-worker grants need a separate accepted adapter.
func RunTrial() (Report, error) {
	report := Report{Schema: "tool_guard_trial_v1", Status: "passed", DataClass: "synthetic", Checks: []Check{}, Limitations: []string{
		"Scripted poisoned-tool proposals; no LLM or measured prompt-injection success rate.",
		"Fixed loopback fixture only; no production identity, TLS, persistence or multi-process authority.",
		"Separate in-process observer reads actual counters, not executor receipts; no external observer trust claim.",
		"Allowed operations can still be semantically harmful; capability binding is not intent detection.",
		"No workload throughput, denial-of-service resilience or Internet-scale security claim.",
	}}
	check := func(code string, ok bool) {
		report.Checks = append(report.Checks, Check{code, ok})
		if !ok {
			report.Status = "failed"
		}
	}
	control, protected := newLab(false), newLab(true)
	defer control.close()
	defer protected.close()
	session, err := protected.session("agent_alpha", "tenant_alpha")
	if err != nil {
		return report, err
	}
	other, err := protected.session("agent_beta", "tenant_beta")
	if err != nil {
		return report, err
	}
	read := sample("read_record")
	grant, err := protected.issue(session, read, time.Minute, false)
	if err != nil {
		return report, err
	}
	base := protected.effects.snapshot()

	// This is the synthetic attacker-controlled proposal after reading poisoned text.
	mutations := []struct {
		code   string
		change func(*request)
	}{
		{"poisoned_read_to_write", func(r *request) { r.Operation = "mark_reviewed" }},
		{"wrong_case", func(r *request) { r.Case = "case_beta" }},
		{"wrong_asset", func(r *request) { r.Asset = "asset_beta" }},
		{"wrong_object", func(r *request) { r.Object = "record_beta" }},
		{"wrong_agent", func(r *request) { r.Agent = "agent_beta" }},
		{"wrong_tenant", func(r *request) { r.Tenant = "tenant_beta" }},
		{"recipient_rebinding", func(r *request) { r.Recipient = "inbox_beta" }},
		{"data_class_rebinding", func(r *request) { r.DataClass = "confidential" }},
		{"scope_drift", func(r *request) { r.Scope = "scope_2" }},
		{"policy_drift", func(r *request) { r.Policy = "policy_2" }},
		{"evidence_drift", func(r *request) { r.Evidence = 2 }},
		{"parameter_revision_rebinding", func(r *request) { r.Params.Revision = 2 }},
		{"parameter_value_rebinding", func(r *request) { r.Params.Value = "other" }},
	}
	for _, test := range mutations {
		proposal := read
		test.change(&proposal)
		status, err := protected.post(session, grant, encode(proposal))
		if err != nil {
			return report, err
		}
		check(test.code, status != 200 && protected.effects.snapshot() == base)
	}
	receipt, err := protected.issue(session, sample("send_receipt"), time.Minute, true)
	if err != nil {
		return report, err
	}
	misdirected := sample("send_receipt")
	misdirected.Recipient = "inbox_beta"
	status, err := protected.post(session, receipt, encode(misdirected))
	if err != nil {
		return report, err
	}
	check("approved_receipt_wrong_recipient", status != 200 && protected.effects.snapshot() == base)
	for _, test := range []struct{ code, session, grant string }{
		{"direct_invocation_no_grant", session, ""}, {"forged_approval", session, strings.Repeat("f", 64)}, {"forged_session", strings.Repeat("e", 64), grant}, {"cross_agent_grant", other, grant},
	} {
		status, err := protected.post(test.session, test.grant, encode(read))
		if err != nil {
			return report, err
		}
		check(test.code, status != 200 && protected.effects.snapshot() == base)
	}
	for _, operation := range []string{"mark_reviewed", "send_receipt"} {
		proposal := sample(operation)
		if operation == "send_receipt" {
			proposal.Recipient = "inbox_beta"
		}
		status, err := control.post("", "", encode(proposal))
		if err != nil {
			return report, err
		}
		check("negative_control_"+operation, status == 200)
	}
	report.NegativeControl = control.effects.snapshot()
	report.NegativeRecipientDeliveries = control.effects.received("inbox_beta")
	check("negative_control_observed_forbidden_effects", report.NegativeControl.Marks == 1 && report.NegativeControl.Deliveries == 1)
	check("negative_control_receiver_observed", report.NegativeRecipientDeliveries == 1)

	malformed := map[string]string{
		"duplicate_operation":   strings.Replace(string(encode(read)), `"operation":"read_record"`, `"operation":"read_record","operation":"mark_reviewed"`, 1),
		"case_alias":            strings.Replace(string(encode(read)), `"caseId"`, `"CaseId"`, 1),
		"forged_approval_field": strings.Replace(string(encode(read)), `"agentId":`, `"approved":true,"agentId":`, 1),
		"duplicate_parameter":   strings.Replace(string(encode(read)), `"revision":1`, `"revision":1,"revision":1`, 1),
		"boolean_parameter":     strings.Replace(string(encode(read)), `"revision":1`, `"revision":true`, 1),
		"float_parameter":       strings.Replace(string(encode(read)), `"revision":1`, `"revision":1.0`, 1),
		"null_parameter":        strings.Replace(string(encode(read)), `"revision":1`, `"revision":null`, 1),
		"unknown_parameter":     strings.Replace(string(encode(read)), `"revision":1`, `"revision":1,"extra":1`, 1),
		"null_evidence":         strings.Replace(string(encode(read)), `"evidenceVersion":1`, `"evidenceVersion":null`, 1),
		"trailing_document":     string(encode(read)) + `{}`,
		"oversized_body":        strings.Repeat(" ", maxBody) + string(encode(read)),
		"invalid_utf8":          string([]byte{0xff}) + string(encode(read)),
	}
	for code, body := range malformed {
		status, err := protected.post(session, grant, []byte(body))
		if err != nil {
			return report, err
		}
		check(code, status == 400 && protected.effects.snapshot() == base)
	}
	expired, err := protected.issue(session, read, 5*time.Millisecond, false)
	if err != nil {
		return report, err
	}
	time.Sleep(20 * time.Millisecond)
	status, err = protected.post(session, expired, encode(read))
	if err != nil {
		return report, err
	}
	check("expired_grant", status != 200 && protected.effects.snapshot() == base)
	report.ProtectedForbidden = delta(protected.effects.snapshot(), base)
	check("no_forbidden_effects", report.ProtectedForbidden == (Counters{}))

	// Failed substitutions must not consume the original allowed read grant.
	canonical := read
	canonical.Params.Value = " READY "
	status, readResult, err := protected.call(session, grant, encode(canonical))
	if err != nil {
		return report, err
	}
	check("legitimate_read_after_attacks", status == 200 && readResult.Value == "pending" && protected.effects.snapshot().Reads == 1)
	status, err = protected.post(session, grant, encode(read))
	if err != nil {
		return report, err
	}
	check("replay_denied", status != 200 && protected.effects.snapshot().Reads == 1)
	status, err = protected.post(session, receipt, encode(sample("send_receipt")))
	if err != nil {
		return report, err
	}
	check("approved_receipt_after_recipient_attack", status == 200 && protected.effects.received("inbox_alpha") == 1 && protected.effects.received("inbox_beta") == 0)
	status, err = protected.post(session, receipt, encode(sample("send_receipt")))
	if err != nil {
		return report, err
	}
	check("receipt_replay_denied", status != 200 && protected.effects.snapshot().Deliveries == 1)
	_, err = protected.issue(session, sample("mark_reviewed"), time.Minute, false)
	check("controller_requires_write_approval", err != nil)
	write, err := protected.issue(session, sample("mark_reviewed"), time.Minute, true)
	if err != nil {
		return report, err
	}
	var accepted atomic.Int32
	var failures atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status, err := protected.post(session, write, encode(sample("mark_reviewed")))
			if err != nil {
				failures.Add(1)
			}
			if status == 200 {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	report.ConcurrentAccepted = int(accepted.Load())
	check("concurrent_one_use", accepted.Load() == 1 && failures.Load() == 0 && protected.effects.snapshot().Marks == 1)
	for range 8 {
		probe, err := protected.issue(session, read, time.Minute, false)
		if err != nil {
			return report, err
		}
		status, result, err := protected.call(session, probe, encode(read))
		if err != nil {
			return report, err
		}
		if status != 200 || result.Value != "reviewed" {
			check("benign_probe_after_attacks", false)
			break
		}
	}
	report.ProtectedAllowed = delta(protected.effects.snapshot(), base)
	check("benign_probe_after_attacks", report.ProtectedAllowed == (Counters{9, 1, 1}))
	sort.Slice(report.Checks, func(i, j int) bool { return report.Checks[i].Code < report.Checks[j].Code })
	if report.Status != "passed" {
		return report, errors.New("TRIAL_ASSERTION_FAILED")
	}
	return report, nil
}
