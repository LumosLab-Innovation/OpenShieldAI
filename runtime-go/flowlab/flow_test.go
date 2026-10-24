package flowlab

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestTrialObservesActualEffects(t *testing.T) {
	r, err := RunTrial()
	if err != nil || r.Status != "passed" || len(r.Checks) != 48 {
		t.Fatal("trial failed", err)
	}
	if r.NegativeControl != (Effects{4, 3, 3}) || r.ProtectedForbidden != (Effects{}) || r.ProtectedAllowed != (Effects{2, 2, 2}) || r.NegativeOutsideDeliveries != 2 || r.ProtectedOutsideRequests != 0 || r.ProtectedOutsideDeliveries != 0 || r.AllowedDeliveries != 1 || r.IdempotentCommits != 1 {
		t.Fatal("independent effect mismatch")
	}
	seen := map[string]bool{}
	for _, check := range r.Checks {
		if !check.Passed || seen[check.Code] {
			t.Fatal("failed or duplicate assertion")
		}
		seen[check.Code] = true
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"127.0.0.1", "http://", "X-Flow-", "synthetic_alpha", "synthetic_beta"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatal("raw route, token carrier or body leaked to report")
		}
	}
	if r.ModelCalls != 0 || r.ProductionActions {
		t.Fatal("synthetic experiment relabelled live")
	}
}

func TestExactApplicationRequest(t *testing.T) {
	valid := string(encode(sample("read")))
	if _, err := decode([]byte(valid)); err != nil {
		t.Fatal("valid request rejected")
	}
	for name, data := range map[string]string{
		"escaped_duplicate": strings.Replace(valid, `"objectId":"object_alpha"`, `"objectId":"object_alpha","\u006fbjectId":"object_beta"`, 1),
		"case_alias":        strings.Replace(valid, `"objectId"`, `"ObjectId"`, 1),
		"injected_approval": strings.Replace(valid, `"operation":`, `"approved":true,"operation":`, 1),
		"arbitrary_url":     strings.Replace(valid, `"recipientId":""`, `"recipientId":"http://127.0.0.1"`, 1),
		"float_units":       strings.Replace(valid, `"units":0`, `"units":0.0`, 1),
		"null_units":        strings.Replace(valid, `"units":0`, `"units": null `, 1),
		"null_key":          strings.Replace(valid, `"idempotencyKey":""`, `"idempotencyKey": null `, 1),
		"unsupported_class": strings.Replace(valid, `"synthetic"`, `"restricted"`, 1),
		"unknown_operation": strings.Replace(valid, `"read"`, `"shell"`, 1),
		"oversize":          valid + strings.Repeat(" ", 1024),
		"trailing":          valid + `[]`,
		"invalid_utf8":      string([]byte{0xff}) + valid,
		"null":              "null",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decode([]byte(data)); err == nil {
				t.Fatal("unsupported input accepted")
			}
		})
	}
}

func TestGrantSessionAndLifetimeBinding(t *testing.T) {
	l := newLab(true)
	defer l.close()
	s, err := l.session("principal_alpha")
	if err != nil {
		t.Fatal(err)
	}
	other, err := l.session("principal_alpha")
	if err != nil {
		t.Fatal(err)
	}
	op := sample("charge")
	op.Units = 1
	op.Key = "tx_test"
	g, err := l.issue(s, op, true)
	if err != nil {
		t.Fatal(err)
	}
	res, err := l.post("/v1/resource", other, g, encode(op))
	if err != nil || res.status != 403 || l.ledger.snapshot() != (Effects{}) {
		t.Fatal("cross-session grant accepted")
	}
	res, err = l.post("/v1/resource", s, g, encode(op))
	if err != nil || res.status != 200 || l.ledger.rowCount(op.Key) != 1 {
		t.Fatal("negative consumed original authority")
	}
	op.Key = "tx_expired"
	g, err = l.issue(s, op, true)
	if err != nil {
		t.Fatal(err)
	}
	l.advance(31 * time.Second)
	res, err = l.post("/v2/resource", s, g, encode(op))
	if err != nil || res.status != 403 || l.ledger.rowCount(op.Key) != 0 {
		t.Fatal("expired capability accepted")
	}
	l.advance(30 * time.Second)
	res, err = l.post("/v1/resource", s, "", encode(sample("read")))
	if err != nil || res.status != 403 {
		t.Fatal("expired session accepted")
	}
}

func TestAlternateRoutesAndMalformedAuthorityHaveNoEffect(t *testing.T) {
	l := newLab(true)
	defer l.close()
	s, err := l.session("principal_alpha")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/resource?approved=true", "/v3/resource", "/revoke", "/approve", "/deliver"} {
		res, err := l.post(path, s, "", encode(sample("read")))
		if err != nil || res.status != 400 || l.ledger.snapshot() != (Effects{}) {
			t.Fatal("unexpected route accepted")
		}
	}
	r, err := l.post("/v1/resource", strings.Repeat("f", 64), "", encode(sample("read")))
	if err != nil || r.status != 403 || l.ledger.snapshot() != (Effects{}) {
		t.Fatal("forged session accepted")
	}
	g := sample("export")
	g.Recipient = "inbox_outside"
	if _, err := l.issue(s, g, true); err == nil {
		t.Fatal("controller authorized outside recipient")
	}
	wrong := sample("charge")
	wrong.Object = "object_beta"
	wrong.Key = "tx_wrong"
	wrong.Units = 1
	if _, err := l.issue(s, wrong, true); err == nil {
		t.Fatal("controller authorized cross-tenant mutation")
	}
}

func TestValidProofBeforeFailuresRemainsUsable(t *testing.T) {
	l := newLab(true)
	defer l.close()
	login, err := l.post("/login", "", "", []byte(`{"principalId":"principal_alpha","proofClass":"accepted_fixture"}`))
	if err != nil || login.status != 200 {
		t.Fatal("valid synthetic login failed")
	}
	read, err := l.post("/v1/resource", login.token, "", encode(sample("read")))
	if err != nil || read.status != 200 || read.objectValue != "synthetic_alpha" || l.ledger.snapshot().Reads != 1 {
		t.Fatal("valid session cannot read its object")
	}
	// A valid stolen proof has the same fixture result: failure counters cannot identify its holder.
}
