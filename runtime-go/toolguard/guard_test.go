package toolguard

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestTrialActualEffects(t *testing.T) {
	report, err := RunTrial()
	if err != nil || report.Status != "passed" || len(report.Checks) < 43 {
		t.Fatal("trial checks failed", err)
	}
	if report.NegativeControl != (Counters{0, 1, 1}) || report.NegativeRecipientDeliveries != 1 || report.ProtectedForbidden != (Counters{}) || report.ProtectedAllowed != (Counters{9, 1, 1}) || report.ConcurrentAccepted != 1 {
		t.Fatal("independent effect mismatch")
	}
	data, err := json.Marshal(report)
	if err != nil || bytes.Contains(data, []byte("X-Lab-")) || bytes.Contains(data, []byte("127.0.0.1")) || report.ModelCalls != 0 || report.ProductionActions {
		t.Fatal("unsafe or misleading report")
	}
}

func TestExactParser(t *testing.T) {
	valid := string(encode(sample("read_record")))
	if _, err := decode([]byte(valid)); err != nil {
		t.Fatal("valid rejected")
	}
	tests := map[string]string{
		"escaped_duplicate":   strings.Replace(valid, `"caseId":"case_alpha"`, `"caseId":"case_alpha","\u0063aseId":"case_alpha"`, 1),
		"unknown_operation":   strings.Replace(valid, `"read_record"`, `"shell"`, 1),
		"array":               `[]`,
		"null":                `null`,
		"unknown_field":       strings.Replace(valid, `"agentId":`, `"toolText":"approved","agentId":`, 1),
		"missing_field":       strings.Replace(valid, `"dataClass":"synthetic",`, ``, 1),
		"nested_parameters":   strings.Replace(valid, `"revision":1`, `"revision":{"value":1}`, 1),
		"bool_evidence":       strings.Replace(valid, `"evidenceVersion":1`, `"evidenceVersion":true`, 1),
		"float_evidence":      strings.Replace(valid, `"evidenceVersion":1`, `"evidenceVersion":1.0`, 1),
		"exponent_revision":   strings.Replace(valid, `"revision":1`, `"revision":1e0`, 1),
		"huge_integer":        strings.Replace(valid, `"revision":1`, `"revision":9223372036854775808`, 1),
		"oversize_identifier": strings.Replace(valid, `"agent_alpha"`, `"`+strings.Repeat("x", 65)+`"`, 1),
		"boolean_string":      strings.Replace(valid, `"synthetic"`, `true`, 1),
		"trailing":            valid + ` []`,
		"malformed":           strings.TrimSuffix(valid, "}"),
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decode([]byte(body)); err == nil {
				t.Fatal("invalid JSON/schema accepted")
			}
		})
	}
}

func TestScopeAndApprovalAtIssuance(t *testing.T) {
	l := newLab(true)
	defer l.close()
	s, err := l.session("agent_alpha", "tenant_alpha")
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"mark_reviewed", "send_receipt", "shell"} {
		if _, err := l.issue(s, sample(operation), time.Minute, false); err == nil {
			t.Fatal("unapproved mutation or unknown operation authorized")
		}
	}
	for _, ttl := range []time.Duration{0, -time.Second, time.Hour} {
		if _, err := l.issue(s, sample("read_record"), ttl, false); err == nil {
			t.Fatal("invalid lifetime authorized")
		}
	}
	wrong := sample("read_record")
	wrong.Tenant = "tenant_beta"
	if _, err := l.issue(s, wrong, time.Minute, false); err == nil {
		t.Fatal("wrong tenant grant issued")
	}
	for range 128 {
		if _, err := l.issue(s, sample("read_record"), time.Minute, false); err != nil {
			t.Fatal("bounded capacity unavailable")
		}
	}
	if _, err := l.issue(s, sample("read_record"), time.Minute, false); err == nil {
		t.Fatal("grant cap bypassed")
	}
}

func TestDirectHTTPBoundaryAndDuplicateHeaders(t *testing.T) {
	l := newLab(true)
	defer l.close()
	s, err := l.session("agent_alpha", "tenant_alpha")
	if err != nil {
		t.Fatal(err)
	}
	g, err := l.issue(s, sample("read_record"), time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		method, path, contentType string
		duplicate                 bool
	}{
		{"POST", "/tool?approved=true", "application/json", false},
		{"GET", "/tool", "application/json", false},
		{"POST", "/direct", "application/json", false},
		{"POST", "/tool", "text/plain", false},
		{"POST", "/tool", "application/json", true},
	} {
		req, err := http.NewRequest(test.method, l.server.URL+test.path, bytes.NewReader(encode(sample("read_record"))))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", test.contentType)
		req.Header.Set("X-Lab-Session", s)
		req.Header.Set("X-Lab-Grant", g)
		if test.duplicate {
			req.Header.Add("X-Lab-Grant", g)
		}
		res, err := l.client.Do(req)
		if err != nil {
			t.Fatal("HTTP boundary unavailable")
		}
		res.Body.Close()
		if res.StatusCode == 200 || l.effects.snapshot() != (Counters{}) {
			t.Fatal("alternate path or header ambiguity caused effect")
		}
	}
	status, result, err := l.call(s, g, encode(sample("read_record")))
	if err != nil || status != 200 || result.Value != "pending" {
		t.Fatal("boundary negatives consumed valid authority")
	}
}

func TestActualFixedReceiversAndRecordState(t *testing.T) {
	l := newLab(true)
	defer l.close()
	s, err := l.session("agent_alpha", "tenant_alpha")
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"mark_reviewed", "send_receipt", "read_record"} {
		r := sample(operation)
		g, err := l.issue(s, r, time.Minute, true)
		if err != nil {
			t.Fatal(err)
		}
		status, result, err := l.call(s, g, encode(r))
		if err != nil || status != 200 || result.Value != "reviewed" {
			t.Fatal("legitimate operation failed")
		}
	}
	l.effects.mu.Lock()
	defer l.effects.mu.Unlock()
	if !l.effects.reviewed || len(l.effects.inboxes["inbox_alpha"]) != 1 || l.effects.inboxes["inbox_alpha"][0] != "synthetic_receipt" || len(l.effects.inboxes["inbox_beta"]) != 0 {
		t.Fatal("independent resource/receiver state mismatch")
	}
}
