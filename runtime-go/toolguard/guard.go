// Package toolguard runs a fixed synthetic tool-boundary experiment, not a service.
package toolguard

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const maxBody = 2048

var invalid = errors.New("INVALID_REQUEST")

type parameters struct {
	Revision int    `json:"revision"`
	Value    string `json:"value"`
}
type request struct {
	Agent     string     `json:"agentId"`
	Tenant    string     `json:"tenantId"`
	Case      string     `json:"caseId"`
	Asset     string     `json:"assetId"`
	Object    string     `json:"objectId"`
	Operation string     `json:"operation"`
	Params    parameters `json:"params"`
	Recipient string     `json:"recipientId"`
	DataClass string     `json:"dataClass"`
	Scope     string     `json:"scopeVersion"`
	Policy    string     `json:"policyVersion"`
	Evidence  int        `json:"evidenceVersion"`
}

func sample(operation string) request {
	return request{"agent_alpha", "tenant_alpha", "case_alpha", "asset_alpha", "record_alpha", operation,
		parameters{1, "ready"}, "inbox_alpha", "synthetic", "scope_1", "policy_1", 1}
}

// Exact token names and duplicate rejection avoid encoding/json struct aliases.
func object(data []byte, names ...string) (map[string]json.RawMessage, error) {
	if !utf8.Valid(data) {
		return nil, invalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, invalid
	}
	allowed := map[string]bool{}
	for _, name := range names {
		allowed[name] = true
	}
	result := map[string]json.RawMessage{}
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		if err != nil || !ok || !allowed[name] || result[name] != nil {
			return nil, invalid
		}
		var raw json.RawMessage
		if d.Decode(&raw) != nil {
			return nil, invalid
		}
		result[name] = raw
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') || len(result) != len(names) {
		return nil, invalid
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, invalid
	}
	return result, nil
}

func decode(data []byte) (request, error) {
	var r request
	fields, err := object(data, "agentId", "tenantId", "caseId", "assetId", "objectId", "operation", "params", "recipientId", "dataClass", "scopeVersion", "policyVersion", "evidenceVersion")
	if err != nil {
		return r, err
	}
	for name, dst := range map[string]*string{"agentId": &r.Agent, "tenantId": &r.Tenant, "caseId": &r.Case, "assetId": &r.Asset, "objectId": &r.Object, "operation": &r.Operation, "recipientId": &r.Recipient, "dataClass": &r.DataClass, "scopeVersion": &r.Scope, "policyVersion": &r.Policy} {
		if json.Unmarshal(fields[name], dst) != nil || *dst == "" || len(*dst) > 64 {
			return r, invalid
		}
	}
	params, err := object(fields["params"], "revision", "value")
	if err != nil || bytes.Equal(bytes.TrimSpace(fields["evidenceVersion"]), []byte("null")) || json.Unmarshal(fields["evidenceVersion"], &r.Evidence) != nil || r.Evidence != 1 {
		return r, invalid
	}
	if bytes.Equal(bytes.TrimSpace(params["revision"]), []byte("null")) || json.Unmarshal(params["revision"], &r.Params.Revision) != nil || r.Params.Revision != 1 || json.Unmarshal(params["value"], &r.Params.Value) != nil || len(r.Params.Value) > 32 {
		return r, invalid
	}
	r.Params.Value = strings.ToLower(strings.TrimSpace(r.Params.Value))
	if r.Params.Value != "ready" {
		return r, invalid
	}
	if r.Operation != "read_record" && r.Operation != "mark_reviewed" && r.Operation != "send_receipt" {
		return r, invalid
	}
	return r, nil
}

type identity struct{ agent, tenant string }
type grant struct {
	session string
	request request
	expires time.Time
}

// Counters are read from a separate fixture observer, never from executor receipts.
type Counters struct {
	Reads      int `json:"reads"`
	Marks      int `json:"marks"`
	Deliveries int `json:"deliveries"`
}
type effects struct {
	mu       sync.Mutex
	counts   Counters
	reviewed bool
	inboxes  map[string][]string
}

func (e *effects) apply(r request) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	switch r.Operation {
	case "read_record":
		e.counts.Reads++
	case "mark_reviewed":
		e.counts.Marks++
		e.reviewed = true
	case "send_receipt":
		e.counts.Deliveries++
		if e.inboxes == nil {
			e.inboxes = map[string][]string{}
		}
		e.inboxes[r.Recipient] = append(e.inboxes[r.Recipient], "synthetic_receipt")
	}
	if e.reviewed {
		return "reviewed"
	}
	return "pending"
}

func (e *effects) received(recipient string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.inboxes[recipient])
}
func (e *effects) snapshot() Counters { e.mu.Lock(); defer e.mu.Unlock(); return e.counts }
func delta(after, before Counters) Counters {
	return Counters{after.Reads - before.Reads, after.Marks - before.Marks, after.Deliveries - before.Deliveries}
}

type lab struct {
	mu        sync.Mutex
	protected bool
	sessions  map[string]identity
	grants    map[string]grant
	effects   effects
	server    *httptest.Server
	client    *http.Client
}

func opaque() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", errors.New("RANDOM_UNAVAILABLE")
	}
	return hex.EncodeToString(b[:]), nil
}
func newLab(protected bool) *lab {
	l := &lab{protected: protected, sessions: map[string]identity{}, grants: map[string]grant{}}
	l.server = httptest.NewUnstartedServer(http.HandlerFunc(l.serve))
	l.server.Config.ReadHeaderTimeout = time.Second
	l.server.Config.ReadTimeout = 2 * time.Second
	l.server.Config.WriteTimeout = 2 * time.Second
	l.server.Config.IdleTimeout = time.Second
	l.server.Config.MaxHeaderBytes = 1024
	l.server.Start() // httptest binds only to a literal loopback address.
	l.client = &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil, MaxConnsPerHost: 16}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("REDIRECT_DENIED") }}
	return l
}
func (l *lab) close() { l.client.CloseIdleConnections(); l.server.Close() }

// The trusted controller is outside HTTP. Tool text cannot call these methods.
func (l *lab) session(agent, tenant string) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.sessions) >= 4 {
		return "", errors.New("SESSION_LIMIT")
	}
	s, err := opaque()
	if err == nil {
		l.sessions[s] = identity{agent, tenant}
	}
	return s, err
}
func allowed(r request, who identity) bool {
	return who == (identity{"agent_alpha", "tenant_alpha"}) && r.Agent == who.agent && r.Tenant == who.tenant && r.Case == "case_alpha" && r.Asset == "asset_alpha" && r.Object == "record_alpha" && r.Recipient == "inbox_alpha" && r.DataClass == "synthetic" && r.Scope == "scope_1" && r.Policy == "policy_1" && r.Evidence == 1 && r.Params == (parameters{1, "ready"})
}
func (l *lab) issue(session string, r request, ttl time.Duration, approved bool) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	who, exists := l.sessions[session]
	if !exists || !allowed(r, who) || (r.Operation != "read_record" && !approved) || ttl <= 0 || ttl > time.Minute || len(l.grants) >= 128 {
		return "", errors.New("GRANT_DENIED")
	}
	if r.Operation != "read_record" && r.Operation != "mark_reviewed" && r.Operation != "send_receipt" {
		return "", invalid
	}
	g, err := opaque()
	if err == nil {
		l.grants[g] = grant{session, r, time.Now().Add(ttl)}
	}
	return g, err
}

func singleHeader(r *http.Request, name string) string {
	values := r.Header.Values(name)
	if len(values) != 1 || len(values[0]) != 64 {
		return ""
	}
	return values[0]
}
func (l *lab) authorize(session, token string, r request) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	who, exists := l.sessions[session]
	g, known := l.grants[token]
	if !exists || !known || !allowed(r, who) || g.session != session || g.request != r || !time.Now().Before(g.expires) {
		return false
	}
	delete(l.grants, token) // Atomic consume precedes the only fixed effect; no retry.
	return true
}

func (l *lab) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost || r.URL.Path != "/tool" || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(400)
		io.WriteString(w, `{"code":"INVALID_REQUEST"}`)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		w.WriteHeader(400)
		io.WriteString(w, `{"code":"INVALID_REQUEST"}`)
		return
	}
	proposal, err := decode(body)
	if err != nil {
		w.WriteHeader(400)
		io.WriteString(w, `{"code":"INVALID_REQUEST"}`)
		return
	}
	if l.protected && !l.authorize(singleHeader(r, "X-Lab-Session"), singleHeader(r, "X-Lab-Grant"), proposal) {
		w.WriteHeader(403)
		io.WriteString(w, `{"code":"DENIED"}`)
		return
	}
	value := l.effects.apply(proposal)
	json.NewEncoder(w).Encode(map[string]any{"code": "COMPLETED", "synthetic": true, "value": value})
}

type response struct {
	Code      string `json:"code"`
	Synthetic bool   `json:"synthetic"`
	Value     string `json:"value"`
}

func (l *lab) call(session, token string, data []byte) (int, response, error) {
	result := response{}
	r, err := http.NewRequest(http.MethodPost, l.server.URL+"/tool", bytes.NewReader(data))
	if err != nil {
		return 0, result, errors.New("LAB_REQUEST_FAILED")
	}
	r.Header.Set("Content-Type", "application/json")
	if session != "" {
		r.Header.Set("X-Lab-Session", session)
	}
	if token != "" {
		r.Header.Set("X-Lab-Grant", token)
	}
	res, err := l.client.Do(r)
	if err != nil {
		return 0, result, errors.New("LAB_HTTP_FAILED")
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1025))
	if err != nil || len(body) > 1024 || json.Unmarshal(body, &result) != nil {
		return 0, result, errors.New("LAB_RESPONSE_FAILED")
	}
	return res.StatusCode, result, nil
}

func (l *lab) post(session, token string, data []byte) (int, error) {
	status, _, err := l.call(session, token, data)
	return status, err
}
func encode(r request) []byte { data, _ := json.Marshal(r); return data }
