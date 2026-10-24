// Package flowlab exercises fixed synthetic application effects over loopback HTTP.
package flowlab

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

const maxBody = 1024

type operation struct {
	Operation string `json:"operation"`
	Object    string `json:"objectId"`
	Key       string `json:"idempotencyKey"`
	Units     int    `json:"units"`
	Recipient string `json:"recipientId"`
	DataClass string `json:"dataClass"`
}

// Exact fields and duplicate rejection prevent aliases from changing authority.
func fields(data []byte, names ...string) (map[string]json.RawMessage, error) {
	bad := errors.New("INVALID_REQUEST")
	if len(data) > maxBody || !utf8.Valid(data) {
		return nil, bad
	}
	d := json.NewDecoder(bytes.NewReader(data))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return nil, bad
	}
	result := map[string]json.RawMessage{}
	for d.More() {
		t, err = d.Token()
		name, ok := t.(string)
		if err != nil || !ok {
			return nil, bad
		}
		found := false
		for _, expected := range names {
			if name == expected {
				found = true
			}
		}
		if !found || result[name] != nil {
			return nil, bad
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, bad
		}
		result[name] = value
	}
	if t, err = d.Token(); err != nil || t != json.Delim('}') || len(result) != len(names) {
		return nil, bad
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, bad
	}
	return result, nil
}

func decode(data []byte) (operation, error) {
	var op operation
	f, err := fields(data, "operation", "objectId", "idempotencyKey", "units", "recipientId", "dataClass")
	if err != nil {
		return op, err
	}
	for name, target := range map[string]*string{"operation": &op.Operation, "objectId": &op.Object, "idempotencyKey": &op.Key, "recipientId": &op.Recipient, "dataClass": &op.DataClass} {
		if bytes.Equal(bytes.TrimSpace(f[name]), []byte("null")) || json.Unmarshal(f[name], target) != nil || len(*target) > 40 {
			return op, errors.New("INVALID_REQUEST")
		}
	}
	if bytes.Equal(bytes.TrimSpace(f["units"]), []byte("null")) || json.Unmarshal(f["units"], &op.Units) != nil || op.DataClass != "synthetic" {
		return op, errors.New("INVALID_REQUEST")
	}
	if op.Object != "object_alpha" && op.Object != "object_beta" {
		return op, errors.New("INVALID_REQUEST")
	}
	switch op.Operation {
	case "read":
		if op.Key != "" || op.Units != 0 || op.Recipient != "" {
			return op, errors.New("INVALID_REQUEST")
		}
	case "charge":
		if !strings.HasPrefix(op.Key, "tx_") || len(op.Key) < 4 || op.Units < 1 || op.Units > 2 || op.Recipient != "" {
			return op, errors.New("INVALID_REQUEST")
		}
		for _, c := range op.Key {
			if c != '_' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
				return op, errors.New("INVALID_REQUEST")
			}
		}
	case "export":
		if op.Key != "" || op.Units != 0 || (op.Recipient != "inbox_alpha" && op.Recipient != "inbox_outside") {
			return op, errors.New("INVALID_REQUEST")
		}
	default:
		return op, errors.New("INVALID_REQUEST")
	}
	return op, nil
}

type session struct {
	principal string
	active    bool
	expires   time.Time
}
type capability struct {
	session string
	op      operation
	expires time.Time
}
type attemptWindow struct {
	start    time.Time
	failures int
}
type pauseHook struct {
	entered chan struct{}
	release chan struct{}
}

type Effects struct {
	Reads        int `json:"reads"`
	Charges      int `json:"charges"`
	ChargedUnits int `json:"chargedUnits"`
}
type ledger struct {
	mu      sync.Mutex
	effects Effects
	rows    []operation
}

func (l *ledger) snapshot() Effects { l.mu.Lock(); defer l.mu.Unlock(); return l.effects }
func (l *ledger) apply(op operation) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if op.Operation == "read" {
		l.effects.Reads++
	}
	if op.Operation == "charge" {
		l.rows = append(l.rows, op)
		l.effects.Charges++
		l.effects.ChargedUnits += op.Units
	}
}
func (l *ledger) rowCount(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, row := range l.rows {
		if row.Key == key {
			n++
		}
	}
	return n
}

type receivers struct {
	mu                                sync.Mutex
	redirect                          bool
	allowed, outside, outsideRequests int
}

func (r *receivers) snapshot() (int, int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.allowed, r.outside, r.outsideRequests
}

// shortcut: sessions, grants and idempotency records are ephemeral; production and restart claims require a separately accepted durable application adapter.
type lab struct {
	mu                     sync.Mutex
	protected              bool
	now                    time.Time
	sessions               map[string]session
	cache                  map[string]session
	grants                 map[string]capability
	attempts               map[string]attemptWindow
	checks, totalAttempts  int
	spent                  map[string]int
	transactions           map[string]operation
	ledger                 ledger
	receivers              receivers
	pause                  *pauseHook
	workers                chan struct{}
	server, inbox, outside *httptest.Server
	client, broker         *http.Client
}

func opaque() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", errors.New("RANDOM_UNAVAILABLE")
	}
	return hex.EncodeToString(b[:]), nil
}
func client(follow bool) *http.Client {
	c := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil, MaxConnsPerHost: 16}}
	if !follow {
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("REDIRECT_DENIED") }
	}
	return c
}
func server(handler http.HandlerFunc) *httptest.Server {
	s := httptest.NewUnstartedServer(handler)
	s.Config.ReadHeaderTimeout = time.Second
	s.Config.ReadTimeout = 2 * time.Second
	s.Config.WriteTimeout = 2 * time.Second
	s.Config.IdleTimeout = time.Second
	s.Config.MaxHeaderBytes = 1024
	s.Start()
	return s
}
func newLab(protected bool) *lab {
	l := &lab{protected: protected, now: time.Now(), sessions: map[string]session{}, cache: map[string]session{}, grants: map[string]capability{}, attempts: map[string]attemptWindow{}, spent: map[string]int{}, transactions: map[string]operation{}, workers: make(chan struct{}, 4)}
	l.client, l.broker = client(false), client(!protected)
	l.outside = server(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 65))
		l.receivers.mu.Lock()
		defer l.receivers.mu.Unlock()
		l.receivers.outsideRequests++
		if string(body) == `{"data":"synthetic-record"}` {
			l.receivers.outside++
		}
		w.WriteHeader(204)
	})
	l.inbox = server(func(w http.ResponseWriter, r *http.Request) {
		l.receivers.mu.Lock()
		redirect := l.receivers.redirect
		l.receivers.mu.Unlock()
		if redirect {
			w.Header().Set("Location", l.outside.URL+"/sink")
			w.WriteHeader(307)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 65))
		if string(body) != `{"data":"synthetic-record"}` {
			w.WriteHeader(400)
			return
		}
		l.receivers.mu.Lock()
		l.receivers.allowed++
		l.receivers.mu.Unlock()
		w.WriteHeader(204)
	})
	l.server = server(l.serve)
	return l
}
func (l *lab) close() {
	l.client.CloseIdleConnections()
	l.broker.CloseIdleConnections()
	l.server.Close()
	l.inbox.Close()
	l.outside.Close()
}
func (l *lab) advance(d time.Duration) { l.mu.Lock(); defer l.mu.Unlock(); l.now = l.now.Add(d) }
func (l *lab) authChecks() int         { l.mu.Lock(); defer l.mu.Unlock(); return l.checks }
func principalObject(principal, object string) bool {
	return principal == "principal_alpha" && object == "object_alpha" || principal == "principal_beta" && object == "object_beta"
}

// Trusted controller methods are absent from the HTTP route catalog.
func (l *lab) session(principal string) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sessionLocked(principal)
}
func (l *lab) sessionLocked(principal string) (string, error) {
	if principal != "principal_alpha" && principal != "principal_beta" {
		return "", errors.New("DENIED")
	}
	if len(l.sessions) >= 16 {
		return "", errors.New("SESSION_LIMIT")
	}
	n := 0
	for _, s := range l.sessions {
		if s.principal == principal {
			n++
		}
	}
	if n >= 8 {
		return "", errors.New("SESSION_LIMIT")
	}
	t, err := opaque()
	if err == nil {
		l.sessions[t] = session{principal, true, l.now.Add(time.Minute)}
	}
	return t, err
}
func (l *lab) revoke(token string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s, ok := l.sessions[token]
	if ok {
		s.active = false
		l.sessions[token] = s
	}
}
func (l *lab) issue(token string, op operation, approved bool) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s, ok := l.sessions[token]
	if !ok || !s.active || !l.now.Before(s.expires) || !principalObject(s.principal, op.Object) || op.Operation == "read" || !approved || op.Recipient == "inbox_outside" || len(l.grants) >= 64 {
		return "", errors.New("GRANT_DENIED")
	}
	if _, err := decode(encode(op)); err != nil {
		return "", errors.New("GRANT_DENIED")
	}
	g, err := opaque()
	if err == nil {
		l.grants[g] = capability{token, op, l.now.Add(30 * time.Second)}
	}
	return g, err
}
func single(r *http.Request, name string) string {
	v := r.Header.Values(name)
	if len(v) != 1 || len(v[0]) != 64 {
		return ""
	}
	return v[0]
}
func (l *lab) identityLocked(path, token string) (session, bool) {
	if !l.protected && path == "/v2/resource" {
		if s, ok := l.cache[token]; ok {
			return s, l.now.Before(s.expires)
		}
	}
	s, ok := l.sessions[token]
	ok = ok && s.active && l.now.Before(s.expires)
	if ok && !l.protected && path == "/v2/resource" {
		l.cache[token] = s
	}
	return s, ok
}
func (l *lab) login(data []byte) (int, string) {
	f, err := fields(data, "principalId", "proofClass")
	if err != nil {
		return 400, ""
	}
	var principal, proof string
	if json.Unmarshal(f["principalId"], &principal) != nil || json.Unmarshal(f["proofClass"], &proof) != nil || (principal != "principal_alpha" && principal != "principal_beta") || (proof != "accepted_fixture" && proof != "rejected_fixture") {
		return 400, ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.attempts[principal]
	if w.start.IsZero() || l.now.Sub(w.start) >= time.Minute {
		w = attemptWindow{start: l.now}
	}
	if l.protected && (w.failures >= 3 || l.totalAttempts >= 24) {
		return 429, ""
	}
	l.totalAttempts++
	l.checks++
	if proof == "rejected_fixture" {
		w.failures++
		l.attempts[principal] = w
		return 401, ""
	}
	l.attempts[principal] = w
	token, err := l.sessionLocked(principal)
	if err != nil {
		return 429, ""
	}
	return 200, token
}
func reply(w http.ResponseWriter, status int, token string) {
	w.WriteHeader(status)
	if token != "" {
		json.NewEncoder(w).Encode(map[string]string{"session": token})
	} else {
		io.WriteString(w, `{"synthetic":true}`)
	}
}
func (l *lab) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	select {
	case l.workers <- struct{}{}:
		defer func() { <-l.workers }()
	default:
		reply(w, 429, "")
		return
	}
	if r.Method != "POST" || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" {
		reply(w, 400, "")
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		reply(w, 400, "")
		return
	}
	if r.URL.Path == "/login" {
		status, token := l.login(data)
		reply(w, status, token)
		return
	}
	if r.URL.Path != "/v1/resource" && r.URL.Path != "/v2/resource" {
		reply(w, 400, "")
		return
	}
	op, err := decode(data)
	if err != nil {
		reply(w, 400, "")
		return
	}
	token := single(r, "X-Flow-Session")
	grant := single(r, "X-Flow-Grant")
	l.mu.Lock()
	who, ok := l.identityLocked(r.URL.Path, token)
	pause := l.pause
	l.pause = nil
	l.mu.Unlock()
	if !ok {
		reply(w, 403, "")
		return
	}
	if pause != nil {
		close(pause.entered)
		select {
		case <-pause.release:
		case <-r.Context().Done():
			return
		case <-time.After(time.Second):
			reply(w, 503, "")
			return
		}
	}
	l.mu.Lock()
	if l.protected {
		who, ok = l.identityLocked(r.URL.Path, token)
	}
	if !ok || l.protected && !principalObject(who.principal, op.Object) {
		l.mu.Unlock()
		reply(w, 403, "")
		return
	}
	if op.Operation == "read" {
		if l.protected && l.spent[who.principal] >= 8 {
			l.mu.Unlock()
			reply(w, 429, "")
			return
		}
		l.spent[who.principal]++
		l.ledger.apply(op)
		l.mu.Unlock()
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]string{"objectValue": "synthetic_" + strings.TrimPrefix(op.Object, "object_")})
		return
	}
	if l.protected {
		g, exists := l.grants[grant]
		if !exists || g.session != token || g.op != op || !l.now.Before(g.expires) || op.Recipient == "inbox_outside" {
			l.mu.Unlock()
			reply(w, 403, "")
			return
		}
		delete(l.grants, grant)
	}
	if op.Operation == "charge" {
		key := who.principal + ":" + op.Key
		if previous, exists := l.transactions[key]; l.protected && exists {
			l.mu.Unlock()
			if previous != op {
				reply(w, 409, "")
			} else {
				reply(w, 200, "")
			}
			return
		}
		if len(l.transactions) >= 32 {
			l.mu.Unlock()
			reply(w, 429, "")
			return
		}
		l.transactions[key] = op
		l.ledger.apply(op)
		l.mu.Unlock()
		reply(w, 200, "")
		return
	}
	l.mu.Unlock()
	// Only fixed enrolled receiver IDs exist; neither request nor model supplies a URL.
	url := l.inbox.URL + "/deliver"
	if op.Recipient == "inbox_outside" {
		url = l.outside.URL + "/sink"
	}
	req, _ := http.NewRequestWithContext(r.Context(), "POST", url, strings.NewReader(`{"data":"synthetic-record"}`))
	req.Header.Set("Content-Type", "application/json")
	res, err := l.broker.Do(req)
	if res != nil {
		res.Body.Close()
	}
	if err != nil || res.StatusCode != 204 {
		reply(w, 502, "")
		return
	}
	reply(w, 200, "")
}

func encode(op operation) []byte { data, _ := json.Marshal(op); return data }
func sample(name string) operation {
	return operation{Operation: name, Object: "object_alpha", DataClass: "synthetic"}
}

type response struct {
	status      int
	token       string
	objectValue string
}

func (l *lab) post(path, token, grant string, data []byte) (response, error) {
	r, err := http.NewRequest("POST", l.server.URL+path, bytes.NewReader(data))
	if err != nil {
		return response{}, errors.New("REQUEST_FAILED")
	}
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("X-Flow-Session", token)
	}
	if grant != "" {
		r.Header.Set("X-Flow-Grant", grant)
	}
	res, err := l.client.Do(r)
	if err != nil {
		return response{}, errors.New("HTTP_FAILED")
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1025))
	var result map[string]json.RawMessage
	if err != nil || len(body) > 1024 || json.Unmarshal(body, &result) != nil {
		return response{}, errors.New("RESPONSE_FAILED")
	}
	var session string
	if result["session"] != nil && json.Unmarshal(result["session"], &session) != nil {
		return response{}, errors.New("RESPONSE_FAILED")
	}
	var objectValue string
	if result["objectValue"] != nil && json.Unmarshal(result["objectValue"], &objectValue) != nil {
		return response{}, errors.New("RESPONSE_FAILED")
	}
	return response{res.StatusCode, session, objectValue}, nil
}
