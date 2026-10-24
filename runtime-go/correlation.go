// Package correlation produces bounded synthetic access candidates, never actions.
package correlation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"time"
	"unicode/utf8"
)

const MaxInput = 1 << 20
const MaxOutput = 64 << 10
const RuleVersion = "access_window_v1"

var invalid = errors.New("INVALID_REQUEST")
var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
var secretPattern = regexp.MustCompile(`(?i)^(sk-|gh[pousr]_|github_pat_|AIza|Bearer)`)
var timePattern = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$`)
var hashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Candidate struct {
	Code      string   `json:"code"`
	Subject   string   `json:"subjectLabel"`
	Object    string   `json:"objectLabel"`
	Evidence  []string `json:"evidenceIds"`
	Count     int      `json:"observedCount"`
	Truncated bool     `json:"evidenceTruncated"`
	IsFinding bool     `json:"isFinding"`
}

type Counts struct {
	Input      int `json:"inputEvents"`
	Unique     int `json:"uniqueEvents"`
	Duplicates int `json:"duplicateEvents"`
	Window     int `json:"windowEvents"`
	Old        int `json:"oldEvents"`
	Future     int `json:"futureEvents"`
}

type Coverage struct {
	Complete bool     `json:"complete"`
	Gaps     []string `json:"gaps"`
	Sources  []string `json:"sourcesObserved"`
}

type Result struct {
	Schema      string      `json:"schemaVersion"`
	Status      string      `json:"status"`
	Rule        string      `json:"ruleVersion"`
	Run         string      `json:"runId"`
	Project     string      `json:"projectId"`
	Case        string      `json:"caseId"`
	Asset       string      `json:"assetId"`
	Scope       string      `json:"scopeVersion"`
	InputHash   string      `json:"inputSha256"`
	AsOf        string      `json:"asOf"`
	Window      int         `json:"windowSeconds"`
	Counts      Counts      `json:"counts"`
	Candidates  []Candidate `json:"candidates"`
	Coverage    Coverage    `json:"coverage"`
	Limitations []string    `json:"limitations"`
	IsFinding   bool        `json:"isFinding"`
}

type event struct {
	id, source, kind, decision, subject, object string
	at                                          time.Time
	available                                   bool
	dropped                                     int64
}

// Token parsing rejects duplicate names before maps can overwrite them. Exact
// field validation also avoids encoding/json's case-insensitive struct matching.
func value(dec *json.Decoder, depth int, nodes *int, deadline time.Time) (any, error) {
	(*nodes)++
	if depth > 16 || *nodes > 60000 {
		return nil, invalid
	}
	if time.Now().After(deadline) {
		return nil, errors.New("DEADLINE_EXCEEDED")
	}
	token, err := dec.Token()
	if err != nil {
		return nil, invalid
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return token, nil
	}
	switch delimiter {
	case '{':
		result := map[string]any{}
		for dec.More() {
			key, err := dec.Token()
			name, ok := key.(string)
			if err != nil || !ok {
				return nil, invalid
			}
			if _, exists := result[name]; exists {
				return nil, invalid
			}
			item, err := value(dec, depth+1, nodes, deadline)
			if err != nil {
				return nil, err
			}
			result[name] = item
		}
		if closing, err := dec.Token(); err != nil || closing != json.Delim('}') {
			return nil, invalid
		}
		return result, nil
	case '[':
		result := []any{}
		for dec.More() {
			item, err := value(dec, depth+1, nodes, deadline)
			if err != nil {
				return nil, err
			}
			result = append(result, item)
		}
		if closing, err := dec.Token(); err != nil || closing != json.Delim(']') {
			return nil, invalid
		}
		return result, nil
	}
	return nil, invalid
}

func fields(input any, required []string, optional ...string) (map[string]any, error) {
	result, ok := input.(map[string]any)
	if !ok {
		return nil, invalid
	}
	allowed := map[string]bool{}
	for _, name := range required {
		allowed[name] = true
		if _, ok := result[name]; !ok {
			return nil, invalid
		}
	}
	for _, name := range optional {
		allowed[name] = true
	}
	for name := range result {
		if !allowed[name] {
			return nil, invalid
		}
	}
	return result, nil
}

func text(value any) string { result, _ := value.(string); return result }
func id(value any) bool {
	s, ok := value.(string)
	return ok && idPattern.MatchString(s) && !secretPattern.MatchString(s)
}
func instant(value any) (time.Time, error) {
	s := text(value)
	if !timePattern.MatchString(s) {
		return time.Time{}, invalid
	}
	at, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || at.Year() < 1 {
		return time.Time{}, invalid
	}
	return at, nil
}

func parseEvent(input any, req map[string]any, sources map[string]bool) (event, error) {
	e := event{}
	row, err := fields(input, []string{"schemaVersion", "id", "projectId", "caseId", "assetId", "sourceId", "observedAt", "kind", "facts", "dataClass"}, "receivedAt")
	if err != nil {
		return e, err
	}
	if text(row["schemaVersion"]) != "lab_event_v1" || text(row["dataClass"]) != "synthetic" {
		return e, invalid
	}
	for _, key := range []string{"id", "projectId", "caseId", "assetId", "sourceId"} {
		if !id(row[key]) {
			return e, invalid
		}
	}
	for _, key := range []string{"projectId", "caseId", "assetId"} {
		if row[key] != req[key] {
			return e, invalid
		}
	}
	if !sources[text(row["sourceId"])] {
		return e, invalid
	}
	e.at, err = instant(row["observedAt"])
	if err != nil {
		return e, err
	}
	if at, exists := row["receivedAt"]; exists {
		if _, err := instant(at); err != nil {
			return e, err
		}
	}
	e.id, e.source, e.kind = text(row["id"]), text(row["sourceId"]), text(row["kind"])
	switch e.kind {
	case "auth_decision":
		facts, err := fields(row["facts"], []string{"decision", "subjectLabel", "objectLabel"})
		if err != nil || !id(facts["subjectLabel"]) || !id(facts["objectLabel"]) {
			return e, invalid
		}
		e.decision, e.subject, e.object = text(facts["decision"]), text(facts["subjectLabel"]), text(facts["objectLabel"])
		if e.decision != "allow" && e.decision != "deny" {
			return e, invalid
		}
	case "source_health":
		facts, err := fields(row["facts"], []string{"available", "dropped"})
		if err != nil {
			return e, invalid
		}
		available, ok := facts["available"].(bool)
		dropped, number := facts["dropped"].(json.Number)
		if !ok || !number {
			return e, invalid
		}
		count, err := dropped.Int64()
		if err != nil || count < 0 || count > 1000000 {
			return e, invalid
		}
		e.available, e.dropped = available, count
	default:
		return e, invalid
	}
	return e, nil
}

func Analyze(data []byte) (*Result, error) {
	if len(data) > MaxInput {
		return nil, errors.New("INPUT_LIMIT")
	}
	if !utf8.Valid(data) {
		return nil, invalid
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	nodes := 0
	raw, err := value(dec, 0, &nodes, deadline)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, invalid
	}
	req, err := fields(raw, []string{"schemaVersion", "projectId", "caseId", "assetId", "runId", "scopeVersion", "asOf", "sourceIds", "upstreamGaps", "events"})
	if err != nil || text(req["schemaVersion"]) != "correlation_request_v1" {
		return nil, invalid
	}
	for _, key := range []string{"projectId", "caseId", "assetId", "runId"} {
		if !id(req[key]) {
			return nil, invalid
		}
	}
	if !hashPattern.MatchString(text(req["scopeVersion"])) {
		return nil, invalid
	}
	asOf, err := instant(req["asOf"])
	if err != nil {
		return nil, err
	}
	sources := map[string]bool{}
	ids, ok := req["sourceIds"].([]any)
	if !ok || len(ids) < 1 || len(ids) > 16 {
		return nil, invalid
	}
	for _, item := range ids {
		if !id(item) || sources[text(item)] {
			return nil, invalid
		}
		sources[text(item)] = true
	}
	upstream, ok := req["upstreamGaps"].([]any)
	if !ok || len(upstream) > 4 {
		return nil, invalid
	}
	gaps := map[string]bool{}
	for _, item := range upstream {
		name := text(item)
		switch name {
		case "stale_evidence", "visibility_gap", "source_clock_skew", "no_independent_observer":
		default:
			return nil, invalid
		}
		if gaps["upstream_"+name] {
			return nil, invalid
		}
		gaps["upstream_"+name] = true
	}
	input, ok := req["events"].([]any)
	if !ok || len(input) > 1000 {
		return nil, invalid
	}
	sum := sha256.Sum256(data)
	result := &Result{Schema: "correlation_result_v1", Status: "succeeded", Rule: RuleVersion,
		Run: text(req["runId"]), Project: text(req["projectId"]), Case: text(req["caseId"]), Asset: text(req["assetId"]), Scope: text(req["scopeVersion"]),
		InputHash: hex.EncodeToString(sum[:]), AsOf: text(req["asOf"]), Window: 60,
		Candidates: []Candidate{}, Coverage: Coverage{Gaps: []string{}, Sources: []string{}},
		Limitations: []string{"synthetic_lab_only", "authorization_not_authentication", "candidate_not_compromise", "source_authentication_unverified", "fixed_threshold_uncalibrated", "bounded_window", "no_actuator"}}
	result.Counts.Input = len(input)
	observed := map[string]bool{}
	seen := map[string]string{}
	events := []event{}
	start := asOf.Add(-60 * time.Second)
	for _, row := range input {
		if time.Now().After(deadline) {
			return nil, errors.New("DEADLINE_EXCEEDED")
		}
		e, err := parseEvent(row, req, sources)
		if err != nil {
			return nil, err
		}
		canonical, _ := json.Marshal(row)
		if previous, exists := seen[e.id]; exists {
			if previous != string(canonical) {
				return nil, invalid
			}
			result.Counts.Duplicates++
			continue
		}
		seen[e.id] = string(canonical)
		result.Counts.Unique++
		if e.at.After(asOf) {
			result.Counts.Future++
			gaps["future_event"] = true
			continue
		}
		if e.kind == "source_health" {
			if !e.available {
				gaps["source_unavailable"] = true
			}
			if e.dropped > 0 {
				gaps["source_events_dropped"] = true
			}
		}
		if !e.at.After(start) {
			result.Counts.Old++
			continue
		}
		observed[e.source] = true
		result.Counts.Window++
		if e.kind == "auth_decision" {
			events = append(events, e)
		}
	}
	for source := range sources {
		if !observed[source] {
			gaps["source_missing"] = true
		}
	}
	if result.Counts.Window == 0 {
		gaps["empty_window"] = true
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].at.Equal(events[j].at) {
			return events[i].id < events[j].id
		}
		return events[i].at.Before(events[j].at)
	})
	groups := map[string][]event{}
	for _, e := range events {
		key := e.subject + "\x00" + e.object
		groups[key] = append(groups[key], e)
	}
	keys := []string{}
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	add := func(code string, records []event) {
		if len(result.Candidates) >= 64 {
			gaps["candidate_limit"] = true
			return
		}
		refs := []string{}
		for _, record := range records {
			refs = append(refs, record.id)
		}
		truncated := len(refs) > 20
		if truncated {
			refs = append(refs[:19], refs[len(refs)-1])
			gaps["evidence_limit"] = true
		}
		result.Candidates = append(result.Candidates, Candidate{Code: code, Subject: records[0].subject, Object: records[0].object, Evidence: refs, Count: len(records), Truncated: truncated})
	}
	for _, key := range keys {
		denies := []event{}
		group := groups[key]
		ties := map[string]int{}
		for _, e := range group {
			stamp := e.at.Format(time.RFC3339Nano)
			if e.decision == "deny" {
				ties[stamp] |= 1
			} else {
				ties[stamp] |= 2
			}
			if ties[stamp] == 3 {
				gaps["same_timestamp_order_unknown"] = true
			}
		}
		sequenceAdded := false
		for _, e := range group {
			if e.decision == "deny" {
				denies = append(denies, e)
				continue
			}
			earlier := []event{}
			for _, denied := range denies {
				if denied.at.Before(e.at) {
					earlier = append(earlier, denied)
				} else {
					gaps["same_timestamp_order_unknown"] = true
				}
			}
			if len(earlier) >= 3 && !sequenceAdded {
				add("denied_access_then_allow", append(earlier, e))
				sequenceAdded = true
			}
		}
		if len(denies) >= 5 {
			add("repeated_access_denials", denies)
		}
	}
	for name := range gaps {
		result.Coverage.Gaps = append(result.Coverage.Gaps, name)
	}
	for name := range observed {
		result.Coverage.Sources = append(result.Coverage.Sources, name)
	}
	sort.Strings(result.Coverage.Gaps)
	sort.Strings(result.Coverage.Sources)
	if len(gaps) > 0 {
		result.Status = "partial"
	}
	for {
		encoded, err := json.Marshal(result)
		if err != nil {
			return nil, errors.New("INTERNAL_ERROR")
		}
		if len(encoded)+1 <= MaxOutput {
			break
		}
		if len(result.Candidates) == 0 {
			return nil, errors.New("INTERNAL_ERROR")
		}
		result.Candidates = result.Candidates[:len(result.Candidates)-1]
		if !gaps["candidate_limit"] {
			gaps["candidate_limit"] = true
			result.Coverage.Gaps = append(result.Coverage.Gaps, "candidate_limit")
			sort.Strings(result.Coverage.Gaps)
		}
		result.Status = "partial"
	}
	if time.Now().After(deadline) {
		return nil, errors.New("DEADLINE_EXCEEDED")
	}
	return result, nil
}
