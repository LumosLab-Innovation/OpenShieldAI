package correlation

import (
	"encoding/json"
	"fmt"
	"testing"
)

func fixture(size int) []byte {
	events := []any{}
	for i := 0; i < size; i++ {
		events = append(events, map[string]any{"schemaVersion": "lab_event_v1", "id": fmt.Sprintf("event_%d", i),
			"projectId": "project_a", "caseId": "case_a", "assetId": "asset_a", "sourceId": "source_a",
			"observedAt": "2026-10-24T03:00:30Z", "kind": "auth_decision", "dataClass": "synthetic",
			"facts": map[string]any{"decision": "deny", "subjectLabel": fmt.Sprintf("subject_%d", i/10), "objectLabel": "object_a"}})
	}
	data, _ := json.Marshal(map[string]any{"schemaVersion": "correlation_request_v1", "projectId": "project_a", "caseId": "case_a",
		"assetId": "asset_a", "runId": "run_a", "scopeVersion": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"asOf": "2026-10-24T03:01:00Z", "sourceIds": []string{"source_a"}, "upstreamGaps": []string{}, "events": events})
	return data
}

func TestAnalyze(t *testing.T) {
	result, err := Analyze(fixture(10))
	if err != nil || len(result.Candidates) != 1 || result.Candidates[0].Count != 10 || result.IsFinding || result.Coverage.Complete {
		t.Fatalf("unexpected bounded rule result: %v", err)
	}
}

func TestInvalidDocuments(t *testing.T) {
	for _, data := range [][]byte{[]byte(`null`), []byte(`{"x":1,"x":2}`), []byte(`{} {}`), make([]byte, MaxInput+1)} {
		if _, err := Analyze(data); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
}

func TestOutputBoundAndStableReplay(t *testing.T) {
	data := fixture(1000)
	first, err := Analyze(data)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Analyze(data)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if len(a)+1 > MaxOutput || string(a) != string(b) || first.Status != "partial" {
		t.Fatal("bound/determinism failed")
	}
}

func FuzzAnalyze(f *testing.F) {
	f.Add(fixture(10))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		result, err := Analyze(data)
		if err == nil {
			encoded, _ := json.Marshal(result)
			if result.IsFinding || result.Coverage.Complete || len(encoded)+1 > MaxOutput {
				t.Fatal("authority/output invariant")
			}
		}
	})
}

func BenchmarkAnalyze1000(b *testing.B) {
	data := fixture(1000)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Analyze(data); err != nil {
			b.Fatal(err)
		}
	}
}
