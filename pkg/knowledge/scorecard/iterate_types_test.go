/*
Copyright (c) 2026 Security Research
*/
package scorecard

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDefaultIterateOptions(t *testing.T) {
	got := DefaultIterateOptions()
	want := IterateOptions{
		MaxIter:        5,
		Threshold:      80,
		RequireAll12:   true,
		PerIterTimeout: 4 * time.Minute,
	}
	if got != want {
		t.Fatalf("DefaultIterateOptions = %+v, want %+v", got, want)
	}
}

// TestIterationRecordJSONRoundTrip exercises B1 (rich-shape schema fidelity).
// Every snake_case field must be present and decode back equal.
func TestIterationRecordJSONRoundTrip(t *testing.T) {
	in := IterationRecord{
		ID:       "iter-1",
		Iter:     1,
		TS:       "2026-05-07T12:34:56Z",
		WeakDims: []string{"wire", "auth", "ipc", "state_machines"},
		Dispatched: []DispatchResult{
			{Pass: "wire", TargetDims: []string{"wire"}, DurationMs: 3200, FramesCaptured: 42, OK: true, Note: ""},
			{Pass: "auth", TargetDims: []string{"auth"}, DurationMs: 100, FramesCaptured: 0, OK: false, Note: "no frames"},
		},
		Bumps:                     map[string]int{"wire": 85, "auth": 80, "ipc": 80, "state_machines": 80},
		Mean:                      72,
		Coverage:                  7,
		PostMean:                  81,
		PostCoverage:              12,
		RuntimeCaptureUnavailable: false,
		CitationsOK:               false,
	}

	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	for _, field := range []string{
		`"id":"iter-1"`,
		`"iter":1`,
		`"ts":"2026-05-07T12:34:56Z"`,
		`"weak_dims"`,
		`"dispatched"`,
		`"bumps"`,
		`"mean":72`,
		`"coverage":7`,
		`"post_mean":81`,
		`"post_coverage":12`,
		`"runtime_capture_unavailable":false`,
		`"citations_ok":false`,
		`"target_dims"`,
		`"duration_ms":3200`,
		`"frames_captured":42`,
		`"ok":true`,
		`"note":""`,
	} {
		if !strings.Contains(s, field) {
			t.Errorf("missing snake_case field %s in %s", field, s)
		}
	}

	var out IterationRecord
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round-trip mismatch:\n in: %+v\nout: %+v", in, out)
	}
}

// TestDispatchResultIsStructured asserts B1: dispatched entries are structured
// objects, not bare strings.
func TestDispatchResultIsStructured(t *testing.T) {
	dr := DispatchResult{Pass: "wire", TargetDims: []string{"wire"}, OK: true}
	b, _ := json.Marshal(dr)
	if !strings.HasPrefix(string(b), "{") {
		t.Fatalf("DispatchResult must marshal as object, got %s", b)
	}
}
