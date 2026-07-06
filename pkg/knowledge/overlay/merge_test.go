/*
Copyright (c) 2026 Security Research
*/

package overlay

import (
	"reflect"
	"testing"
	"time"
)

var (
	sTS = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	lTS = time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	opt = Options{StaticTS: sTS, LiveTS: lTS}
)

func TestMerge_StaticOnlyLeaf(t *testing.T) {
	static := map[string]any{"k": "v"}
	live := map[string]any{}
	got := Merge(static, live, opt).(map[string]any)
	leaf := got["k"].(map[string]any)
	if leaf["_source"].(string) != "static" {
		t.Fatalf("source=%v want static", leaf["_source"])
	}
	if leaf["_value"].(string) != "v" {
		t.Fatalf("value=%v want v", leaf["_value"])
	}
}

func TestMerge_LiveOnlyLeaf(t *testing.T) {
	static := map[string]any{}
	live := map[string]any{"k": "v"}
	got := Merge(static, live, opt).(map[string]any)
	leaf := got["k"].(map[string]any)
	if leaf["_source"].(string) != "live" {
		t.Fatalf("source=%v want live", leaf["_source"])
	}
}

func TestMerge_BothEqualLeaf(t *testing.T) {
	static := map[string]any{"k": "v"}
	live := map[string]any{"k": "v"}
	got := Merge(static, live, opt).(map[string]any)
	leaf := got["k"].(map[string]any)
	if leaf["_source"].(string) != "both" {
		t.Fatalf("source=%v want both", leaf["_source"])
	}
	if _, ok := leaf["_static_value"]; ok {
		t.Fatal("expected no _static_value when equal")
	}
}

func TestMerge_BothDifferentLeaf(t *testing.T) {
	static := map[string]any{"k": "v1"}
	live := map[string]any{"k": "v2"}
	got := Merge(static, live, opt).(map[string]any)
	leaf := got["k"].(map[string]any)
	if leaf["_source"].(string) != "live" {
		t.Fatalf("source=%v want live", leaf["_source"])
	}
	if leaf["_value"].(string) != "v2" {
		t.Fatalf("value=%v want v2", leaf["_value"])
	}
	if leaf["_static_value"].(string) != "v1" {
		t.Fatalf("_static_value=%v want v1", leaf["_static_value"])
	}
}

func TestMerge_NestedMapPartialOverlap(t *testing.T) {
	static := map[string]any{
		"a": map[string]any{"x": 1.0, "y": 2.0},
		"s": "static-only",
	}
	live := map[string]any{
		"a": map[string]any{"x": 1.0, "z": 3.0},
		"l": "live-only",
	}
	got := Merge(static, live, opt).(map[string]any)
	a := got["a"].(map[string]any)
	xLeaf := a["x"].(map[string]any)
	if xLeaf["_source"].(string) != "both" {
		t.Fatalf("a.x source=%v want both", xLeaf["_source"])
	}
	yLeaf := a["y"].(map[string]any)
	if yLeaf["_source"].(string) != "static" {
		t.Fatalf("a.y source=%v want static", yLeaf["_source"])
	}
	zLeaf := a["z"].(map[string]any)
	if zLeaf["_source"].(string) != "live" {
		t.Fatalf("a.z source=%v want live", zLeaf["_source"])
	}
	if got["s"].(map[string]any)["_source"].(string) != "static" {
		t.Fatal("s should be static")
	}
	if got["l"].(map[string]any)["_source"].(string) != "live" {
		t.Fatal("l should be live")
	}
}

func TestMerge_ArrayEqual(t *testing.T) {
	static := map[string]any{"arr": []any{"a", "b"}}
	live := map[string]any{"arr": []any{"a", "b"}}
	got := Merge(static, live, opt).(map[string]any)
	leaf := got["arr"].(map[string]any)
	if leaf["_source"].(string) != "both" {
		t.Fatalf("source=%v want both", leaf["_source"])
	}
	if _, ok := leaf["_static_value"]; ok {
		t.Fatal("expected no _static_value when equal")
	}
}

func TestMerge_ArrayDifferent(t *testing.T) {
	static := map[string]any{"arr": []any{"a"}}
	live := map[string]any{"arr": []any{"a", "b"}}
	got := Merge(static, live, opt).(map[string]any)
	leaf := got["arr"].(map[string]any)
	if leaf["_source"].(string) != "live" {
		t.Fatalf("source=%v want live", leaf["_source"])
	}
	if _, ok := leaf["_static_value"]; !ok {
		t.Fatal("expected _static_value when different")
	}
}

func TestMerge_MismatchedTypes(t *testing.T) {
	static := map[string]any{"k": map[string]any{"nested": 1.0}}
	live := map[string]any{"k": "scalar"}
	got := Merge(static, live, opt).(map[string]any)
	leaf := got["k"].(map[string]any)
	if leaf["_source"].(string) != "live" {
		t.Fatalf("source=%v want live", leaf["_source"])
	}
	if leaf["_value"].(string) != "scalar" {
		t.Fatalf("value=%v want scalar", leaf["_value"])
	}
	if _, ok := leaf["_static_value"]; !ok {
		t.Fatal("expected _static_value on type mismatch")
	}
}

type sampleStruct struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func TestMergeJSON_TypedInputs(t *testing.T) {
	s := sampleStruct{Name: "app", Version: "1.0"}
	l := sampleStruct{Name: "app", Version: "2.0"}
	merged, err := MergeJSON(s, l, opt)
	if err != nil {
		t.Fatalf("MergeJSON: %v", err)
	}
	if merged["name"].(map[string]any)["_source"].(string) != "both" {
		t.Fatal("name should be both")
	}
	if merged["version"].(map[string]any)["_source"].(string) != "live" {
		t.Fatal("version should be live")
	}
}

func TestMerge_DoesNotMutateInputs(t *testing.T) {
	static := map[string]any{"k": "v1", "nested": map[string]any{"x": 1.0}}
	live := map[string]any{"k": "v2"}
	staticCopy := map[string]any{"k": "v1", "nested": map[string]any{"x": 1.0}}
	liveCopy := map[string]any{"k": "v2"}
	_ = Merge(static, live, opt)
	if !reflect.DeepEqual(static, staticCopy) {
		t.Fatalf("static was mutated: %v vs %v", static, staticCopy)
	}
	if !reflect.DeepEqual(live, liveCopy) {
		t.Fatalf("live was mutated: %v vs %v", live, liveCopy)
	}
}

func TestMerge_CaptureTSFormat(t *testing.T) {
	static := map[string]any{"k": "v"}
	live := map[string]any{"k": "v"}
	got := Merge(static, live, opt).(map[string]any)
	leaf := got["k"].(map[string]any)
	ts := leaf["_capture_ts"].(string)
	if ts != "2026-01-02T00:00:00Z" {
		t.Fatalf("capture_ts=%q want 2026-01-02T00:00:00Z", ts)
	}
}
