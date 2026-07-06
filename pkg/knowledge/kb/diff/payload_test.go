/*
Copyright (c) 2026 Security Research
*/

package diff

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestPayload_DepDiff_RoundTrip(t *testing.T) {
	in := DepDiff{Name: "Google.Protobuf", OldVersion: "3.21.0", NewVersion: "3.25.0", Source: "deps.json"}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	for _, want := range []string{`"name"`, `"old_version"`, `"new_version"`, `"source"`} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing key %s in %s", want, s)
		}
	}
	var out DepDiff
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("roundtrip mismatch: in=%+v out=%+v", in, out)
	}
}

func TestPayload_DepDiff_OmitEmpty(t *testing.T) {
	in := DepDiff{Name: "x", Source: "deps.json"}
	b, _ := json.Marshal(in)
	s := string(b)
	if strings.Contains(s, "old_version") || strings.Contains(s, "new_version") {
		t.Fatalf("expected omitempty to drop old/new_version, got %s", s)
	}
}

func TestPayload_CapabilityDiff_RoundTrip(t *testing.T) {
	in := CapabilityDiff{Name: "internetClient", Namespace: "", Severity: "low"}
	b, _ := json.Marshal(in)
	var out CapabilityDiff
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestPayload_URLDiff_RoundTrip(t *testing.T) {
	in := URLDiff{URL: "https://x/y", Host: "x", Scheme: "https"}
	b, _ := json.Marshal(in)
	if !strings.Contains(string(b), `"host"`) {
		t.Fatalf("missing host key")
	}
	var out URLDiff
	_ = json.Unmarshal(b, &out)
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestPayload_RiskDiff_OmitEmpty(t *testing.T) {
	in := RiskDiff{}
	b, _ := json.Marshal(in)
	if string(b) != "{}" {
		t.Fatalf("expected empty risk to marshal to {}, got %s", string(b))
	}
	score := 42
	in2 := RiskDiff{NewScore: &score, NewLevel: "medium"}
	b2, _ := json.Marshal(in2)
	if !strings.Contains(string(b2), `"new_score":42`) {
		t.Fatalf("missing new_score: %s", string(b2))
	}
	if strings.Contains(string(b2), "old_score") {
		t.Fatalf("expected omitempty to drop old_score: %s", string(b2))
	}
	var out RiskDiff
	_ = json.Unmarshal(b2, &out)
	if !reflect.DeepEqual(in2, out) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestPayload_CertDiff_RoundTrip(t *testing.T) {
	in := CertDiff{FingerprintNew: "abc", SubjectNew: "CN=x"}
	b, _ := json.Marshal(in)
	if strings.Contains(string(b), "fingerprint_old") {
		t.Fatalf("expected omitempty fingerprint_old")
	}
	for _, want := range []string{`"fingerprint_new"`, `"subject_new"`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("missing key %s: %s", want, string(b))
		}
	}
	var out CertDiff
	_ = json.Unmarshal(b, &out)
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestPayload_FactDiff_RoundTrip(t *testing.T) {
	in := FactDiff{Key: "crypto/db_cipher", OldValue: "AES-CBC", NewValue: "AES-GCM"}
	b, _ := json.Marshal(in)
	for _, want := range []string{`"key"`, `"old_value"`, `"new_value"`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("missing key %s: %s", want, string(b))
		}
	}
	var out FactDiff
	_ = json.Unmarshal(b, &out)
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestPayload_ModuleDiff_SnakeCase(t *testing.T) {
	in := ModuleDiff{BodySHA256: "abc", Name: "wa", Lang: "js"}
	b, _ := json.Marshal(in)
	if !strings.Contains(string(b), `"body_sha256"`) {
		t.Fatalf("expected snake_case body_sha256, got %s", string(b))
	}
	if strings.Contains(string(b), "BodySHA256") {
		t.Fatalf("PascalCase leaked into JSON")
	}
	var out ModuleDiff
	_ = json.Unmarshal(b, &out)
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestPayload_ComponentDiff_RoundTrip(t *testing.T) {
	in := ComponentDiff{ModuleID: "42", OldComponent: "ui", NewComponent: "auth", Classifier: "rule"}
	b, _ := json.Marshal(in)
	for _, want := range []string{`"module_id"`, `"old_component"`, `"new_component"`, `"classifier"`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("missing key %s: %s", want, string(b))
		}
	}
	var out ComponentDiff
	_ = json.Unmarshal(b, &out)
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestPayload_FileDiff_SnakeCase(t *testing.T) {
	in := FileDiff{FileSHA256: "deadbeef", RelPath: "a/b.txt", SizeBytes: 12345}
	b, _ := json.Marshal(in)
	for _, want := range []string{`"file_sha256"`, `"rel_path"`, `"size_bytes"`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("missing key %s: %s", want, string(b))
		}
	}
	var out FileDiff
	_ = json.Unmarshal(b, &out)
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("roundtrip mismatch")
	}
}
