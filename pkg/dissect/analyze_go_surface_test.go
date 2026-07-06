/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// writeBlob writes printable runs separated by NUL bytes so scanGoSurface sees
// them as distinct strings, mimicking a Go binary's string table.
func writeBlob(t *testing.T, runs ...string) string {
	t.Helper()
	var b []byte
	for _, r := range runs {
		b = append(b, []byte(r)...)
		b = append(b, 0x00)
	}
	p := filepath.Join(t.TempDir(), "blob.bin")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestScanGoSurface(t *testing.T) {
	p := writeBlob(t,
		"https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary",
		"https://oauth2.googleapis.com/token",
		"exa.language_server_pb.LanguageServerService",
		"google.internal.cloud.code.v1internal.RetrieveUserQuotaSummaryRequest",
		"google.protobuf.Timestamp", // vendored noise -> dropped
		"grpc.health.v1.Health",     // vendored noise -> dropped
		"/v1internal:loadCodeAssist",
		"~/.gemini/oauth_creds.json",
		"settings.json",
		"hi", // shorter than min run -> ignored
	)

	s, err := scanGoSurface(p)
	if err != nil {
		t.Fatal(err)
	}
	if s.Empty() {
		t.Fatal("expected a non-empty surface")
	}

	wantHost := "https://cloudcode-pa.googleapis.com" // scheme+host only, path stripped
	if !slices.Contains(s.Hosts, wantHost) {
		t.Errorf("hosts missing %q: %v", wantHost, s.Hosts)
	}
	if slices.ContainsFunc(s.Hosts, func(h string) bool { return len(h) > 0 && h[len(h)-1] == '/' }) {
		t.Errorf("host should not keep trailing path: %v", s.Hosts)
	}

	for _, want := range []string{
		"exa.language_server_pb.LanguageServerService",
		"google.internal.cloud.code.v1internal.RetrieveUserQuotaSummaryRequest",
		"/v1internal:retrieveUserQuotaSummary",
		"/v1internal:loadCodeAssist",
	} {
		if !slices.Contains(s.RPCServices, want) {
			t.Errorf("rpc services missing %q: %v", want, s.RPCServices)
		}
	}
	for _, noise := range []string{"google.protobuf.Timestamp", "grpc.health.v1.Health"} {
		if slices.Contains(s.RPCServices, noise) {
			t.Errorf("vendored proto noise %q should be filtered", noise)
		}
	}
	if !slices.Contains(s.ConfigPaths, "settings.json") {
		t.Errorf("config paths missing settings.json: %v", s.ConfigPaths)
	}
}

func TestScanGoSurfaceEmpty(t *testing.T) {
	p := writeBlob(t, "no surface here", "just words")
	s, err := scanGoSurface(p)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Empty() {
		t.Errorf("expected empty surface, got %+v", s)
	}
}

func TestTopNDeterministicOrder(t *testing.T) {
	counts := map[string]int{"a": 1, "b": 3, "c": 3, "d": 2}
	got := topN(counts, 3)
	want := []string{"b", "c", "d"} // freq desc, ties alpha; "a" dropped by cap
	if !slices.Equal(got, want) {
		t.Errorf("topN = %v, want %v", got, want)
	}
}
