// Copyright (c) 2026 Security Research
package enrich

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/frida"
)

// stubClient implements MCPClient with a canned response.
type stubClient struct {
	resp EnrichResponse
	err  error
	last string
}

func (s *stubClient) EnrichScript(_ context.Context, prompt string) (EnrichResponse, error) {
	s.last = prompt
	if s.err != nil {
		return EnrichResponse{}, s.err
	}
	return s.resp, nil
}

const sampleScript = `Java.perform(function () {
  var sslHook = Java.use("javax.net.ssl.SSLContext");
  Interceptor.attach(sslHook, {
    onEnter: function (args) {},
    onLeave: function (ret) {}
  });
});
`

func newStubResp() EnrichResponse {
	return EnrichResponse{
		HeaderSummary: "SSL pinning bypass via SSLContext init.",
		Hooks: []HookEnrichment{
			{
				ID:           "sslHook",
				Summary:      "Hooks SSLContext.init to neutralise certificate pinning.",
				WhyItMatters: "Apps with custom pinning blacklists MITM proxies.",
				WatchFor:     "Calls with non-null TrustManager arrays.",
				Expected: Expected{
					Args:   []ExpectedArg{{Index: 0, Op: "present"}},
					Return: &ExpectedValue{Op: "present"},
				},
			},
		},
	}
}

func TestEnrich_BasicHappyPath(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "ssl.frida.js")
	if err := os.WriteFile(scriptPath, []byte(sampleScript), 0o644); err != nil {
		t.Fatalf("seed script: %v", err)
	}
	o := New()
	o.MCP = &stubClient{resp: newStubResp()}
	o.CacheDir = filepath.Join(dir, "cache")

	res, err := o.Enrich(context.Background(), scriptPath, "")
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if res.CacheHit {
		t.Errorf("first run should be cache miss")
	}
	if res.SchemaVersion != 1 {
		t.Errorf("schema_version=%d want 1", res.SchemaVersion)
	}
	body, _ := os.ReadFile(scriptPath)
	if !strings.Contains(string(body), "[unravel-enriched header]") {
		t.Errorf("script missing enrichment header: %s", body)
	}
	if !strings.Contains(string(body), "Hook: sslHook") {
		t.Errorf("script missing per-hook JSDoc")
	}

	criteriaPath := strings.TrimSuffix(scriptPath, ".frida.js") + ".criteria.json"
	cb, err := os.ReadFile(criteriaPath)
	if err != nil {
		t.Fatalf("read criteria: %v", err)
	}
	var cf frida.CriteriaFile
	if err := json.Unmarshal(cb, &cf); err != nil {
		t.Fatalf("decode criteria: %v", err)
	}
	if cf.SchemaVersion != 1 || len(cf.Hooks) != 1 || cf.Hooks[0].ID != "sslHook" {
		t.Errorf("criteria shape unexpected: %+v", cf)
	}
}

func TestEnrich_CacheHitOnSecondRun(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "ssl.frida.js")
	_ = os.WriteFile(scriptPath, []byte(sampleScript), 0o644)
	cli := &stubClient{resp: newStubResp()}
	o := &Orchestrator{MCP: cli, CacheDir: filepath.Join(dir, "cache")}

	if _, err := o.Enrich(context.Background(), scriptPath, ""); err != nil {
		t.Fatalf("first Enrich: %v", err)
	}
	// Reset the script to its original for the second run so the cache key
	// remains identical.
	_ = os.WriteFile(scriptPath, []byte(sampleScript), 0o644)
	cli.last = ""

	res, err := o.Enrich(context.Background(), scriptPath, "")
	if err != nil {
		t.Fatalf("second Enrich: %v", err)
	}
	if !res.CacheHit {
		t.Errorf("second run should be cache hit")
	}
	if cli.last != "" {
		t.Errorf("cache hit should not call MCP")
	}
}

func TestEnrich_PathTraversalRejected(t *testing.T) {
	o := New()
	o.MCP = &stubClient{resp: newStubResp()}
	if _, err := o.Enrich(context.Background(), "foo/../etc/passwd", ""); err == nil {
		t.Errorf("expected path-traversal rejection")
	}
}

func TestEnrich_UnknownHookSafelySkipped(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "ssl.frida.js")
	_ = os.WriteFile(scriptPath, []byte(sampleScript), 0o644)
	resp := newStubResp()
	resp.Hooks[0].ID = "noSuchHook"
	o := &Orchestrator{MCP: &stubClient{resp: resp}, CacheDir: filepath.Join(dir, "cache")}
	if _, err := o.Enrich(context.Background(), scriptPath, ""); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	body, _ := os.ReadFile(scriptPath)
	if strings.Contains(string(body), "Hook: noSuchHook") {
		t.Errorf("unknown hook id should not produce JSDoc on a real attach site")
	}
}
