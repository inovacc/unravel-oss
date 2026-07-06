/*
Copyright (c) 2026 Security Research
*/
package migrate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stubMCP records every prompt and returns a canned hint.
type stubMCP struct {
	prompts []string
	canned  MigrationHint
	err     error
}

func (s *stubMCP) GenerateHint(_ context.Context, prompt string) (MigrationHint, error) {
	s.prompts = append(s.prompts, prompt)
	if s.err != nil {
		return MigrationHint{}, s.err
	}
	return s.canned, nil
}

// makeKB builds a synthetic kb directory at t.TempDir() with the given
// component->files map. File contents default to a fixed body unless content
// is supplied.
func makeKB(t *testing.T, layout map[string]map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for comp, files := range layout {
		dir := filepath.Join(root, "sources", comp)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, body := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root
}

func cannedHint() MigrationHint {
	return MigrationHint{
		SchemaVersion: 1,
		Role:          "Authenticate the user via OAuth2",
		Inputs:        []string{"username:string"},
		Outputs:       []string{"jwt:string"},
		SideEffects:   []string{"writes localStorage.token"},
		Equivalents:   map[string]string{"react": "Custom hook useAuth() that wraps fetch + context."},
	}
}

func TestGenerateForFrameworkRejectsUnknown(t *testing.T) {
	kb := makeKB(t, map[string]map[string]string{
		"auth": {"login.js": "body"},
	})
	stub := &stubMCP{canned: cannedHint()}
	err := GenerateForFramework(context.Background(), kb, "ruby-on-rails", stub)
	if err == nil {
		t.Fatal("expected error for unknown framework")
	}
	if !strings.Contains(err.Error(), "ruby-on-rails") {
		t.Errorf("error must mention framework name; got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(kb, "migrations")); !os.IsNotExist(statErr) {
		t.Errorf("migrations dir should not exist after rejection")
	}
	if len(stub.prompts) != 0 {
		t.Errorf("MCP must not be called for invalid framework")
	}
}

func TestGenerateForFrameworkPathTraversal(t *testing.T) {
	stub := &stubMCP{canned: cannedHint()}
	if err := GenerateForFramework(context.Background(), "/tmp/foo/../etc", "react", stub); err == nil {
		t.Fatal("expected path-traversal rejection")
	}
}

func TestGenerateForFrameworkPerComponent(t *testing.T) {
	kb := makeKB(t, map[string]map[string]string{
		"auth":      {"login.js": "function login() {}"},
		"telemetry": {"sentry.js": "Sentry.init({})"},
	})
	stub := &stubMCP{canned: cannedHint()}
	if err := GenerateForFramework(context.Background(), kb, "react", stub); err != nil {
		t.Fatalf("GenerateForFramework: %v", err)
	}
	for _, comp := range []string{"auth", "telemetry"} {
		jsonPath := filepath.Join(kb, "migrations", "react", comp, "migration.json")
		mdPath := filepath.Join(kb, "migrations", "react", comp, "summary.md")
		if _, err := os.Stat(jsonPath); err != nil {
			t.Errorf("missing %s: %v", jsonPath, err)
		}
		if _, err := os.Stat(mdPath); err != nil {
			t.Errorf("missing %s: %v", mdPath, err)
		}
		body, err := os.ReadFile(mdPath)
		if err != nil {
			continue
		}
		if got := countSentences(string(body)); got > 5 {
			t.Errorf("summary.md for %s has %d sentences; want <= 5", comp, got)
		}
	}
}

func countSentences(s string) int {
	n := strings.Count(s, ". ")
	if strings.HasSuffix(strings.TrimSpace(s), ".") {
		n++
	}
	return n
}

func TestMigrationJSONSchema(t *testing.T) {
	kb := makeKB(t, map[string]map[string]string{
		"auth": {"login.js": "x"},
	})
	stub := &stubMCP{canned: cannedHint()}
	if err := GenerateForFramework(context.Background(), kb, "react", stub); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(kb, "migrations", "react", "auth", "migration.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("emitted JSON malformed: %v", err)
	}
	for _, f := range []string{"schema_version", "component", "framework", "role", "inputs", "outputs", "side_effects", "equivalents"} {
		if _, ok := got[f]; !ok {
			t.Errorf("migration.json missing field %q", f)
		}
	}
	if got["schema_version"] != float64(1) {
		t.Errorf("schema_version = %v; want 1", got["schema_version"])
	}
	if got["component"] != "auth" {
		t.Errorf("component = %v; want auth", got["component"])
	}
	if got["framework"] != "react" {
		t.Errorf("framework = %v; want react", got["framework"])
	}
	eq, ok := got["equivalents"].(map[string]any)
	if !ok {
		t.Fatalf("equivalents not a map: %T", got["equivalents"])
	}
	if _, ok := eq["react"]; !ok {
		t.Errorf("equivalents must cover the requested target framework")
	}
}

func TestRepresentativeFileCap(t *testing.T) {
	files := map[string]string{}
	for i := 0; i < 50; i++ {
		files[fmt.Sprintf("mod%02d.js", i)] = fmt.Sprintf("// unique %d\n%s", i, strings.Repeat("a", i+1))
	}
	kb := makeKB(t, map[string]map[string]string{"auth": files})
	stub := &stubMCP{canned: cannedHint()}
	if err := GenerateForFramework(context.Background(), kb, "react", stub); err != nil {
		t.Fatal(err)
	}
	if len(stub.prompts) != 1 {
		t.Fatalf("expected 1 prompt for one component; got %d", len(stub.prompts))
	}
	count := strings.Count(stub.prompts[0], "--- sources/auth/mod")
	if count > MaxRepresentativeFiles {
		t.Errorf("prompt embedded %d files; cap is %d", count, MaxRepresentativeFiles)
	}
	if count == 0 {
		t.Errorf("prompt embedded zero files")
	}
}

func TestPromptSentinels(t *testing.T) {
	kb := makeKB(t, map[string]map[string]string{
		"auth": {"login.js": "// some content"},
	})
	stub := &stubMCP{canned: cannedHint()}
	if err := GenerateForFramework(context.Background(), kb, "react", stub); err != nil {
		t.Fatal(err)
	}
	if len(stub.prompts) == 0 {
		t.Fatal("MCP not invoked")
	}
	body := stub.prompts[0]
	if !strings.Contains(body, "<<<USER_SOURCE_BEGIN>>>") {
		t.Errorf("missing USER_SOURCE_BEGIN sentinel")
	}
	if !strings.Contains(body, "<<<USER_SOURCE_END>>>") {
		t.Errorf("missing USER_SOURCE_END sentinel")
	}
}

func TestMigrationAtomicWrite(t *testing.T) {
	kb := makeKB(t, map[string]map[string]string{"auth": {"login.js": "x"}})
	stub := &stubMCP{canned: cannedHint()}
	if err := GenerateForFramework(context.Background(), kb, "react", stub); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(kb, "migrations", "react", "auth")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

func TestMigrationSkipsCSS(t *testing.T) {
	kb := makeKB(t, map[string]map[string]string{
		"auth": {"login.js": "x"},
		"css":  {"theme.css": "body{}"},
	})
	stub := &stubMCP{canned: cannedHint()}
	if err := GenerateForFramework(context.Background(), kb, "react", stub); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(kb, "migrations", "react", "css")); !os.IsNotExist(err) {
		t.Errorf("css component should not produce migrations; stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(kb, "migrations", "react", "auth", "migration.json")); err != nil {
		t.Errorf("auth migration must still emit when css is present: %v", err)
	}
}

func TestMigrationSkipsUnknown(t *testing.T) {
	kb := makeKB(t, map[string]map[string]string{
		"unknown": {"misc.js": "x"},
	})
	stub := &stubMCP{canned: cannedHint()}
	if err := GenerateForFramework(context.Background(), kb, "react", stub); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(kb, "migrations", "react", "unknown")); !os.IsNotExist(err) {
		t.Errorf("unknown component should not produce migrations")
	}
	if len(stub.prompts) != 0 {
		t.Errorf("MCP must not be called for skipped buckets")
	}
}

// TestNoMigrationOnExtract enforces D-08 lazy invariant: pkg/knowledge/extract*
// MUST NOT import this package. Verified by file scan rather than reflection.
func TestNoMigrationOnExtract(t *testing.T) {
	root := repoRootForTest(t)
	matches, err := filepath.Glob(filepath.Join(root, "pkg", "knowledge", "extract*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range matches {
		body, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), `"github.com/inovacc/unravel-oss/pkg/knowledge/migrate"`) {
			t.Errorf("%s imports migrate package — violates D-08 lazy invariant", p)
		}
	}
}

// TestRepresentativeFileDedup confirms identical-content padding files do not
// crowd out unique content in the prompt.
func TestRepresentativeFileDedup(t *testing.T) {
	files := map[string]string{}
	for i := 0; i < 20; i++ {
		files[fmt.Sprintf("dup%02d.js", i)] = "IDENTICAL CONTENT"
	}
	files["unique.js"] = "// unique\nconsole.log(1)"
	kb := makeKB(t, map[string]map[string]string{"auth": files})
	stub := &stubMCP{canned: cannedHint()}
	if err := GenerateForFramework(context.Background(), kb, "react", stub); err != nil {
		t.Fatal(err)
	}
	body := stub.prompts[0]
	dupCount := strings.Count(body, "IDENTICAL CONTENT")
	if dupCount != 1 {
		t.Errorf("dup content appeared %d times in prompt; want 1 after dedup", dupCount)
	}
	if !strings.Contains(body, "// unique") {
		t.Errorf("unique content was dropped during dedup")
	}
}
