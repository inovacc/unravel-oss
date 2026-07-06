/*
Copyright (c) 2026 Security Research
*/

package component

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestApply(t *testing.T) {
	t.Run("empty registry returns other/1.0", func(t *testing.T) {
		resetForTest()
		got := Apply(Module{Name: "anything", Path: "x/y.go", SymbolsJSON: `["Foo"]`})
		if got.Component != "other" || got.Confidence != 1.0 || got.Classifier != "rule" || got.Evidence != "no rule matched" {
			t.Fatalf("unexpected result: %+v", got)
		}
	})

	t.Run("single positive rule matches", func(t *testing.T) {
		resetForTest()
		Register(Rule{
			Name:           "auth/login-symbol",
			Component:      "auth",
			Confidence:     0.65,
			SymbolKeywords: []string{"Login"},
		})
		got := Apply(Module{Name: "session", Path: "pkg/auth/session.go", SymbolsJSON: `["LoginUser"]`})
		if got.Component != "auth" {
			t.Fatalf("expected auth, got %+v", got)
		}
		if got.Confidence != 0.65 {
			t.Fatalf("expected confidence 0.65, got %v", got.Confidence)
		}
		if got.Classifier != "rule" {
			t.Fatalf("expected classifier rule, got %q", got.Classifier)
		}
		if !strings.Contains(got.Evidence, "auth/login-symbol") {
			t.Fatalf("evidence missing rule name: %q", got.Evidence)
		}
	})

	t.Run("max confidence wins across components", func(t *testing.T) {
		resetForTest()
		Register(Rule{Name: "auth/weak", Component: "auth", Confidence: 0.65, SymbolKeywords: []string{"Login"}})
		Register(Rule{Name: "crypto/strong", Component: "crypto", Confidence: 0.95, SymbolKeywords: []string{"AesGcm"}})
		got := Apply(Module{Name: "x", Path: "x.go", SymbolsJSON: `["Login","AesGcm"]`})
		if got.Component != "crypto" || got.Confidence != 0.95 {
			t.Fatalf("expected crypto/0.95, got %+v", got)
		}
	})

	t.Run("equal confidence resolved by priority", func(t *testing.T) {
		resetForTest()
		// auth(10) beats ui(1) at equal confidence
		Register(Rule{Name: "ui/x", Component: "ui", Confidence: 0.80, SymbolKeywords: []string{"Render"}})
		Register(Rule{Name: "auth/x", Component: "auth", Confidence: 0.80, SymbolKeywords: []string{"Token"}})
		got := Apply(Module{Name: "x", Path: "x.go", SymbolsJSON: `["Render","Token"]`})
		if got.Component != "auth" {
			t.Fatalf("expected auth (priority 10), got %+v", got)
		}
	})

	t.Run("equal confidence equal priority -> ambiguous other", func(t *testing.T) {
		resetForTest()
		// Two registered components share confidence; force equal Priorities by overriding map for test.
		// Using two rules in the SAME bucket would not be ambiguous — they must differ.
		// We rely on real Priorities: auth=10, crypto=9 differ. Force equality by inserting a synthetic
		// component temporarily into Priorities is invasive. Instead, use two rules that match different
		// components which happen to share priority — none do in the locked map. So patch Priorities for the
		// duration of the test.
		orig := Priorities["auth"]
		Priorities["auth"] = Priorities["crypto"] // both 9
		defer func() { Priorities["auth"] = orig }()
		Register(Rule{Name: "auth/a", Component: "auth", Confidence: 0.80, SymbolKeywords: []string{"Token"}})
		Register(Rule{Name: "crypto/a", Component: "crypto", Confidence: 0.80, SymbolKeywords: []string{"AesGcm"}})
		got := Apply(Module{Name: "x", Path: "x.go", SymbolsJSON: `["Token","AesGcm"]`})
		if got.Component != "other" {
			t.Fatalf("expected other on ambiguity, got %+v", got)
		}
		if !strings.HasPrefix(got.Evidence, "ambiguous: ") {
			t.Fatalf("expected ambiguous evidence prefix, got %q", got.Evidence)
		}
	})

	t.Run("negative suppresses positive in same component", func(t *testing.T) {
		resetForTest()
		Register(Rule{Name: "neg/auth-test", Component: "auth", Suppress: true, NameRegex: regexp.MustCompile(`(?i)test`)})
		Register(Rule{Name: "auth/token", Component: "auth", Confidence: 0.80, SymbolKeywords: []string{"Token"}})
		got := Apply(Module{Name: "auth_test", Path: "auth_test.go", SymbolsJSON: `["Token"]`})
		if got.Component != "other" {
			t.Fatalf("expected other after suppression, got %+v", got)
		}
		if got.Evidence != "no rule matched" {
			t.Fatalf("expected 'no rule matched', got %q", got.Evidence)
		}
	})

	t.Run("negative does not suppress different component", func(t *testing.T) {
		resetForTest()
		Register(Rule{Name: "neg/auth-test", Component: "auth", Suppress: true, NameRegex: regexp.MustCompile(`(?i)test`)})
		Register(Rule{Name: "auth/token", Component: "auth", Confidence: 0.80, SymbolKeywords: []string{"Token"}})
		Register(Rule{Name: "crypto/aes", Component: "crypto", Confidence: 0.80, SymbolKeywords: []string{"AesGcm"}})
		got := Apply(Module{Name: "auth_test", Path: "auth_test.go", SymbolsJSON: `["Token","AesGcm"]`})
		if got.Component != "crypto" {
			t.Fatalf("expected crypto to survive, got %+v", got)
		}
	})

	t.Run("path-only matcher", func(t *testing.T) {
		resetForTest()
		Register(Rule{Name: "ui/path", Component: "ui", Confidence: 0.65, PathRegex: regexp.MustCompile(`/ui/`)})
		got := Apply(Module{Name: "x", Path: "pkg/ui/widget.go"})
		if got.Component != "ui" {
			t.Fatalf("path-only failed: %+v", got)
		}
		got = Apply(Module{Name: "x", Path: "pkg/auth/session.go"})
		if got.Component != "other" {
			t.Fatalf("path-only false-positive: %+v", got)
		}
	})

	t.Run("name-only matcher", func(t *testing.T) {
		resetForTest()
		Register(Rule{Name: "telemetry/name", Component: "telemetry", Confidence: 0.65, NameRegex: regexp.MustCompile(`(?i)analytics`)})
		got := Apply(Module{Name: "AnalyticsClient"})
		if got.Component != "telemetry" {
			t.Fatalf("name-only failed: %+v", got)
		}
	})

	t.Run("symbol-only matcher with case-insensitive substring", func(t *testing.T) {
		resetForTest()
		Register(Rule{Name: "storage/sym", Component: "storage", Confidence: 0.65, SymbolKeywords: []string{"SQLite"}})
		got := Apply(Module{Name: "x", SymbolsJSON: `["openSqliteDB"]`})
		if got.Component != "storage" {
			t.Fatalf("symbol-only failed: %+v", got)
		}
	})

	t.Run("multiple criteria require ALL to match", func(t *testing.T) {
		resetForTest()
		Register(Rule{
			Name:           "auth/triple",
			Component:      "auth",
			Confidence:     0.95,
			PathRegex:      regexp.MustCompile(`/auth/`),
			NameRegex:      regexp.MustCompile(`(?i)session`),
			SymbolKeywords: []string{"Login"},
		})
		// All three match
		got := Apply(Module{Name: "Session", Path: "pkg/auth/x.go", SymbolsJSON: `["LoginUser"]`})
		if got.Component != "auth" || got.Confidence != 0.95 {
			t.Fatalf("AND-match failed: %+v", got)
		}
		// Symbol absent -> no match
		got = Apply(Module{Name: "Session", Path: "pkg/auth/x.go", SymbolsJSON: `["foo"]`})
		if got.Component != "other" {
			t.Fatalf("partial match should not fire: %+v", got)
		}
		// Path absent -> no match
		got = Apply(Module{Name: "Session", Path: "pkg/other/x.go", SymbolsJSON: `["LoginUser"]`})
		if got.Component != "other" {
			t.Fatalf("partial match should not fire: %+v", got)
		}
	})

	t.Run("ReDoS bound on adversarial input", func(t *testing.T) {
		resetForTest()
		// Linear RE2 regex; large input must complete <100ms.
		Register(Rule{Name: "any/linear", Component: "ui", Confidence: 0.65, PathRegex: regexp.MustCompile(`^a+b$`)})
		long := strings.Repeat("a", 50000)
		start := time.Now()
		_ = Apply(Module{Name: "x", Path: long, SymbolsJSON: long})
		elapsed := time.Since(start)
		if elapsed > 100*time.Millisecond {
			t.Fatalf("Apply exceeded 100ms on 50k input: %v", elapsed)
		}
	})

	t.Run("symbols json bounded to 64 KiB", func(t *testing.T) {
		resetForTest()
		Register(Rule{Name: "tail/sym", Component: "ui", Confidence: 0.65, SymbolKeywords: []string{"NEEDLE"}})
		// Place needle past 64 KiB; must NOT match.
		big := strings.Repeat("x", 64*1024+10) + "NEEDLE"
		got := Apply(Module{Name: "x", Path: "x.go", SymbolsJSON: big})
		if got.Component != "other" {
			t.Fatalf("symbols beyond 64 KiB must not match, got %+v", got)
		}
	})
}

func TestRegisterPanics(t *testing.T) {
	resetForTest()
	mustPanic := func(name string, fn func()) {
		t.Helper()
		defer func() {
			if r := recover(); r == nil {
				t.Fatalf("%s: expected panic", name)
			}
		}()
		fn()
	}
	mustPanic("empty name", func() { Register(Rule{Component: "auth", Confidence: 0.65}) })
	mustPanic("bad bucket", func() { Register(Rule{Name: "x", Component: "nope", Confidence: 0.65}) })
	mustPanic("bad confidence", func() { Register(Rule{Name: "x", Component: "auth", Confidence: 0.5}) })
}
