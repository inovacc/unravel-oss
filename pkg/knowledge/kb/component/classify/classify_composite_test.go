/*
Copyright (c) 2026 Security Research

Tests for the composite{primary,fallback} Classifier. Phase 45 / LLMC-02.
*/
package classify

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component"
)

// stubClassifier returns a fixed (Result, error). Used to drive composite
// behavior in both branches.
type stubClassifier struct {
	name string
	pv   string
	res  component.Result
	err  error
}

func (s stubClassifier) Name() string          { return s.name }
func (s stubClassifier) PromptVersion() string { return s.pv }
func (s stubClassifier) Classify(_ context.Context, _ ModuleRow) (component.Result, error) {
	return s.res, s.err
}

// TestComposite_PrimarySuccess returns the primary verdict without
// invoking the fallback.
func TestComposite_PrimarySuccess(t *testing.T) {
	primary := stubClassifier{name: "mcp", res: component.Result{Component: "auth", Classifier: "llm"}}
	fallback := stubClassifier{name: "rule", err: errors.New("should not be called")}
	c := NewComposite(primary, fallback)

	res, err := c.Classify(context.Background(), ModuleRow{ID: 1})
	if err != nil {
		t.Fatalf("err = %v; want nil", err)
	}
	if res.Classifier != "llm" {
		t.Fatalf("classifier = %q; want llm (no fallback)", res.Classifier)
	}
}

// TestComposite_FallbackOnPrimaryError exercises the WARN-and-fallback path.
func TestComposite_FallbackOnPrimaryError(t *testing.T) {
	primary := stubClassifier{name: "mcp", err: errors.New("transport down")}
	fallback := stubClassifier{name: "rule", res: component.Result{Component: "ui", Classifier: "rule"}}
	c := NewComposite(primary, fallback)

	res, err := c.Classify(context.Background(), ModuleRow{ID: 42})
	if err != nil {
		t.Fatalf("err = %v; want nil after fallback", err)
	}
	if res.Classifier != "rule" {
		t.Fatalf("classifier = %q; want rule after fallback", res.Classifier)
	}
}

// TestComposite_DoubleFailure surfaces the fallback's error to the caller.
func TestComposite_DoubleFailure(t *testing.T) {
	primary := stubClassifier{name: "mcp", err: errors.New("p")}
	fallback := stubClassifier{name: "rule", err: errors.New("f")}
	c := NewComposite(primary, fallback)

	_, err := c.Classify(context.Background(), ModuleRow{ID: 1})
	if err == nil {
		t.Fatalf("expected error on double failure")
	}
}

// TestComposite_NameDelegatesToPrimary keeps log-field stability.
func TestComposite_NameDelegatesToPrimary(t *testing.T) {
	c := NewComposite(stubClassifier{name: "mcp"}, stubClassifier{name: "rule"})
	if c.Name() != "mcp" {
		t.Fatalf("Name = %q; want mcp", c.Name())
	}
}

// TestComposite_FallbackEmitsWarnLogWithBothNames captures slog output and
// asserts the WARN line carries both the primary and fallback classifier
// names plus the offending module ID. This locks the operator-visible
// signal that a fallback occurred (LLMC-04 / D-45-CLASSIFY-FALLBACK-ORDER).
func TestComposite_FallbackEmitsWarnLogWithBothNames(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	primary := stubClassifier{name: "mcp", err: errors.New("transport down")}
	fallback := stubClassifier{name: "rule", res: component.Result{Component: "ui", Classifier: "rule"}}
	c := NewComposite(primary, fallback)

	if _, err := c.Classify(context.Background(), ModuleRow{ID: 7}); err != nil {
		t.Fatalf("err = %v; want nil after fallback", err)
	}
	out := buf.String()
	if !strings.Contains(out, "level=WARN") {
		t.Errorf("expected WARN level in log, got %q", out)
	}
	if !strings.Contains(out, "primary=mcp") {
		t.Errorf("expected primary=mcp in log, got %q", out)
	}
	if !strings.Contains(out, "fallback=rule") {
		t.Errorf("expected fallback=rule in log, got %q", out)
	}
	if !strings.Contains(out, "module_id=7") {
		t.Errorf("expected module_id=7 in log, got %q", out)
	}
	if !strings.Contains(out, "transport down") {
		t.Errorf("expected primary error text in log, got %q", out)
	}
}

// TestComposite_DoubleFailure_ErrorChainNamesBothClassifiers strengthens
// the existing double-failure test: the returned error must surface the
// fallback's error (Run treats it as Skipped++). The composite returns
// the fallback error directly per current contract; we verify both
// classifier names are visible in the log fields when the primary fails
// (the fallback returning ErrNoClient if nil is a separate path).
func TestComposite_DoubleFailure_ErrorChainNamesBothClassifiers(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	primaryErr := errors.New("primary-down")
	fallbackErr := errors.New("fallback-down")
	primary := stubClassifier{name: "mcp", err: primaryErr}
	fallback := stubClassifier{name: "rule", err: fallbackErr}
	c := NewComposite(primary, fallback)

	_, err := c.Classify(context.Background(), ModuleRow{ID: 9})
	if err == nil {
		t.Fatalf("expected error on double failure")
	}
	// fallback's error is the one surfaced upward.
	if !errors.Is(err, fallbackErr) {
		t.Errorf("err = %v; want it to wrap fallbackErr", err)
	}
	// log carries both names so an operator can see what was tried.
	out := buf.String()
	if !strings.Contains(out, "primary=mcp") || !strings.Contains(out, "fallback=rule") {
		t.Errorf("log missing both classifier names: %q", out)
	}
}
