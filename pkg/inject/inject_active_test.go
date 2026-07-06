/*
Copyright (c) 2026 Security Research
*/
package inject

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

// withClearedHooks resets the package-level hooks for the duration of the
// test. Restores prior values via t.Cleanup.
func withClearedHooks(t *testing.T) {
	t.Helper()
	pa, pc, pt := asarRepatcher, cdpInjector, tauriDetector
	asarRepatcher, cdpInjector, tauriDetector = nil, nil, nil
	t.Cleanup(func() {
		asarRepatcher, cdpInjector, tauriDetector = pa, pc, pt
	})
}

func auditEnv(t *testing.T) {
	t.Helper()
	t.Setenv("UNRAVEL_INJECT_LOG", filepath.Join(t.TempDir(), "log.jsonl"))
}

func TestInject_RefusesWithoutConsent(t *testing.T) {
	withClearedHooks(t)
	auditEnv(t)
	_, err := Inject(context.Background(), "/some/app", InjectOpts{
		Method: MethodCDP,
		Script: []byte("noop"),
		// Confirmed deliberately false
	})
	if !errors.Is(err, ErrConsentRequired) {
		t.Fatalf("expected ErrConsentRequired, got %v", err)
	}
}

func TestInject_TauriReturnsUnsupported(t *testing.T) {
	withClearedHooks(t)
	auditEnv(t)
	RegisterTauriDetector(func(target string) bool { return true })

	_, err := Inject(context.Background(), "/tauri/bundle", InjectOpts{
		Method:    MethodCDP,
		Script:    []byte("noop"),
		Confirmed: true,
	})
	if !errors.Is(err, ErrTauriUnsupported) {
		t.Fatalf("expected ErrTauriUnsupported, got %v", err)
	}
}

func TestInject_UnknownMethod(t *testing.T) {
	withClearedHooks(t)
	auditEnv(t)
	_, err := Inject(context.Background(), "/x", InjectOpts{
		Method:    InjectMethod("garbage"),
		Confirmed: true,
	})
	if !errors.Is(err, ErrInjectMethodUnknown) {
		t.Fatalf("expected ErrInjectMethodUnknown, got %v", err)
	}
}

func TestInject_CDPNotRegistered(t *testing.T) {
	withClearedHooks(t)
	auditEnv(t)
	// cdpInjector cleared → method known but no backend wired
	_, err := Inject(context.Background(), "/x", InjectOpts{
		Method:    MethodCDP,
		Script:    []byte("noop"),
		Confirmed: true,
	})
	if !errors.Is(err, ErrInjectMethodUnknown) {
		t.Fatalf("expected ErrInjectMethodUnknown when CDP unwired, got %v", err)
	}
}

func TestInject_CDPSuccess_WritesAudit(t *testing.T) {
	withClearedHooks(t)
	auditEnv(t)

	called := false
	RegisterCDPInjector(func(_ context.Context, port int, script []byte, opts CDPInjectOpts) (CDPInjectResult, error) {
		called = true
		if port != 9222 {
			t.Errorf("port = %d, want 9222", port)
		}
		if string(script) != "console.log(1)" {
			t.Errorf("script = %q", string(script))
		}
		if !opts.Persistent {
			t.Error("persistent flag not propagated")
		}
		return CDPInjectResult{TargetURL: "https://app/"}, nil
	})

	res, err := Inject(context.Background(), "/electron/app", InjectOpts{
		Method:     MethodCDP,
		Script:     []byte("console.log(1)"),
		ScriptName: "log1.js",
		Persistent: true,
		CDPPort:    9222,
		Confirmed:  true,
	})
	if err != nil {
		t.Fatalf("inject: %v", err)
	}
	if !called {
		t.Fatal("cdp injector hook not invoked")
	}
	if res.ScriptHash == "" || len(res.ScriptHash) != 64 {
		t.Errorf("script hash = %q (expected 64-hex)", res.ScriptHash)
	}
	if res.Method != MethodCDP {
		t.Errorf("method = %s", res.Method)
	}
	if res.FinishedAt.Before(res.StartedAt) {
		t.Errorf("finished < started: %v < %v", res.FinishedAt, res.StartedAt)
	}
}

func TestInject_ASARMode_WiresHook(t *testing.T) {
	withClearedHooks(t)
	auditEnv(t)

	RegisterASARRepatcher(func(_ context.Context, asarPath string, script []byte, name string) (string, error) {
		if asarPath != "/path/app.asar" {
			t.Errorf("asarPath = %q", asarPath)
		}
		if name != "preload.js" {
			t.Errorf("name = %q", name)
		}
		_ = script
		return "/path/app.injected.asar", nil
	})

	res, err := Inject(context.Background(), "/path/app", InjectOpts{
		Method:     MethodASAR,
		ASARPath:   "/path/app.asar",
		Script:     []byte("/* preload */"),
		ScriptName: "preload.js",
		Confirmed:  true,
	})
	if err != nil {
		t.Fatalf("inject: %v", err)
	}
	if res.OutputPath != "/path/app.injected.asar" {
		t.Errorf("OutputPath = %q", res.OutputPath)
	}
	if res.Method != MethodASAR {
		t.Errorf("method = %s", res.Method)
	}
}
