/*
Copyright (c) 2026 Security Research
*/
// Package integration runs end-to-end tests against minimal Electron / Tauri /
// WebView2 application fixtures. Lives in its own package so the blank import
// of pkg/inject/registry stays out of the inject unit-test binary (which uses
// resetScannersForTest aggressively and would clobber real scanner
// registrations).
package integration_test

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/inject"
	_ "github.com/inovacc/unravel-oss/pkg/inject/registry" // populate scanner registry via init()
)

func fixtureDir(t *testing.T, name string) string {
	t.Helper()
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// pkg/inject/integration/integration_test.go ->
	//   ../testdata/integration/<name>
	return filepath.Join(filepath.Dir(here), "..", "testdata", "integration", name)
}

// TestE2E_AllFrameworks scans the three single-framework fixtures end to end
// and asserts each is identified with the right framework token and emits the
// expected number of seams.
func TestE2E_AllFrameworks(t *testing.T) {
	cases := []struct {
		name      string
		fixture   string
		framework inject.Framework
		minSeams  int
	}{
		{"electron", "electron-app", inject.FrameworkElectron, 2},
		{"tauri", "tauri-app", inject.FrameworkTauri, 2},
		{"webview2", "webview2-app", inject.FrameworkWebView2, 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := inject.Scan(context.Background(), fixtureDir(t, tc.fixture))
			if err != nil {
				t.Fatalf("Scan(%s): %v", tc.fixture, err)
			}
			if result == nil {
				t.Fatal("nil result")
			}
			if result.Framework != tc.framework {
				t.Errorf("framework = %q, want %q", result.Framework, tc.framework)
			}
			if got := len(result.Seams); got < tc.minSeams {
				t.Errorf("seam count = %d, want >= %d", got, tc.minSeams)
			}
		})
	}
}

// TestE2E_HybridDetection asserts that a fixture carrying markers from two
// frameworks (Electron + WebView2) is reported as Framework="hybrid".
func TestE2E_HybridDetection(t *testing.T) {
	result, err := inject.Scan(context.Background(), fixtureDir(t, "hybrid-app"))
	if err != nil {
		t.Fatalf("Scan(hybrid): %v", err)
	}
	if result == nil {
		t.Fatal("nil result")
	}
	if result.Framework != inject.FrameworkHybrid {
		t.Errorf("framework = %q, want %q", result.Framework, inject.FrameworkHybrid)
	}
	if len(result.Seams) == 0 {
		t.Errorf("hybrid scan emitted 0 seams")
	}
}
