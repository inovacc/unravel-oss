/*
Copyright (c) 2026 Security Research
*/

package identity_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/identity"
	_ "github.com/inovacc/unravel-oss/pkg/knowledge/kb/identity/resolvers/uwp" // register UWP resolver via init()
)

func mustHash(t *testing.T, key, platform string) string {
	t.Helper()
	h := sha256.Sum256([]byte(key + "|" + platform))
	return hex.EncodeToString(h[:8])
}

func TestFingerprint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		in         identity.FingerprintInputs
		wantKBKey  string // pre-hash key; "" means expect error
		wantKBPlat string
		wantKSID   string
		wantErrSub string
	}{
		{
			name: "package_id wins for msix",
			in: identity.FingerprintInputs{
				Platform:   "windows-msix",
				PackageID:  "ContosoCorp.MyApp_8wekyb3d8bbwe",
				AppVersion: "1.2.3",
				CapturedAt: 1714694400,
			},
			wantKBKey:  "ContosoCorp.MyApp_8wekyb3d8bbwe",
			wantKBPlat: "windows-msix",
		},
		{
			name: "canonical_name fallback when package_id empty",
			in: identity.FingerprintInputs{
				Platform:    "electron",
				DisplayName: "My Cool App!!",
				AppVersion:  "0.1.0",
				CapturedAt:  100,
			},
			wantKBKey:  "my-cool-app",
			wantKBPlat: "electron",
		},
		{
			name: "missing app_version becomes unknown",
			in: identity.FingerprintInputs{
				Platform:   "tauri",
				PackageID:  "com.example.app",
				CapturedAt: 42,
			},
			wantKBKey:  "com.example.app",
			wantKBPlat: "tauri",
		},
		{
			name:       "platform required",
			in:         identity.FingerprintInputs{PackageID: "foo"},
			wantErrSub: "platform is required",
		},
		{
			name:       "unknown platform rejected",
			in:         identity.FingerprintInputs{Platform: "haiku", PackageID: "x"},
			wantErrSub: "unknown platform",
		},
		{
			name:       "no package_id and no display_name",
			in:         identity.FingerprintInputs{Platform: "electron"},
			wantErrSub: "display_name required when package_id absent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			kbID, ksID, err := identity.Fingerprint(tt.in)
			if tt.wantErrSub != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrSub) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErrSub, err)
				}
				if tt.wantErrSub == "unknown platform" && !errors.Is(err, identity.ErrUnknownPlatform) {
					t.Fatalf("expected ErrUnknownPlatform sentinel, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			wantKB := mustHash(t, tt.wantKBKey, tt.wantKBPlat)
			if kbID != wantKB {
				t.Fatalf("kbID mismatch: got %s want %s", kbID, wantKB)
			}
			if len(kbID) != 16 {
				t.Fatalf("kbID length: got %d want 16", len(kbID))
			}
			version := tt.in.AppVersion
			if version == "" {
				version = "unknown"
			}
			wantKS := wantKB + ":" + version + ":" + intStr(tt.in.CapturedAt)
			if ksID != wantKS {
				t.Fatalf("ksID mismatch: got %s want %s", ksID, wantKS)
			}
		})
	}
}

func intStr(n int64) string {
	// avoid pulling strconv into tests just for one site; use fmt-free fast path.
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if negative {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func TestCanonicalName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in, want string
	}{
		{"  --My Cool App!! 1.2  ", "my-cool-app-1-2"},
		{"FooBar", "foobar"},
		{"___", ""},
		{"", ""},
		{"ALL CAPS", "all-caps"},
		{"a/b/c", "a-b-c"},
	}
	for _, tt := range tests {
		got := identity.CanonicalName(tt.in)
		if got != tt.want {
			t.Errorf("CanonicalName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestRegistry(t *testing.T) {
	// Not parallel: mutates the global resolver map.
	called := false
	identity.Register("test-platform-xyz", func(ctx identity.ResolverContext) (string, error) {
		called = true
		return "got:" + ctx.Path, nil
	})

	got, err := identity.Resolve(identity.ResolverContext{Platform: "test-platform-xyz", Path: "/p"})
	if err != nil {
		t.Fatalf("resolve err: %v", err)
	}
	if !called {
		t.Fatalf("registered resolver not invoked")
	}
	if got != "got:/p" {
		t.Fatalf("resolver result mismatch: %q", got)
	}

	// Unregistered platform returns ("", nil) so caller can fall back.
	got, err = identity.Resolve(identity.ResolverContext{Platform: "no-such-platform-zzz"})
	if err != nil {
		t.Fatalf("unexpected err for unregistered platform: %v", err)
	}
	if got != "" {
		t.Fatalf("expected empty result for unregistered platform, got %q", got)
	}
}

func TestUWPResolver(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "AppxManifest.xml")
	const xml = `<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="ContosoCorp.MyApp" Publisher="CN=Contoso" Version="1.0.0.0"/>
  <Properties><DisplayName>My App</DisplayName></Properties>
</Package>`
	if err := os.WriteFile(manifestPath, []byte(xml), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	// Path = directory case
	got, err := identity.Resolve(identity.ResolverContext{Platform: "windows-msix", Path: dir})
	if err != nil {
		t.Fatalf("resolve dir: %v", err)
	}
	if got != "ContosoCorp.MyApp" {
		t.Fatalf("dir resolve: got %q want %q", got, "ContosoCorp.MyApp")
	}

	// Path = file case
	got, err = identity.Resolve(identity.ResolverContext{Platform: "windows-msix", Path: manifestPath})
	if err != nil {
		t.Fatalf("resolve file: %v", err)
	}
	if got != "ContosoCorp.MyApp" {
		t.Fatalf("file resolve: got %q want %q", got, "ContosoCorp.MyApp")
	}

	// Missing file is an error.
	_, err = identity.Resolve(identity.ResolverContext{Platform: "windows-msix", Path: filepath.Join(dir, "missing")})
	if err == nil {
		t.Fatalf("expected error for missing manifest")
	}
}

func TestAllocateEpochNilTx(t *testing.T) {
	t.Parallel()
	_, err := identity.AllocateEpoch(testCtx(), nil, "kb")
	if err == nil || !strings.Contains(err.Error(), "tx is required") {
		t.Fatalf("expected 'tx is required' error, got %v", err)
	}
}

func testCtx() context.Context { return context.Background() }
