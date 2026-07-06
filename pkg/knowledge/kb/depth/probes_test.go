/*
Copyright (c) 2026 Security Research

Per-probe synthetic-fixture tests for the 12 depth probes. Each probe gets
at least one positive and one negative case; ManagedSource gets boundary
coverage (9 vs 10 files).

License: BSD-3-Clause.
*/
package depth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeJSON(t *testing.T, dir string, payload map[string]any) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "knowledge.json"), b, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// --- probeFramework ----------------------------------------------------------

func TestProbeFramework(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		dir := t.TempDir()
		writeJSON(t, dir, map[string]any{"framework": "electron"})
		ok, _ := probeFramework(dir, nil)
		if !ok {
			t.Errorf("expected covered")
		}
	})
	t.Run("empty_string", func(t *testing.T) {
		dir := t.TempDir()
		writeJSON(t, dir, map[string]any{"framework": ""})
		ok, _ := probeFramework(dir, nil)
		if ok {
			t.Errorf("expected uncovered for empty string")
		}
	})
	t.Run("missing_file", func(t *testing.T) {
		dir := t.TempDir()
		ok, _ := probeFramework(dir, nil)
		if ok {
			t.Errorf("expected uncovered when knowledge.json missing")
		}
	})
	t.Run("empty_ksDir", func(t *testing.T) {
		ok, _ := probeFramework("", nil)
		if ok {
			t.Errorf("expected uncovered for empty ksDir")
		}
	})
}

// --- probeManagedSource boundary ---------------------------------------------

func TestProbeManagedSource_Boundary(t *testing.T) {
	mkDecomp := func(t *testing.T, n int) string {
		t.Helper()
		dir := t.TempDir()
		decomp := filepath.Join(dir, "decompiled")
		if err := os.MkdirAll(decomp, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		for i := range n {
			if err := os.WriteFile(filepath.Join(decomp, "f"+itoa(i)+".java"), []byte("x"), 0o644); err != nil {
				t.Fatalf("write: %v", err)
			}
		}
		return dir
	}
	t.Run("ten_files_covered", func(t *testing.T) {
		dir := mkDecomp(t, 10)
		ok, _ := probeManagedSource(dir, nil)
		if !ok {
			t.Errorf("expected covered at 10 files")
		}
	})
	t.Run("nine_files_uncovered", func(t *testing.T) {
		dir := mkDecomp(t, 9)
		ok, _ := probeManagedSource(dir, nil)
		if ok {
			t.Errorf("expected uncovered at 9 files (boundary)")
		}
	})
	t.Run("missing_dir", func(t *testing.T) {
		ok, _ := probeManagedSource(t.TempDir(), nil)
		if ok {
			t.Errorf("expected uncovered when no decompiled/ or sources/source/")
		}
	})
}

// --- probeUI -----------------------------------------------------------------

func TestProbeUI(t *testing.T) {
	t.Run("sources_ui_with_file", func(t *testing.T) {
		dir := t.TempDir()
		ui := filepath.Join(dir, "sources", "ui")
		_ = os.MkdirAll(ui, 0o755)
		_ = os.WriteFile(filepath.Join(ui, "App.tsx"), []byte("x"), 0o644)
		ok, _ := probeUI(dir, nil)
		if !ok {
			t.Errorf("expected covered")
		}
	})
	t.Run("xaml_dir", func(t *testing.T) {
		dir := t.TempDir()
		_ = os.MkdirAll(filepath.Join(dir, "xaml"), 0o755)
		ok, _ := probeUI(dir, nil)
		if !ok {
			t.Errorf("expected covered for xaml/")
		}
	})
	t.Run("empty", func(t *testing.T) {
		ok, _ := probeUI(t.TempDir(), nil)
		if ok {
			t.Errorf("expected uncovered")
		}
	})
}

// --- probeDeps ---------------------------------------------------------------

func TestProbeDeps(t *testing.T) {
	t.Run("dependencies", func(t *testing.T) {
		dir := t.TempDir()
		writeJSON(t, dir, map[string]any{"dependencies": []any{"react"}})
		ok, _ := probeDeps(dir, nil)
		if !ok {
			t.Errorf("expected covered")
		}
	})
	t.Run("manifest_dependencies", func(t *testing.T) {
		dir := t.TempDir()
		writeJSON(t, dir, map[string]any{"manifest": map[string]any{"dependencies": []any{"x"}}})
		ok, _ := probeDeps(dir, nil)
		if !ok {
			t.Errorf("expected covered for manifest.dependencies")
		}
	})
	t.Run("empty", func(t *testing.T) {
		ok, _ := probeDeps(t.TempDir(), nil)
		if ok {
			t.Errorf("expected uncovered")
		}
	})
}

// --- probeWireProtocol -------------------------------------------------------

func TestProbeWireProtocol(t *testing.T) {
	t.Run("proto_file", func(t *testing.T) {
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, "api.proto"), []byte("syntax=\"proto3\";"), 0o644)
		ok, _ := probeWireProtocol(dir, nil)
		if !ok {
			t.Errorf("expected covered")
		}
	})
	t.Run("protobuf_modules", func(t *testing.T) {
		dir := t.TempDir()
		writeJSON(t, dir, map[string]any{"protobuf_modules": []any{"foo.proto"}})
		ok, _ := probeWireProtocol(dir, nil)
		if !ok {
			t.Errorf("expected covered")
		}
	})
	t.Run("empty", func(t *testing.T) {
		ok, _ := probeWireProtocol(t.TempDir(), nil)
		if ok {
			t.Errorf("expected uncovered")
		}
	})
}

// --- probeAuth ---------------------------------------------------------------

func TestProbeAuth(t *testing.T) {
	t.Run("sources_auth_dir", func(t *testing.T) {
		dir := t.TempDir()
		_ = os.MkdirAll(filepath.Join(dir, "sources", "auth"), 0o755)
		ok, _ := probeAuth(dir, nil)
		if !ok {
			t.Errorf("expected covered")
		}
	})
	t.Run("kjson_auth", func(t *testing.T) {
		dir := t.TempDir()
		writeJSON(t, dir, map[string]any{"auth": []any{"oauth"}})
		ok, _ := probeAuth(dir, nil)
		if !ok {
			t.Errorf("expected covered")
		}
	})
	t.Run("empty", func(t *testing.T) {
		ok, _ := probeAuth(t.TempDir(), nil)
		if ok {
			t.Errorf("expected uncovered")
		}
	})
}

// --- probeNative -------------------------------------------------------------

func TestProbeNative(t *testing.T) {
	t.Run("lib_so", func(t *testing.T) {
		dir := t.TempDir()
		lib := filepath.Join(dir, "lib")
		_ = os.MkdirAll(lib, 0o755)
		_ = os.WriteFile(filepath.Join(lib, "foo.so"), []byte("\x7fELF"), 0o644)
		ok, _ := probeNative(dir, nil)
		if !ok {
			t.Errorf("expected covered")
		}
	})
	t.Run("native_dll", func(t *testing.T) {
		dir := t.TempDir()
		nd := filepath.Join(dir, "native")
		_ = os.MkdirAll(nd, 0o755)
		_ = os.WriteFile(filepath.Join(nd, "bar.dll"), []byte("MZ"), 0o644)
		ok, _ := probeNative(dir, nil)
		if !ok {
			t.Errorf("expected covered")
		}
	})
	t.Run("dll_at_root_uncovered", func(t *testing.T) {
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, "loose.dll"), []byte("MZ"), 0o644)
		ok, _ := probeNative(dir, nil)
		if ok {
			t.Errorf("expected uncovered when not under native/ or lib*/")
		}
	})
}

// --- probeWebview ------------------------------------------------------------

func TestProbeWebview(t *testing.T) {
	t.Run("webview_dir", func(t *testing.T) {
		dir := t.TempDir()
		_ = os.MkdirAll(filepath.Join(dir, "webview"), 0o755)
		ok, _ := probeWebview(dir, nil)
		if !ok {
			t.Errorf("expected covered")
		}
	})
	t.Run("empty", func(t *testing.T) {
		ok, _ := probeWebview(t.TempDir(), nil)
		if ok {
			t.Errorf("expected uncovered")
		}
	})
}

// --- probeStorage ------------------------------------------------------------

func TestProbeStorage(t *testing.T) {
	t.Run("leveldb_dir", func(t *testing.T) {
		dir := t.TempDir()
		_ = os.MkdirAll(filepath.Join(dir, "leveldb"), 0o755)
		ok, _ := probeStorage(dir, nil)
		if !ok {
			t.Errorf("expected covered")
		}
	})
	t.Run("sqlite_file", func(t *testing.T) {
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, "data.sqlite"), []byte("SQLite"), 0o644)
		ok, _ := probeStorage(dir, nil)
		if !ok {
			t.Errorf("expected covered")
		}
	})
	t.Run("empty", func(t *testing.T) {
		ok, _ := probeStorage(t.TempDir(), nil)
		if ok {
			t.Errorf("expected uncovered")
		}
	})
}

// --- probeTelemetry ----------------------------------------------------------

func TestProbeTelemetry(t *testing.T) {
	t.Run("kjson_telemetry", func(t *testing.T) {
		dir := t.TempDir()
		writeJSON(t, dir, map[string]any{"telemetry": []any{"ga"}})
		ok, _ := probeTelemetry(dir, nil)
		if !ok {
			t.Errorf("expected covered")
		}
	})
	t.Run("telemetry_dir_with_file", func(t *testing.T) {
		dir := t.TempDir()
		td := filepath.Join(dir, "telemetry")
		_ = os.MkdirAll(td, 0o755)
		_ = os.WriteFile(filepath.Join(td, "x.txt"), []byte("x"), 0o644)
		ok, _ := probeTelemetry(dir, nil)
		if !ok {
			t.Errorf("expected covered")
		}
	})
	t.Run("empty", func(t *testing.T) {
		ok, _ := probeTelemetry(t.TempDir(), nil)
		if ok {
			t.Errorf("expected uncovered")
		}
	})
}

// --- probeRuntime ------------------------------------------------------------

func TestProbeRuntime(t *testing.T) {
	t.Run("frida", func(t *testing.T) {
		dir := t.TempDir()
		_ = os.MkdirAll(filepath.Join(dir, "frida"), 0o755)
		ok, _ := probeRuntime(dir, nil)
		if !ok {
			t.Errorf("expected covered")
		}
	})
	t.Run("capture_json", func(t *testing.T) {
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, "capture.json"), []byte("{}"), 0o644)
		ok, _ := probeRuntime(dir, nil)
		if !ok {
			t.Errorf("expected covered")
		}
	})
	t.Run("empty", func(t *testing.T) {
		ok, _ := probeRuntime(t.TempDir(), nil)
		if ok {
			t.Errorf("expected uncovered")
		}
	})
}

// --- probeIdentity nil-conn --------------------------------------------------

func TestProbeIdentity_NilConn(t *testing.T) {
	ok, _ := probeIdentity(t.TempDir(), nil)
	if ok {
		t.Errorf("expected uncovered when conn is nil")
	}
}
