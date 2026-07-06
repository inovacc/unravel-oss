/*
Copyright (c) 2026 Security Research
*/

package dotnet

import (
	"os"
	"path/filepath"
	"testing"
)

// TestFrameworkPatternsWinUI verifies that the deps.json parser recognizes
// Microsoft.WinUI and Microsoft.WindowsAppSDK package families and surfaces
// them in the Frameworks slice.
func TestFrameworkPatternsWinUI(t *testing.T) {
	dir := t.TempDir()
	depsPath := filepath.Join(dir, "app.deps.json")
	body := `{
  "runtimeTarget": {"name": ".NETCoreApp,Version=v8.0/win-x64"},
  "targets": {
    ".NETCoreApp,Version=v8.0/win-x64": {
      "Microsoft.WinUI/1.5.0": {"dependencies": {}},
      "Microsoft.WindowsAppSDK/1.6.0": {"dependencies": {}},
      "Newtonsoft.Json/13.0.3": {"dependencies": {}}
    }
  },
  "libraries": {
    "Microsoft.WinUI/1.5.0": {"type": "package", "serviceable": true, "sha512": "", "path": "", "hashPath": ""},
    "Microsoft.WindowsAppSDK/1.6.0": {"type": "package", "serviceable": true, "sha512": "", "path": "", "hashPath": ""},
    "Newtonsoft.Json/13.0.3": {"type": "package", "serviceable": true, "sha512": "", "path": "", "hashPath": ""}
  }
}`
	if err := os.WriteFile(depsPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	res, err := ParseDeps(depsPath)
	if err != nil {
		t.Fatalf("ParseDeps: %v", err)
	}
	want := map[string]bool{
		"WinUI 3":       false,
		"WindowsAppSDK": false,
	}
	for _, fw := range res.Frameworks {
		if _, ok := want[fw]; ok {
			want[fw] = true
		}
	}
	for fw, found := range want {
		if !found {
			t.Errorf("framework %q missing from Frameworks: %v", fw, res.Frameworks)
		}
	}
}

func TestFrameworkPatternsWindowsAppRuntime(t *testing.T) {
	dir := t.TempDir()
	depsPath := filepath.Join(dir, "app.deps.json")
	body := `{
  "runtimeTarget": {"name": ".NETCoreApp,Version=v8.0/win-x64"},
  "targets": {
    ".NETCoreApp,Version=v8.0/win-x64": {
      "Microsoft.WindowsAppRuntime.1.6/6000.0": {"dependencies": {}}
    }
  },
  "libraries": {
    "Microsoft.WindowsAppRuntime.1.6/6000.0": {"type": "package", "serviceable": true, "sha512": "", "path": "", "hashPath": ""}
  }
}`
	if err := os.WriteFile(depsPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	res, err := ParseDeps(depsPath)
	if err != nil {
		t.Fatalf("ParseDeps: %v", err)
	}
	found := false
	for _, fw := range res.Frameworks {
		if fw == "WindowsAppRuntime" {
			found = true
		}
	}
	if !found {
		t.Errorf("WindowsAppRuntime missing from Frameworks: %v", res.Frameworks)
	}
}
