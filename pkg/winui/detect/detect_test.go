/*
Copyright (c) 2026 Security Research
*/

package detect

import (
	"testing"
)

func TestDetectFromDeps_WinUI(t *testing.T) {
	got := DetectFromDeps([]PackageRef{{Name: "Microsoft.WinUI", Version: "1.5.0"}})
	if len(got) != 1 {
		t.Fatalf("want 1 entry, got %d (%+v)", len(got), got)
	}
	fi := got[0]
	if fi.Name != "WinUI 3" {
		t.Errorf("Name = %q, want %q", fi.Name, "WinUI 3")
	}
	if fi.Source != "dotnet-deps" {
		t.Errorf("Source = %q, want %q", fi.Source, "dotnet-deps")
	}
	if fi.Confidence != "high" {
		t.Errorf("Confidence = %q, want %q", fi.Confidence, "high")
	}
	if len(fi.Evidence) == 0 || fi.Evidence[0] != "Microsoft.WinUI 1.5.0" {
		t.Errorf("Evidence = %v, want [\"Microsoft.WinUI 1.5.0\"]", fi.Evidence)
	}
}

func TestDetectFromDeps_WindowsAppSDK(t *testing.T) {
	got := DetectFromDeps([]PackageRef{{Name: "Microsoft.WindowsAppSDK", Version: "1.6.0"}})
	if len(got) != 1 {
		t.Fatalf("want 1 entry, got %d", len(got))
	}
	if got[0].Name != "WindowsAppSDK" {
		t.Errorf("Name = %q, want WindowsAppSDK", got[0].Name)
	}
	if got[0].Source != "dotnet-deps" {
		t.Errorf("Source = %q", got[0].Source)
	}
	if got[0].Confidence != "high" {
		t.Errorf("Confidence = %q", got[0].Confidence)
	}
}

func TestDetectFromDeps_WindowsAppRuntime_Medium(t *testing.T) {
	got := DetectFromDeps([]PackageRef{{Name: "Microsoft.WindowsAppRuntime.1.6", Version: "6000.0"}})
	if len(got) != 1 {
		t.Fatalf("want 1 entry, got %d", len(got))
	}
	if got[0].Confidence != "medium" {
		t.Errorf("Confidence = %q, want medium", got[0].Confidence)
	}
}

func TestDetectFromDeps_None(t *testing.T) {
	got := DetectFromDeps([]PackageRef{{Name: "Newtonsoft.Json", Version: "13.0.3"}})
	if len(got) != 0 {
		t.Errorf("want empty, got %v", got)
	}
}

func TestDetectFromDeps_Empty(t *testing.T) {
	if got := DetectFromDeps(nil); got != nil {
		t.Errorf("want nil, got %v", got)
	}
}

func TestDetectFromImports_MUX(t *testing.T) {
	got := DetectFromImports([]string{"KERNEL32.dll", "Microsoft.UI.Xaml.dll"})
	if len(got) != 1 {
		t.Fatalf("want 1 signal, got %d", len(got))
	}
	if got[0].Kind != "pe-import" {
		t.Errorf("Kind = %q", got[0].Kind)
	}
	if got[0].Confidence != "high" {
		t.Errorf("Confidence = %q, want high", got[0].Confidence)
	}
	if got[0].Detail != "Microsoft.UI.Xaml.dll" {
		t.Errorf("Detail = %q", got[0].Detail)
	}
}

func TestDetectFromImports_WUX(t *testing.T) {
	got := DetectFromImports([]string{"Windows.UI.Xaml.dll"})
	if len(got) != 1 {
		t.Fatalf("want 1 signal, got %d", len(got))
	}
	if got[0].Confidence != "medium" {
		t.Errorf("Confidence = %q, want medium", got[0].Confidence)
	}
}

func TestDetectFromImports_CaseInsensitive(t *testing.T) {
	got := DetectFromImports([]string{"microsoft.ui.xaml.DLL"})
	if len(got) != 1 {
		t.Fatalf("want 1 signal, got %d", len(got))
	}
	if got[0].Detail != "Microsoft.UI.Xaml.dll" {
		t.Errorf("Detail = %q (must canonicalize)", got[0].Detail)
	}
}

func TestDetectFromImports_None(t *testing.T) {
	if got := DetectFromImports([]string{"KERNEL32.dll", "USER32.dll"}); len(got) != 0 {
		t.Errorf("want empty, got %v", got)
	}
}

func TestIsValidConfidence_Indirect(t *testing.T) {
	// All emitted FrameworkInfo entries from this detector must be valid.
	got := DetectFromDeps([]PackageRef{
		{Name: "Microsoft.WinUI", Version: "1.5.0"},
		{Name: "Microsoft.WindowsAppSDK", Version: "1.6.0"},
		{Name: "Microsoft.WindowsAppRuntime.1.6", Version: "6000.0"},
	})
	wantConfs := map[string]string{
		"WinUI 3":           "high",
		"WindowsAppSDK":     "high",
		"WindowsAppRuntime": "medium",
	}
	for _, fi := range got {
		if want, ok := wantConfs[fi.Name]; ok && fi.Confidence != want {
			t.Errorf("%s confidence = %q, want %q", fi.Name, fi.Confidence, want)
		}
	}
}
