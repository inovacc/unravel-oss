/*
Copyright (c) 2026 Security Research
*/
package autogen

import (
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/inject"
)

func TestRender_LinuxHasPreflight(t *testing.T) {
	yes := true
	s := inject.Seam{
		Kind:                 "DT_NEEDED",
		Confidence:           inject.ConfidenceMedium,
		Framework:            inject.FrameworkElectron,
		Evidence:             []inject.Evidence{{Type: inject.EvidenceFileContent, Path: "libdl.so.2"}},
		PtraceEligibleBinary: &yes,
		PtraceFlags:          []string{"non_pie"},
	}
	js, err := renderJS(s, "linux", "abc12345")
	if err != nil {
		t.Fatal(err)
	}
	str := string(js)
	for _, want := range []string{
		"preflight: ptrace_scope",
		"/proc/sys/kernel/yama/ptrace_scope",
		"preflight_failed",
		"throw new Error",
	} {
		if !strings.Contains(str, want) {
			t.Errorf("linux template missing %q", want)
		}
	}
}

func TestRender_WindowsNoPreflight(t *testing.T) {
	s := inject.Seam{
		Kind:      "IAT",
		Framework: inject.FrameworkElectron,
		Evidence:  []inject.Evidence{{Type: inject.EvidencePEImport, Path: "app.exe"}},
	}
	js, err := renderJS(s, "windows", "deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(js), "ptrace_scope") {
		t.Error("windows template must not contain ptrace_scope")
	}
	if !strings.Contains(string(js), "LoadLibraryW") {
		t.Error("windows template should hook LoadLibraryW")
	}
}

func TestRender_MacOSNoPreflight(t *testing.T) {
	s := inject.Seam{
		Kind:          "LC_LOAD_DYLIB",
		Framework:     inject.FrameworkMacOS,
		Evidence:      []inject.Evidence{{Type: inject.EvidenceFileContent, Path: "/usr/lib/libSystem.B.dylib"}},
		SigningBlocks: []string{"LC_CODE_SIGNATURE"},
	}
	js, err := renderJS(s, "macos", "cafef00d")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(js), "ptrace_scope") {
		t.Error("macos template must not contain ptrace_scope")
	}
	if !strings.Contains(string(js), "dlopen_intercepted") {
		t.Error("macos template should emit dlopen_intercepted")
	}
}

func TestRender_UnknownPlatform(t *testing.T) {
	_, err := renderJS(inject.Seam{}, "plan9", "00000000")
	if err == nil {
		t.Fatal("expected error for unknown platform")
	}
}
