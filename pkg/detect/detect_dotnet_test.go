/*
Copyright (c) 2026 Security Research
*/

package detect

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func TestDetectDotNetDir_PlainApp(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "MyApp.deps.json", `{"runtimeTarget":{}}`)
	writeFile(t, dir, "MyApp.runtimeconfig.json", `{"runtimeOptions":{"tfm":"net8.0","framework":{"name":"Microsoft.NETCore.App","version":"8.0.0"}}}`)
	res := &DetectResult{Path: dir}
	if !detectDotNetDir(res, dir) {
		t.Fatalf("expected .NET detection to fire on app dir")
	}
	if res.FileType != TypeDotNetApp {
		t.Errorf("FileType = %q, want %q (plain app — no Service.exe, no ASP.NET, no Hosting)", res.FileType, TypeDotNetApp)
	}
}

func TestDetectDotNetDir_ServiceViaWorkerSuffixedExe(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "MyBackgroundWorker.deps.json", `{"runtimeTarget":{}}`)
	writeFile(t, dir, "MyBackgroundWorker.runtimeconfig.json", `{"runtimeOptions":{"tfm":"net8.0"}}`)
	writeFile(t, dir, "MyBackgroundWorker.exe", "PE\x00\x00")
	res := &DetectResult{Path: dir}
	if !detectDotNetDir(res, dir) {
		t.Fatalf("expected .NET detection to fire")
	}
	if res.FileType != TypeDotNetService {
		t.Errorf("FileType = %q, want %q (Worker-suffixed .exe is the Generic Host pattern)", res.FileType, TypeDotNetService)
	}
}

func TestDetectDotNetDir_ServiceViaAspNetCore(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "WebApi.deps.json", `{"runtimeTarget":{}}`)
	writeFile(t, dir, "WebApi.runtimeconfig.json", `{"runtimeOptions":{"tfm":"net8.0","frameworks":[{"name":"Microsoft.AspNetCore.App","version":"8.0.0"}]}}`)
	writeFile(t, dir, "WebApi.exe", "PE\x00\x00")
	res := &DetectResult{Path: dir}
	if !detectDotNetDir(res, dir) {
		t.Fatalf("expected .NET detection to fire")
	}
	if res.FileType != TypeDotNetService {
		t.Errorf("FileType = %q, want %q (ASP.NET Core framework reference is a long-running daemon signal)", res.FileType, TypeDotNetService)
	}
}

func TestDetectDotNetDir_MissingRuntimeConfigSkips(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "MyApp.deps.json", `{}`)
	res := &DetectResult{Path: dir}
	if detectDotNetDir(res, dir) {
		t.Errorf("expected no detection on lone .deps.json (need both sibling files)")
	}
}

func TestDetectDotNetDir_MissingDepsSkips(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "MyApp.runtimeconfig.json", `{}`)
	res := &DetectResult{Path: dir}
	if detectDotNetDir(res, dir) {
		t.Errorf("expected no detection on lone .runtimeconfig.json")
	}
}
