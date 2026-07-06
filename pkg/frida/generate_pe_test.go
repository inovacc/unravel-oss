/*
Copyright (c) 2026 Security Research
*/
package frida

import (
	"strings"
	"testing"
)

func TestGenerate_WindowsPE_DefaultsToMainOnly(t *testing.T) {
	r := Generate(ScriptConfig{Target: TargetWindowsPE, PackageName: "WhatsApp.Root.exe"})
	if len(r.Scripts) != 1 || r.Scripts[0].Name != "main" {
		t.Fatalf("expected lone main.js entry script, got %v", scriptNames(r.Scripts))
	}
}

func TestGenerate_WindowsPE_NetworkAndCrypto(t *testing.T) {
	r := Generate(ScriptConfig{
		Target:         TargetWindowsPE,
		IncludeNetwork: true,
		IncludeCrypto:  true,
		IncludeDebug:   true,
		CustomHooks:    []string{"WAExt.dll!noise_seal"},
	})

	want := []string{"schannel_capture", "boringssl_capture", "bcrypt_monitor", "dpapi_monitor", "anti_debug_bypass", "custom_WAExt_dll_noise_seal", "main"}
	got := scriptNames(r.Scripts)
	if len(got) != len(want) {
		t.Fatalf("script count = %d %v, want %d %v", len(got), got, len(want), want)
	}
	for i, name := range want {
		if got[i] != name {
			t.Errorf("scripts[%d] = %q, want %q", i, got[i], name)
		}
	}

	// PE scripts must NOT contain Java.perform — that's the JVM-only path.
	for _, s := range r.Scripts {
		if strings.Contains(s.Content, "Java.perform") {
			t.Errorf("PE script %q contains Java.perform (Android-only)", s.Name)
		}
	}

	// Network capture must reference Schannel.
	var net *GeneratedScript
	for i := range r.Scripts {
		if r.Scripts[i].Name == "schannel_capture" {
			net = &r.Scripts[i]
			break
		}
	}
	if net == nil || !strings.Contains(net.Content, "EncryptMessage") {
		t.Error("schannel_capture missing EncryptMessage hook")
	}
}

func TestGenerate_WindowsPE_BoringSSL_Content(t *testing.T) {
	r := Generate(ScriptConfig{Target: TargetWindowsPE, IncludeNetwork: true})

	var bssl *GeneratedScript
	for i := range r.Scripts {
		if r.Scripts[i].Name == "boringssl_capture" {
			bssl = &r.Scripts[i]
			break
		}
	}
	if bssl == nil {
		t.Fatalf("boringssl_capture not emitted with IncludeNetwork=true; got %v", scriptNames(r.Scripts))
	}

	// Three resolver strategies (export → symbol → pattern).
	resolvers := []string{"findExportByName", "enumerateSymbols", "Memory.scanSync"}
	for _, kw := range resolvers {
		if !strings.Contains(bssl.Content, kw) {
			t.Errorf("boringssl_capture missing resolver keyword %q", kw)
		}
	}

	// Four honest-scoring tags.
	tags := []string{"BORINGSSL_TARGET", "BORINGSSL_HOOK", "BORINGSSL_PATTERN", "BORINGSSL_GIVE_UP"}
	for _, tag := range tags {
		if !strings.Contains(bssl.Content, tag) {
			t.Errorf("boringssl_capture missing tag %q", tag)
		}
	}

	// IncludeSSL alone must also emit the script (gate is IncludeNetwork||IncludeSSL).
	r2 := Generate(ScriptConfig{Target: TargetWindowsPE, IncludeSSL: true})
	found := false
	for _, s := range r2.Scripts {
		if s.Name == "boringssl_capture" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("boringssl_capture not emitted with IncludeSSL=true; got %v", scriptNames(r2.Scripts))
	}
}

func TestGenerate_WindowsPE_BoringSSL_NotEmitted(t *testing.T) {
	// Negative: IncludeNetwork=false AND IncludeSSL=false ⇒ no boringssl_capture.
	r := Generate(ScriptConfig{
		Target:        TargetWindowsPE,
		IncludeCrypto: true,
		IncludeDebug:  true,
	})
	for _, s := range r.Scripts {
		if s.Name == "boringssl_capture" {
			t.Fatalf("boringssl_capture leaked when IncludeNetwork=false && IncludeSSL=false; got %v", scriptNames(r.Scripts))
		}
	}

	// Negative: Android target must never emit the PE BSSL script.
	rAndroid := Generate(ScriptConfig{Target: TargetAndroid, IncludeNetwork: true})
	for _, s := range rAndroid.Scripts {
		if s.Name == "boringssl_capture" {
			t.Fatalf("boringssl_capture leaked into Android pack; got %v", scriptNames(rAndroid.Scripts))
		}
	}
}

func TestGenerate_AndroidUnchanged(t *testing.T) {
	// Backwards-compat: empty Target must keep emitting Java.perform scripts.
	r := Generate(ScriptConfig{IncludeNetwork: true})
	if len(r.Scripts) != 1 || r.Scripts[0].Name != "network_capture" {
		t.Fatalf("Android path regressed: %v", scriptNames(r.Scripts))
	}
	if !strings.Contains(r.Scripts[0].Content, "Java.perform") {
		t.Error("Android network_capture lost Java.perform")
	}
}

func scriptNames(s []GeneratedScript) []string {
	out := make([]string, len(s))
	for i, x := range s {
		out[i] = x.Name
	}
	return out
}
