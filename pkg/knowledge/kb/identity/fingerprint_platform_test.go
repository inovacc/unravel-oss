package identity

import "testing"

func TestPlatformForArtifact(t *testing.T) {
	cases := map[string]string{
		"app.dll":      "windows-pe",
		"App.EXE":      "windows-pe",
		"Package.msix": "windows-msix",
		"bundle.appx":  "windows-msix",
		"game.apk":     "android",
		"App.ipa":      "ios",
		"pkg.deb":      "linux-deb",
		"pkg.rpm":      "linux-rpm",
		"mod.wasm":     "web",
		"lib.so":       "linux-elf",
		"Helper.dylib": "macos",
		"service.jar":  "other",
		"addon.node":   "other",
		"noextension":  "other",
		"":             "other",
	}
	for name, want := range cases {
		if got := PlatformForArtifact(name); got != want {
			t.Errorf("PlatformForArtifact(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestPlatformForArtifact_AlwaysInSet(t *testing.T) {
	// Every returned platform must be accepted by Fingerprint.
	for _, name := range []string{"x.dll", "y.jar", "z", "a.wasm", "b.so"} {
		in := FingerprintInputs{Platform: PlatformForArtifact(name), DisplayName: name}
		if _, _, err := Fingerprint(in); err != nil {
			t.Errorf("synthesized platform for %q rejected by Fingerprint: %v", name, err)
		}
	}
}
