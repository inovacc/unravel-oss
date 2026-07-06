/*
Copyright (c) 2026 Security Research
*/
package manifest

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/msix"
)

func TestSummarize_NilSafe(t *testing.T) {
	if got := Summarize(nil); got != nil {
		t.Errorf("Summarize(nil) = %+v, want nil", got)
	}
}

func TestSummarize_PreservesOrder(t *testing.T) {
	xml := []byte(`<?xml version="1.0"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">
  <Identity Name="A" Version="1.0.0.0" Publisher="CN=X"/>
  <Capabilities>
    <Capability Name="internetClient"/>
    <uap:Capability Name="userDataSystem"/>
    <rescap:Capability Name="runFullTrust"/>
  </Capabilities>
</Package>`)
	m, err := msix.ParseAppxManifest(xml)
	if err != nil {
		t.Fatal(err)
	}

	sum := Summarize(m)
	if len(sum.Capabilities) != 3 {
		t.Fatalf("expected 3 capabilities, got %d", len(sum.Capabilities))
	}

	wantNames := []string{"internetClient", "userDataSystem", "runFullTrust"}
	wantNS := []string{"", "uap", "rescap"}
	for i, c := range sum.Capabilities {
		if c.Name != wantNames[i] {
			t.Errorf("[%d] name=%q want %q", i, c.Name, wantNames[i])
		}
		if c.Namespace != wantNS[i] {
			t.Errorf("[%d] ns=%q want %q", i, c.Namespace, wantNS[i])
		}
		if c.Index != i {
			t.Errorf("[%d] index=%d want %d", i, c.Index, i)
		}
	}
}

func TestSummarize_NamespaceTagging(t *testing.T) {
	xml := []byte(`<?xml version="1.0"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:uap2="http://schemas.microsoft.com/appx/manifest/uap/windows10/2"
         xmlns:uap4="http://schemas.microsoft.com/appx/manifest/foundation/windows10/4"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">
  <Identity Name="A" Version="1.0.0.0" Publisher="CN=X"/>
  <Capabilities>
    <Capability Name="internetClient"/>
    <uap:Capability Name="userDataSystem"/>
    <uap2:Capability Name="phoneCallHistorySystem"/>
    <rescap:Capability Name="runFullTrust"/>
    <DeviceCapability Name="webcam"/>
    <uap4:CustomCapability Name="contoso.cap_xx"/>
  </Capabilities>
</Package>`)
	m, err := msix.ParseAppxManifest(xml)
	if err != nil {
		t.Fatal(err)
	}
	sum := Summarize(m)

	wantNS := map[string]string{
		"internetClient":         "",
		"userDataSystem":         "uap",
		"phoneCallHistorySystem": "uap2",
		"runFullTrust":           "rescap",
		"webcam":                 "device",
		"contoso.cap_xx":         "custom",
	}
	for _, c := range sum.Capabilities {
		want, ok := wantNS[c.Name]
		if !ok {
			t.Errorf("unexpected capability %q", c.Name)
			continue
		}
		if c.Namespace != want {
			t.Errorf("%s: ns=%q want %q", c.Name, c.Namespace, want)
		}
	}
}

func TestSummarize_PFN(t *testing.T) {
	xml := []byte(`<?xml version="1.0"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="TestApp" Version="1.0.0.0" Publisher="CN=Test"/>
  <Applications>
    <Application Id="App" Executable="app.exe" EntryPoint="Windows.FullTrustApplication"/>
  </Applications>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22621.0"/>
  </Dependencies>
</Package>`)
	m, err := msix.ParseAppxManifest(xml)
	if err != nil {
		t.Fatal(err)
	}
	sum := Summarize(m)

	if sum.Identity.Name != "TestApp" {
		t.Errorf("Identity.Name=%q", sum.Identity.Name)
	}
	if sum.PFN == "" {
		t.Error("PFN empty")
	}
	if got := sum.PFN[:len("TestApp_")]; got != "TestApp_" {
		t.Errorf("PFN prefix=%q want TestApp_", got)
	}
	if len(sum.PFN) != len("TestApp_")+13 {
		t.Errorf("PFN length=%d want %d (publisher hash is 13 chars)", len(sum.PFN), len("TestApp_")+13)
	}
	if len(sum.EntryPoints) != 1 || sum.EntryPoints[0].Executable != "app.exe" {
		t.Errorf("EntryPoints wrong: %+v", sum.EntryPoints)
	}
	if len(sum.TargetFamilies) != 1 || sum.TargetFamilies[0] != "Windows.Desktop" {
		t.Errorf("TargetFamilies wrong: %+v", sum.TargetFamilies)
	}
}

func TestPublisherIdHash_Deterministic(t *testing.T) {
	// Same input => same output (deterministic).
	a := PublisherIdHash("CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US")
	b := PublisherIdHash("CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US")
	if a != b {
		t.Errorf("non-deterministic: %q vs %q", a, b)
	}
	if len(a) != 13 {
		t.Errorf("PublisherIdHash length=%d want 13", len(a))
	}
	// Alphabet check: only Crockford-style chars.
	for _, ch := range a {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z')) {
			t.Errorf("invalid char %q in hash %q", ch, a)
		}
		if ch == 'i' || ch == 'l' || ch == 'o' || ch == 'u' {
			t.Errorf("forbidden char %q in hash %q", ch, a)
		}
	}
}

func TestPublisherIdHash_Empty(t *testing.T) {
	if got := PublisherIdHash(""); got != "" {
		t.Errorf("PublisherIdHash(\"\")=%q want \"\"", got)
	}
}

func TestComputePFN_NoName(t *testing.T) {
	if got := ComputePFN("", "CN=X"); got != "" {
		t.Errorf("ComputePFN with empty name=%q want \"\"", got)
	}
}

func TestSummarize_FallbackOrder(t *testing.T) {
	// Build a CapabilitiesBlock manually (no OrderedRefs populated) — exercises
	// the degraded-path fallback.
	m := &msix.AppxManifest{}
	m.Identity.Name = "A"
	m.Identity.Publisher = "CN=X"
	m.Capabilities.Capability = []msix.NamedCap{{Name: "internetClient"}}
	m.Capabilities.UAPCapability = []msix.NamedCap{{Name: "userDataSystem"}}
	m.Capabilities.RestrictedCapability = []msix.NamedCap{{Name: "runFullTrust"}}

	sum := Summarize(m)
	if len(sum.Capabilities) != 3 {
		t.Fatalf("want 3 caps, got %d", len(sum.Capabilities))
	}
	wantNS := []string{"", "uap", "rescap"}
	for i, c := range sum.Capabilities {
		if c.Namespace != wantNS[i] {
			t.Errorf("[%d] ns=%q want %q", i, c.Namespace, wantNS[i])
		}
		if c.Index != i {
			t.Errorf("[%d] index=%d want %d", i, c.Index, i)
		}
	}
}
