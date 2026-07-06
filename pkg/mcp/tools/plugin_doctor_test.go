/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/aihost"
)

// TestDoctorContract_AllHostsReported pins the multi-host iteration in
// doctorContract: every registered host (claude, codex, gemini) appears under
// "hosts" with a structured Doctor() report. None falls back to the
// NOT_IMPLEMENTED string, since all three implement aihost.Doctor today.
func TestDoctorContract_AllHostsReported(t *testing.T) {
	c := doctorContract()

	for _, key := range []string{"required_mcp_tools", "required_plugin_commands", "hosts"} {
		if _, ok := c[key]; !ok {
			t.Errorf("contract missing key %q", key)
		}
	}

	hosts, ok := c["hosts"].(map[string]any)
	if !ok {
		t.Fatalf("contract hosts is %T, want map[string]any", c["hosts"])
	}
	for _, name := range []string{"claude", "codex", "gemini"} {
		entry, ok := hosts[name].(map[string]any)
		if !ok {
			t.Fatalf("hosts[%q] is %T, want map[string]any", name, hosts[name])
		}
		if entry["name"] != name {
			t.Errorf("hosts[%q].name = %v, want %q", name, entry["name"], name)
		}
		report, ok := entry["doctor"].(aihost.DoctorReport)
		if !ok {
			t.Fatalf("hosts[%q].doctor is %T, want aihost.DoctorReport (NOT_IMPLEMENTED fallback?)", name, entry["doctor"])
		}
		if report.Host != name {
			t.Errorf("hosts[%q].doctor.Host = %q, want %q", name, report.Host, name)
		}
		if report.Verdict == "" {
			t.Errorf("hosts[%q].doctor.Verdict is empty", name)
		}
	}
}

// TestCapabilityFallback_DetectsMissingDoctor pins the capability check that
// drives doctorContract's NOT_IMPLEMENTED branch: a host that does not
// implement aihost.Doctor must not satisfy the interface, while one that does
// must. Guards against an accidental Doctor interface change silently dropping
// every host into the fallback path.
func TestCapabilityFallback_DetectsMissingDoctor(t *testing.T) {
	var without aihost.Host = noDoctorHost{}
	if _, ok := without.(aihost.Doctor); ok {
		t.Fatal("noDoctorHost unexpectedly satisfies aihost.Doctor")
	}

	var with aihost.Host = withDoctorHost{}
	if _, ok := with.(aihost.Doctor); !ok {
		t.Fatal("withDoctorHost should satisfy aihost.Doctor")
	}
}

// noDoctorHost implements aihost.Host but deliberately omits Doctor().
type noDoctorHost struct{}

func (noDoctorHost) Name() string                                    { return "no-doctor" }
func (noDoctorHost) InstallTarget() (string, error)                  { return "", nil }
func (noDoctorHost) Walk(func(path string, data []byte) error) error { return nil }
func (noDoctorHost) ManifestFiles() (map[string][]byte, error)       { return nil, nil }

// withDoctorHost embeds noDoctorHost and adds Doctor(), satisfying both
// aihost.Host and aihost.Doctor.
type withDoctorHost struct{ noDoctorHost }

func (withDoctorHost) Doctor() aihost.DoctorReport {
	return aihost.DoctorReport{Host: "with-doctor", Verdict: "OK"}
}
