/*
Copyright (c) 2026 Security Research
*/
package cve

import (
	"context"
	"testing"
)

// ---------------------------------------------------------------------------
// W5 — ghsa.go: cveID allow-list guard
// ---------------------------------------------------------------------------

func TestGHSAClient_Lookup_RejectsInvalidCVEID(t *testing.T) {
	tests := []struct {
		name  string
		cveID string
	}{
		{"empty_string", ""},
		{"dash_injection", "-H=Authorization: Bearer stolen"},
		{"newline_injection", "CVE-2023-1234\nContent-Type: evil"},
		{"equals_injection", "CVE-2023-1234=extra"},
		{"space", "CVE-2023 1234"},
		{"too_many_digits", "CVE-2023-12345678"},
		{"no_year", "CVE-1234"},
		{"wrong_prefix", "cve-2023-1234"},
		{"arbitrary_string", "anything"},
		{"leading_dash", "-CVE-2023-1234"},
	}
	// Use a client with an empty ghPath so it short-circuits before exec.
	// The cveID check happens before ghPath is consulted for non-empty IDs.
	c := &ghsaClient{ghPath: "/usr/bin/gh"}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, err := c.Lookup(context.Background(), tt.cveID)
			if tt.cveID == "" {
				// Empty string is a silent no-op (nil, nil).
				if err != nil || rec != nil {
					t.Errorf("empty cveID: want (nil, nil), got (%v, %v)", rec, err)
				}
				return
			}
			if err == nil {
				t.Errorf("Lookup(%q): expected error, got nil (rec=%v)", tt.cveID, rec)
			}
		})
	}
}

func TestGHSAClient_Lookup_AcceptsValidCVEID(t *testing.T) {
	valid := []string{
		"CVE-2021-1234",
		"CVE-2023-12345",
		"CVE-1999-0001",
		"CVE-2026-9999999",
	}
	// Use ghPath="" so Lookup returns (nil, nil) immediately after validation
	// passes — we just want to confirm no error from the validation step.
	c := &ghsaClient{ghPath: ""}
	for _, id := range valid {
		t.Run(id, func(t *testing.T) {
			rec, err := c.Lookup(context.Background(), id)
			if err != nil {
				t.Errorf("valid CVE ID %q unexpectedly rejected: %v", id, err)
			}
			// ghPath=="" → short-circuit nil, nil.
			if rec != nil {
				t.Errorf("expected nil record with no ghPath, got %+v", rec)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// W5 — grype.go: dep name/version allow-list guard
// ---------------------------------------------------------------------------

func TestGrypeValidateDepInput_RejectsMalicious(t *testing.T) {
	tests := []struct {
		name string
		dep  DepInput
	}{
		{
			name: "name_starts_with_dash",
			dep:  DepInput{Ecosystem: EcosystemNPM, Name: "-o /tmp/evil --add-cpe", Version: "1.0.0"},
		},
		{
			name: "version_starts_with_dash",
			dep:  DepInput{Ecosystem: EcosystemNPM, Name: "lodash", Version: "--config=/attacker"},
		},
		{
			name: "npm_name_with_semicolon",
			dep:  DepInput{Ecosystem: EcosystemNPM, Name: "lodash;rm -rf /", Version: "1.0.0"},
		},
		{
			name: "npm_name_uppercase_blocked",
			dep:  DepInput{Ecosystem: EcosystemNPM, Name: "Lodash", Version: "1.0.0"},
		},
		{
			name: "version_with_space",
			dep:  DepInput{Ecosystem: EcosystemNPM, Name: "lodash", Version: "1.0.0 --help"},
		},
		{
			name: "go_path_with_shell_meta",
			dep:  DepInput{Ecosystem: EcosystemGo, Name: "github.com/foo;whoami", Version: "v1.0.0"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateDepInput(tt.dep); err == nil {
				t.Errorf("validateDepInput(%+v): expected error, got nil", tt.dep)
			}
		})
	}
}

func TestGrypeValidateDepInput_AcceptsValid(t *testing.T) {
	tests := []DepInput{
		{Ecosystem: EcosystemNPM, Name: "lodash", Version: "4.17.21"},
		{Ecosystem: EcosystemNPM, Name: "@babel/core", Version: "7.22.0"},
		{Ecosystem: EcosystemNPM, Name: "some-pkg", Version: "1.0.0-beta.1"},
		{Ecosystem: EcosystemGo, Name: "github.com/foo/bar", Version: "v1.2.3"},
		{Ecosystem: EcosystemPyPI, Name: "requests", Version: "2.31.0"},
		{Ecosystem: EcosystemNuGet, Name: "Newtonsoft.Json", Version: "13.0.1"},
	}
	for _, dep := range tests {
		t.Run(dep.Name+"@"+dep.Version, func(t *testing.T) {
			if err := validateDepInput(dep); err != nil {
				t.Errorf("validateDepInput(%+v) unexpectedly rejected: %v", dep, err)
			}
		})
	}
}

func TestBuildGrypeTarget_NoLeadingDash(t *testing.T) {
	// Even if validation were bypassed, buildGrypeTarget must produce a string
	// that does not start with "-".
	tests := []struct {
		dep  DepInput
		want string // prefix
	}{
		{DepInput{Ecosystem: EcosystemNPM, Name: "lodash", Version: "4.17.21"}, "pkg:npm/lodash@4.17.21"},
		{DepInput{Ecosystem: EcosystemGo, Name: "github.com/foo/bar", Version: "v1.0.0"}, "pkg:golang/github.com/foo/bar@v1.0.0"},
	}
	for _, tt := range tests {
		t.Run(tt.dep.Name, func(t *testing.T) {
			got := buildGrypeTarget(tt.dep)
			if got != tt.want {
				t.Errorf("buildGrypeTarget = %q; want %q", got, tt.want)
			}
			if len(got) > 0 && got[0] == '-' {
				t.Errorf("buildGrypeTarget returned a value starting with '-': %q", got)
			}
		})
	}
}
