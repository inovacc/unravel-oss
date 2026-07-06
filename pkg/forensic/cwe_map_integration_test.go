/*
Copyright (c) 2026 Security Research
*/
package forensic_test

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/cve"
	"github.com/inovacc/unravel-oss/pkg/forensic"
	"github.com/inovacc/unravel-oss/pkg/knowledge"
)

// TestCWEAutoFeed_FromEnrichedDeps verifies the D-07 contract: when
// knowledge.WriteEnrichedDeps emits cve.json files, every CWE id observed
// across the dep set is auto-fed into pkg/forensic's runtime CWE registry
// so Phase 10 reports auto-populate.
func TestCWEAutoFeed_FromEnrichedDeps(t *testing.T) {
	tmp := t.TempDir()

	// Wire pkg/forensic.RegisterCWE behind the knowledge seam — same
	// production wiring expected from cmd/init code, applied here in-test.
	knowledge.SetCWERegistrar(forensic.RegisterCWE)
	defer knowledge.SetCWERegistrar(nil)

	deps := []cve.EnrichedDep{
		{
			Ecosystem:       cve.EcosystemNPM,
			Package:         "lodash",
			VersionDeclared: "4.17.20",
			Status:          "ok",
			Vulnerabilities: []cve.Vulnerability{
				{
					ID:      "CVE-2021-23337",
					Aliases: []string{"CVE-2021-23337"},
					CWE:     []string{"CWE-77"},
				},
			},
		},
		{
			Ecosystem:       cve.EcosystemPyPI,
			Package:         "requests",
			VersionDeclared: "2.27.0",
			Status:          "ok",
			Vulnerabilities: []cve.Vulnerability{
				{
					ID:      "CVE-2023-32681",
					Aliases: []string{"CVE-2023-32681"},
					CWE:     []string{"CWE-200"},
				},
			},
		},
	}

	if err := knowledge.WriteEnrichedDeps(tmp, deps); err != nil {
		t.Fatalf("WriteEnrichedDeps: %v", err)
	}

	if cweInt, ok := forensic.CWEFor("CWE-77"); !ok {
		t.Errorf("CWE-77 not auto-fed into forensic registry")
	} else if cweInt != 77 {
		t.Errorf("CWE-77 numeric id = %d, want 77", cweInt)
	}
	if cweInt, ok := forensic.CWEFor("CWE-200"); !ok {
		t.Errorf("CWE-200 not auto-fed into forensic registry")
	} else if cweInt != 200 {
		t.Errorf("CWE-200 numeric id = %d, want 200", cweInt)
	}
}
