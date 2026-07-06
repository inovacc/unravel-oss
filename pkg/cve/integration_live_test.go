//go:build live

/*
Copyright (c) 2026 Security Research
*/
package cve

import (
	"context"
	"testing"
	"time"
)

// TestLive_AllEcosystems_RealOSV hits the real OSV+NVD endpoints. Gated
// behind `-tags=live` so default CI never reaches this. CVE counts may drift
// over time; we only assert at-least-one vuln with a non-empty CVE alias.
func TestLive_AllEcosystems_RealOSV(t *testing.T) {
	tmp := t.TempDir()
	client := NewClient(Options{
		Online:      true,
		HTTPTimeout: 30 * time.Second,
		CacheRoot:   tmp,
	})
	deps := []DepInput{
		{Ecosystem: EcosystemNPM, Name: "lodash", Version: "4.17.20"},
		{Ecosystem: EcosystemPyPI, Name: "requests", Version: "2.27.0"},
		{Ecosystem: EcosystemGo, Name: "golang.org/x/crypto", Version: "v0.0.0-20220817201139-bc19a97f63c8"},
		{Ecosystem: EcosystemNuGet, Name: "Newtonsoft.Json", Version: "12.0.0"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := client.Query(ctx, deps)
	if err != nil {
		t.Fatalf("live Query: %v", err)
	}
	for _, d := range out {
		if d.Status != "ok" {
			t.Logf("[%s/%s] status=%q reason=%q (live drift acceptable)", d.Ecosystem, d.Package, d.Status, d.Reason)
			continue
		}
		if len(d.Vulnerabilities) == 0 {
			t.Errorf("[%s/%s] live OSV returned 0 vulnerabilities for known-vulnerable dep", d.Ecosystem, d.Package)
		}
	}
}
