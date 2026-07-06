/*
Copyright (c) 2026 Security Research
*/
package forensic

import (
	"fmt"
	"sync"
)

// cweEntry pairs a CWE numeric id with an optional human description.
type cweEntry struct {
	cwe         int
	description string
}

// cweMu guards cweMap. The map seeded at init() time may be extended at
// runtime via RegisterCWE (Phase 14 D-07: dependency-derived CWEs feed in
// here so Phase 10 reports' "CWE Mappings" auto-populate).
var (
	cweMu  sync.RWMutex
	cweMap = map[string]cweEntry{
		// Electron-stealth originals (CONTEXT seed)
		"csp_relaxation":        {cwe: 693, description: "Protection Mechanism Failure"},
		"eval_or_unsafe_inline": {cwe: 95, description: "Improper Neutralization in Dynamically Evaluated Code"},
		"hardcoded_credential":  {cwe: 798, description: "Use of Hard-coded Credentials"},
		"dangerous_permission":  {cwe: 250, description: "Execution with Unnecessary Privileges"},
		"content_protection":    {cwe: 732, description: "Incorrect Permission Assignment for Critical Resource"},
		"sandbox_removed":       {cwe: 693, description: "Protection Mechanism Failure"},

		// Generic Android / cross-framework forensic categories.
		"permissions":    {cwe: 250, description: "Execution with Unnecessary Privileges"},
		"attack_surface": {cwe: 749, description: "Exposed Dangerous Method or Function"},
		"network":        {cwe: 319, description: "Cleartext Transmission of Sensitive Information"},
		"secrets":        {cwe: 798, description: "Use of Hard-coded Credentials"},
		"crypto":         {cwe: 327, description: "Use of a Broken or Risky Cryptographic Algorithm"},
		"tls":            {cwe: 295, description: "Improper Certificate Validation"},
		"webview":        {cwe: 749, description: "Exposed Dangerous Method or Function"},
		"intent":         {cwe: 927, description: "Use of Implicit Intent for Sensitive Communication"},
		"ipc":            {cwe: 927, description: "Use of Implicit Intent for Sensitive Communication"},
		"storage":        {cwe: 922, description: "Insecure Storage of Sensitive Information"},
		"logging":        {cwe: 532, description: "Insertion of Sensitive Information into Log File"},
		"signing":        {cwe: 347, description: "Improper Verification of Cryptographic Signature"},
		"signature":      {cwe: 347, description: "Improper Verification of Cryptographic Signature"},
		"obfuscation":    {cwe: 693, description: "Protection Mechanism Failure"},
		"debug":          {cwe: 489, description: "Active Debug Code"},
		"debuggable":     {cwe: 489, description: "Active Debug Code"},
		"backup":         {cwe: 200, description: "Exposure of Sensitive Information"},
		"telemetry":      {cwe: 359, description: "Exposure of Private Personal Information"},
		"stealth":        {cwe: 732, description: "Incorrect Permission Assignment for Critical Resource"},
		"screen_capture": {cwe: 732, description: "Incorrect Permission Assignment for Critical Resource"},
	}
)

// CWEFor returns (cwe, true) if findingType has a mapping; (0, false) otherwise.
func CWEFor(findingType string) (int, bool) {
	cweMu.RLock()
	defer cweMu.RUnlock()
	e, ok := cweMap[findingType]
	if !ok {
		return 0, false
	}
	return e.cwe, true
}

// CWEDescription returns the textual description for a finding type, if any.
func CWEDescription(findingType string) (string, bool) {
	cweMu.RLock()
	defer cweMu.RUnlock()
	e, ok := cweMap[findingType]
	if !ok {
		return "", false
	}
	return e.description, true
}

// RegisterCWE upserts a runtime CWE mapping (Phase 14 D-07).
//
// Behavior:
//   - If id is empty, the call is a no-op.
//   - If the entry does not exist, it is inserted with the given description
//     (CWE id is parsed from the leading "CWE-NNNN" prefix; otherwise 0).
//   - If the entry exists with an empty description, the description is
//     filled in. A non-empty seed description is NOT overwritten.
//   - Idempotent: repeated calls with identical inputs are no-ops.
func RegisterCWE(id, description string) {
	if id == "" {
		return
	}
	cweMu.Lock()
	defer cweMu.Unlock()
	cweInt := parseCWEPrefix(id)
	existing, ok := cweMap[id]
	if !ok {
		cweMap[id] = cweEntry{cwe: cweInt, description: description}
		return
	}
	// Idempotent: fill empty description only.
	if existing.description == "" && description != "" {
		existing.description = description
		cweMap[id] = existing
	}
}

// parseCWEPrefix extracts an integer N from "CWE-N" / "CWE-N..." or returns 0.
func parseCWEPrefix(id string) int {
	const prefix = "CWE-"
	if len(id) <= len(prefix) || id[:len(prefix)] != prefix {
		return 0
	}
	n := 0
	for i := len(prefix); i < len(id); i++ {
		ch := id[i]
		if ch < '0' || ch > '9' {
			break
		}
		n = n*10 + int(ch-'0')
	}
	return n
}

// CWELink returns the canonical MITRE link per D-09.
func CWELink(cwe int) string {
	return fmt.Sprintf("https://cwe.mitre.org/data/definitions/%d.html", cwe)
}
