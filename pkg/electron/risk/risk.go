/*
Copyright (c) 2026 Security Research
*/
package risk

import (
	"github.com/inovacc/unravel-oss/pkg/manifest"
)

// Score holds the calculated risk score and level.
type Score struct {
	Value int    `json:"value"`
	Level string `json:"level"`
}

// Calculate computes a risk score from security, stealth, and IPC findings.
func Calculate(weights map[string]int, securityRisks, stealthRisks, ipcRisks []string) Score {
	score := 0

	for _, r := range securityRisks {
		if w, ok := weights[r]; ok {
			score += w
		}
	}

	for _, r := range stealthRisks {
		if w, ok := weights[r]; ok {
			score += w
		}
	}

	for _, r := range ipcRisks {
		if w, ok := weights[r]; ok {
			score += w
		}
	}

	level := "LOW"
	if score >= 100 {
		level = "CRITICAL"
	} else if score >= 50 {
		level = "HIGH"
	} else if score >= 20 {
		level = "MEDIUM"
	}

	return Score{Value: score, Level: level}
}

// CalculateFromManifest is a convenience wrapper using manifest weights.
func CalculateFromManifest(m *manifest.Manifest, securityRisks, stealthRisks, ipcRisks []string) Score {
	return Calculate(m.RiskScoring.Weights, securityRisks, stealthRisks, ipcRisks)
}
