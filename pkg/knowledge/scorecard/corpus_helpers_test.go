//go:build corpus_validation

/*
Copyright (c) 2026 Security Research
*/

package scorecard

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// corpusPackageIDs is the canonical 10-app Electron-class corpus from
// v2.9 P52 W-loop scorecards (Wave-0 capture, P60 60-00). Used by VALD-03
// majority gate.
var corpusPackageIDs = []string{
	"5319275A.WhatsAppDesktop",
	"MSTeams_8wekyb3d8bbwe",
	"Angel",
	"Cluely",
	"Cursor",
	"Discord",
	"Notion",
	"Obsidian",
	"Perssua",
	"VSCode",
}

// loadSidecarScorecard loads a *_score.json sidecar (richer shape than
// pure scorecard.Scorecard — we extract just the dimensions/coverage we
// need into a Scorecard for tests). MD-first not implemented; numeric
// fidelity wins per RUBR-04.
func loadSidecarScorecard(dir, packageID string) (*Scorecard, string, error) {
	// Try the runbook's exact filename pattern: <pkg>_score.json
	candidates := []string{
		filepath.Join(dir, packageID+"_score.json"),
		filepath.Join(dir, packageID+"-_score.json"),
	}
	var path string
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			path = c
			break
		}
	}
	if path == "" {
		return nil, "", os.ErrNotExist
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, path, err
	}
	// Sidecar has extra fields (package, started_at, iterations, coverage
	// object). Decode into an intermediate, then project into Scorecard.
	var src struct {
		KbID       string     `json:"kb_id"`
		Package    string     `json:"package"`
		Dimensions []DimScore `json:"dimensions"`
		Coverage   struct {
			DimsAt80 int `json:"dimensions_at_80"`
		} `json:"coverage"`
		CitationsOK bool `json:"citations_ok"`
	}
	if err := json.Unmarshal(raw, &src); err != nil {
		return nil, path, err
	}
	sc := &Scorecard{
		KbID:        src.KbID,
		Dimensions:  src.Dimensions,
		Coverage:    src.Coverage.DimsAt80,
		CitationsOK: src.CitationsOK,
	}
	return sc, path, nil
}

// listSidecarPackageIDs walks dir and returns the set of package_ids that
// have a *_score.json present. Used by VALD-03 (>=7/10 gate).
func listSidecarPackageIDs(dir string) (map[string]bool, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*_score.json"))
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, m := range matches {
		base := filepath.Base(m)
		// Strip "_score.json" suffix.
		const suf = "_score.json"
		if len(base) > len(suf) {
			out[base[:len(base)-len(suf)]] = true
		}
	}
	return out, nil
}
