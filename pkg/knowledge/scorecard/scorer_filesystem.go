/*
Copyright (c) 2026 Security Research
*/

// Curve (port of .scripts/whatsapp-W-02-enumerate.ps1:93, W-10:382):
//
//	constant 90 once any package file enumeration is present
//	floor 95 once spec-written marker present (here: enumeration plus a
//	  cert / signature feature, mirroring the W-10 spec-written gate)
//
// Sources counted: MSIXInfo.Files, MSIInfo.Files, DEBInfo, RPMInfo,
// APKExtract, ASARFiles, ExtExtract.
package scorecard

import (
	"github.com/inovacc/unravel-oss/pkg/analysis"
	"github.com/inovacc/unravel-oss/pkg/dissect"
)

func init() { Register(filesystemScorer{}) }

type filesystemScorer struct{}

func (filesystemScorer) ID() string   { return "filesystem" }
func (filesystemScorer) Name() string { return "Filesystem map" }

func (filesystemScorer) Score(r *dissect.DissectResult, _ *analysis.ResultSet) DimScore {
	out := DimScore{ID: "filesystem", Name: "Filesystem map"}
	if r == nil {
		return out
	}
	// P58C-01 (P64-06): per-typed-field Citation. Manifest-level evidence
	// binds to MSIXInfo.ManifestPath when present; per-file evidence (added
	// inline below for MSIXInfo.Files entries) uses the entry name. Falls
	// back to SourcePath for non-UWP stacks.
	var cite *Citation
	if r.MSIXInfo != nil && r.MSIXInfo.ManifestPath != "" {
		cite = &Citation{File: r.MSIXInfo.ManifestPath}
	} else {
		cite = newCitation("", r.SourcePath, 0)
	}
	enumerated := false
	if r.MSIXInfo != nil && (len(r.MSIXInfo.Files) > 0 || r.MSIXInfo.FileCount > 0) {
		enumerated = true
		out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "MSIXInfo.Files", Citation: cite})
	}
	if r.MSIInfo != nil {
		enumerated = true
		out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "MSIInfo", Citation: cite})
	}
	if r.DEBInfo != nil {
		enumerated = true
		out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "DEBInfo", Citation: cite})
	}
	if r.RPMInfo != nil {
		enumerated = true
		out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "RPMInfo", Citation: cite})
	}
	if r.APKExtract != nil {
		enumerated = true
		out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "APKExtract", Citation: cite})
	}
	if len(r.ASARFiles) > 0 {
		enumerated = true
		out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "ASARFiles", Citation: cite})
	}
	if r.ExtExtract != nil {
		enumerated = true
		out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "ExtExtract", Citation: cite})
	}
	if !enumerated {
		return out
	}
	out.Score = 90
	specWritten := r.CertInfo != nil ||
		(r.MSIXInfo != nil && r.MSIXInfo.HasSignature) ||
		(r.MSIXInfo != nil && r.MSIXInfo.HasBlockMap)
	if specWritten {
		out.Score = 95
		out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "spec_written:cert|signature", Citation: cite})
	}
	return out
}
