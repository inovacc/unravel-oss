/*
Copyright (c) 2026 Security Research
*/
package knowledge

import (
	"time"

	"github.com/inovacc/unravel-oss/pkg/capture"
)

// Manifest is the top-level index file for a knowledge directory.
//
// The Version field name is intentionally preserved (not renamed to
// schema_version) for back-compat with consumers that already read it.
type Manifest struct {
	Version     int              `json:"version"`
	GeneratedAt string           `json:"generated_at"`
	AppName     string           `json:"app_name"`
	AppVersion  string           `json:"app_version,omitempty"`
	FileType    string           `json:"file_type"`
	Category    string           `json:"category"`
	Sections    map[string]bool  `json:"sections"`
	Summary     *ManifestSummary `json:"summary"`
	// Files inventories every source emitted under <kb>/sources/<component>/.
	// Populated by WriteDirectory after classification, not by GenerateManifest.
	Files []EmittedFile `json:"files,omitempty"`
	// Captures is the Phase 8 additive index of visual capture states (D-16).
	// Schema Version stays at 1 — additive only. Empty on legacy KBs.
	Captures []capture.CapturedState `json:"captures,omitempty"`
}

// EmittedFile is one entry in the run-level Manifest.Files inventory.
type EmittedFile struct {
	Path               string `json:"path"`
	Component          string `json:"component"`
	SourceLanguage     string `json:"source_language"`
	BeautifyProvenance string `json:"beautify_provenance"`
	RawSourcePath      string `json:"raw_source_path,omitempty"`
}

// ManifestSummary holds aggregate counts derived from the knowledge result.
type ManifestSummary struct {
	SecurityRiskScore int      `json:"security_risk_score,omitempty"`
	Permissions       int      `json:"permissions,omitempty"`
	Dependencies      int      `json:"dependencies,omitempty"`
	Secrets           int      `json:"secrets,omitempty"`
	APIEndpoints      int      `json:"api_endpoints,omitempty"`
	Frameworks        []string `json:"frameworks,omitempty"`
	Platform          string   `json:"platform,omitempty"`
	Signed            bool     `json:"signed"`
}

// GenerateManifest creates a Manifest from a KnowledgeResult.
func GenerateManifest(kr *KnowledgeResult) *Manifest {
	m := &Manifest{
		Version:     1,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		AppName:     kr.AppName,
		AppVersion:  kr.Version,
		FileType:    kr.Framework,
		Sections:    make(map[string]bool),
		Summary:     &ManifestSummary{},
	}

	// Determine category from framework
	m.Category = categorize(kr.Framework)

	// Populate sections based on which fields are non-nil
	m.Sections["communication"] = kr.Communication != nil
	m.Sections["auth"] = kr.Auth != nil
	m.Sections["ui"] = kr.UI != nil
	m.Sections["ipc"] = kr.IPC != nil
	m.Sections["security"] = kr.Security != nil
	m.Sections["stealth"] = kr.Stealth != nil
	m.Sections["telemetry"] = kr.Telemetry != nil
	m.Sections["npm"] = kr.NPM != nil
	m.Sections["android"] = kr.Android != nil
	m.Sections["binary"] = kr.Binary != nil
	m.Sections["go_binary"] = kr.GoBinary != nil
	m.Sections["packaging"] = kr.Packaging != nil
	m.Sections["package"] = kr.Package != nil
	m.Sections["ios"] = kr.IOS != nil
	m.Sections["source_files"] = len(kr.SourceFiles) > 0
	m.Sections["data_dir"] = kr.DataDir != nil

	// Derive summary counts
	if kr.Security != nil {
		m.Summary.SecurityRiskScore = kr.Security.RiskScore
	}

	if kr.Communication != nil {
		m.Summary.APIEndpoints = len(kr.Communication.Endpoints)
	}

	if kr.Android != nil {
		m.Summary.Permissions = len(kr.Android.Permissions)
		m.Summary.Secrets = len(kr.Android.Secrets)
		if kr.Android.Framework != nil {
			m.Summary.Frameworks = append(m.Summary.Frameworks, kr.Android.Framework.Name)
		}
	}

	if kr.IOS != nil {
		m.Summary.Permissions = len(kr.IOS.Permissions)
		if len(kr.IOS.Frameworks) > 0 {
			m.Summary.Frameworks = append(m.Summary.Frameworks, kr.IOS.Frameworks...)
		}
	}

	if kr.Packaging != nil {
		m.Summary.Dependencies = len(kr.Packaging.Dependencies)
		m.Summary.Signed = kr.Packaging.HasSignature
	}
	if kr.NPM != nil {
		m.Summary.Dependencies = len(kr.NPM.Dependencies) + len(kr.NPM.DevDependencies)
		m.Summary.SecurityRiskScore = kr.NPM.RiskScore
	}
	if kr.Package != nil {
		if m.Summary.Dependencies == 0 {
			m.Summary.Dependencies = len(kr.Package.Dependencies)
		}
		if !m.Summary.Signed {
			m.Summary.Signed = kr.Package.Signed
		}
	}

	if kr.Binary != nil && kr.Binary.Signing != nil {
		if !m.Summary.Signed {
			m.Summary.Signed = kr.Binary.Signing.HasSignature
		}
	}

	// Determine platform
	m.Summary.Platform = derivePlatform(kr)

	// UI framework
	if kr.UI != nil && kr.UI.Framework != "" {
		m.Summary.Frameworks = append(m.Summary.Frameworks, kr.UI.Framework)
	}

	return m
}

func categorize(framework string) string {
	switch framework {
	case "electron", "tauri":
		return "desktop"
	case "npm", "node", "nodejs":
		return "package"
	case "android":
		return "mobile"
	case "ios":
		return "mobile"
	case "go", "dotnet", "pe", "elf", "macho":
		return "binary"
	default:
		return "unknown"
	}
}

func derivePlatform(kr *KnowledgeResult) string {
	if kr.Framework != "" {
		return kr.Framework
	}
	if kr.Android != nil {
		return "android"
	}
	if kr.IOS != nil {
		return "ios"
	}
	if kr.GoBinary != nil {
		return "go"
	}
	if kr.Binary != nil {
		if kr.Binary.DotnetInfo != nil {
			return "dotnet"
		}
		return kr.Binary.Format
	}
	return ""
}
