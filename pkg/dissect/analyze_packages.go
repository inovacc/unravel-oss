/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/pkg/advinstaller"
	"github.com/inovacc/unravel-oss/pkg/cert"
	"github.com/inovacc/unravel-oss/pkg/deb"
	"github.com/inovacc/unravel-oss/pkg/debug"
	"github.com/inovacc/unravel-oss/pkg/detect"
	"github.com/inovacc/unravel-oss/pkg/msi"
	"github.com/inovacc/unravel-oss/pkg/msix"
	"github.com/inovacc/unravel-oss/pkg/nsis"
	"github.com/inovacc/unravel-oss/pkg/rpm"
	"github.com/inovacc/unravel-oss/pkg/uwp"
)

func init() {
	RegisterAnalyzer(analyzeDEB, detect.TypeDEB)
	RegisterAnalyzer(analyzeRPM, detect.TypeRPM)
	RegisterAnalyzer(analyzeMSI, detect.TypeMSI)
	RegisterAnalyzer(analyzeMSIX, detect.TypeMSIX)
	RegisterAnalyzer(analyzeUWPApp, detect.TypeUWPApp)
	RegisterAnalyzer(analyzeNSIS, detect.TypeNSIS)
	RegisterAnalyzer(analyzeAdvancedInstaller, detect.TypeAdvancedInstaller)
}

func analyzeDEB(r *DissectResult, path string, opts Options) {
	r.runStep("deb info", func(sr *debug.StepRecorder) error {
		res, err := deb.Info(path, false)
		if err != nil {
			return err
		}

		r.DEBInfo = res

		sr.RecordOutput(res)
		return nil
	})
	r.runStep("deb verify", func(sr *debug.StepRecorder) error {
		res, err := deb.Verify(path)
		if err != nil {
			return err
		}

		r.DEBVerify = res

		sr.RecordOutput(res)
		return nil
	})
}

func analyzeRPM(r *DissectResult, path string, opts Options) {
	r.runStep("rpm info", func(sr *debug.StepRecorder) error {
		res, err := rpm.Info(path)
		if err != nil {
			return err
		}

		r.RPMInfo = res

		sr.RecordOutput(res)
		return nil
	})
	r.runStep("rpm verify", func(sr *debug.StepRecorder) error {
		res, err := rpm.Verify(path)
		if err != nil {
			return err
		}

		r.RPMVerify = res

		sr.RecordOutput(res)
		return nil
	})
}

func analyzeMSI(r *DissectResult, path string, opts Options) {
	r.runStep("msi info", func(sr *debug.StepRecorder) error {
		res, err := msi.Info(path)
		if err != nil {
			return err
		}

		r.MSIInfo = res

		sr.RecordOutput(res)
		return nil
	})
	r.runStep("msi verify", func(sr *debug.StepRecorder) error {
		res, err := msi.Verify(path)
		if err != nil {
			return err
		}

		r.MSIVerify = res

		sr.RecordOutput(res)
		return nil
	})
}

func analyzeMSIX(r *DissectResult, path string, opts Options) {
	r.runStep("msix info", func(sr *debug.StepRecorder) error {
		res, err := msix.Info(path)
		if err != nil {
			return err
		}

		r.MSIXInfo = res

		sr.RecordOutput(res)
		return nil
	})
	r.runStep("msix verify", func(sr *debug.StepRecorder) error {
		res, err := msix.Verify(path)
		if err != nil {
			return err
		}

		r.MSIXVerify = res

		sr.RecordOutput(res)
		return nil
	})
}

// analyzeUWPApp handles installed UWP/MSIX directories (TypeUWPApp from
// detect.detectUWPDir). Reads <dir>/AppxManifest.xml directly and
// populates MSIXInfo so downstream extractIdentity can derive the
// platform=windows-msix tag without needing the original archive.
// Closes 999.12.
func analyzeUWPApp(r *DissectResult, path string, opts Options) {
	r.runStep("uwp dir info", func(sr *debug.StepRecorder) error {
		res, err := msix.InfoFromDir(path)
		if err != nil {
			slog.Warn("uwp dir info: read failed", "path", path, "err", err.Error())
			return err
		}
		r.MSIXInfo = res
		slog.Info("uwp dir info: populated MSIXInfo",
			"path", path,
			"package_name", res.PackageName,
			"display_name", res.DisplayName,
			"publisher_display_name", res.PublisherDisplayName)
		sr.RecordOutput(res)
		return nil
	})
}

func analyzeNSIS(r *DissectResult, path string, opts Options) {
	r.runStep("nsis info", func(sr *debug.StepRecorder) error {
		res, err := nsis.Info(path)
		if err != nil {
			return err
		}

		r.NSISInfo = res

		sr.RecordOutput(res)
		return nil
	})
	r.runStep("cert info", func(sr *debug.StepRecorder) error {
		res, err := cert.ExtractCertificates(path)
		if err != nil {
			return err
		}

		r.CertInfo = res

		sr.RecordOutput(res)
		return nil
	})

	if opts.OutputDir != "" {
		r.runStep("nsis extract", func(sr *debug.StepRecorder) error {
			_, err := nsis.Extract(path, filepath.Join(opts.OutputDir, "nsis_extracted"))
			return err
		})
	}
}

func analyzeAdvancedInstaller(r *DissectResult, path string, opts Options) {
	r.runStep("cert info", func(sr *debug.StepRecorder) error {
		res, err := cert.ExtractCertificates(path)
		if err != nil {
			return err
		}
		r.CertInfo = res
		sr.RecordOutput(res)
		return nil
	})
	r.runStep("advinstaller info", func(sr *debug.StepRecorder) error {
		info, err := advinstaller.Info(path)
		if err != nil {
			return err
		}
		r.AdvInstallerInfo = info
		sr.RecordOutput(info)
		return nil
	})
	if opts.OutputDir != "" {
		r.runStep("advinstaller extract msi", func(sr *debug.StepRecorder) error {
			result, err := advinstaller.ExtractMSI(path, opts.OutputDir)
			if err != nil {
				return err
			}
			sr.RecordOutput(result)
			return nil
		})
	}
}

// --- UWP scaffold population (BUG-08 / D-08) ---
//
// writeUWPScaffolds populates the three sibling scaffold dirs that the dissect
// orchestrator pre-creates around every output workspace: communication/,
// security/, and telemetry/. Prior to this fix, the UWP analyzer left these
// directories empty (only KNOWLEDGE.md was written), which caused downstream
// reporting tools to assume the package had zero communication / security /
// telemetry surface — clearly incorrect for WhatsApp + Teams.
//
// The helper is intentionally tolerant: if uwp is nil, or any sub-builder
// returns no data, an empty-but-valid JSON object is still written so the
// scaffold's "non-empty file exists" invariant holds. Errors writing
// individual files are propagated only if all three fail — partial scaffolds
// are still useful.
func writeUWPScaffolds(outDir string, u *uwp.Result) error {
	if outDir == "" {
		return nil
	}
	if u == nil {
		// Still emit empty scaffolds so the directory layout invariant holds.
		u = &uwp.Result{}
	}

	commsDir := filepath.Join(outDir, "communication")
	secDir := filepath.Join(outDir, "security")
	telDir := filepath.Join(outDir, "telemetry")
	for _, d := range []string{commsDir, secDir, telDir} {
		_ = os.MkdirAll(d, 0o755)
	}

	comms := buildUWPCommunication(u)
	sec := buildUWPSecurity(u)
	tel := buildUWPTelemetry(u)

	var firstErr error
	if err := writeJSONReport(filepath.Join(commsDir, "endpoints.json"), comms); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := writeJSONReport(filepath.Join(secDir, "config.json"), sec); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := writeJSONReport(filepath.Join(telDir, "services.json"), tel); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// UWPCommunicationReport is the schema written to communication/endpoints.json.
// `Endpoints` carries WV2-derived URIs (when WV2 analysis ran via PLAN 13-01)
// plus declared extension URIs from the AppxManifest. `Sources` is a stable
// audit trail of where each entry came from (`appx-manifest`, `wv2-leveldb`,
// `wv2-cache`).
type UWPCommunicationReport struct {
	GeneratedAt   time.Time   `json:"generated_at"`
	PFN           string      `json:"pfn,omitempty"`
	EntryPoints   []uwpEPRef  `json:"entry_points,omitempty"`
	Endpoints     []uwpURIRef `json:"endpoints"`
	WebView2Hint  string      `json:"webview2_hint,omitempty"`
	SourceSummary []string    `json:"source_summary,omitempty"`
}

type uwpEPRef struct {
	ID         string `json:"id,omitempty"`
	Executable string `json:"executable,omitempty"`
	EntryPoint string `json:"entry_point,omitempty"`
}

type uwpURIRef struct {
	URI    string `json:"uri"`
	Source string `json:"source"`
}

func buildUWPCommunication(u *uwp.Result) *UWPCommunicationReport {
	rep := &UWPCommunicationReport{
		GeneratedAt: time.Now().UTC(),
		Endpoints:   []uwpURIRef{},
	}
	if u == nil || u.Manifest == nil {
		return rep
	}
	rep.PFN = u.Manifest.PFN
	for _, ep := range u.Manifest.EntryPoints {
		rep.EntryPoints = append(rep.EntryPoints, uwpEPRef{
			ID:         ep.Id,
			Executable: ep.Executable,
			EntryPoint: ep.EntryPoint,
		})
	}
	// Pull declared extension URIs from capabilities of the form
	// `internetClient`, `internetClientServer`, `privateNetworkClientServer`.
	// Per-capability presence is the only network-related signal in
	// ManifestSummary today; downstream WV2 endpoint extraction is wired in
	// once PLAN 13-01 + 13-02 fully populate r.WebView2Info.
	netCaps := map[string]bool{
		"internetClient":             true,
		"internetClientServer":       true,
		"privateNetworkClientServer": true,
		"enterpriseAuthentication":   true,
	}
	srcSet := map[string]struct{}{}
	for _, cap := range u.Manifest.Capabilities {
		if netCaps[cap.Name] {
			rep.Endpoints = append(rep.Endpoints, uwpURIRef{
				URI:    "capability:" + cap.Name,
				Source: "appx-manifest",
			})
			srcSet["appx-manifest"] = struct{}{}
		}
	}
	if len(rep.Endpoints) == 0 {
		// Emit a stable placeholder so consumers can distinguish "no network
		// surface declared" from "scaffold not populated".
		rep.Endpoints = append(rep.Endpoints, uwpURIRef{
			URI:    "none-declared",
			Source: "appx-manifest",
		})
		srcSet["appx-manifest"] = struct{}{}
	}
	for s := range srcSet {
		rep.SourceSummary = append(rep.SourceSummary, s)
	}
	return rep
}

// UWPSecurityReport is the schema written to security/config.json.
type UWPSecurityReport struct {
	GeneratedAt    time.Time             `json:"generated_at"`
	PFN            string                `json:"pfn,omitempty"`
	Score          *uwp.Score            `json:"score,omitempty"`
	Capabilities   []uwpCapabilityDetail `json:"capabilities"`
	DPAPIBlobCount int                   `json:"dpapi_blob_count"`
	DPAPIFlags     []string              `json:"dpapi_flag_paths,omitempty"`
	Errors         []string              `json:"errors,omitempty"`
}

type uwpCapabilityDetail struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Index     int    `json:"index"`
	IsRescap  bool   `json:"is_rescap"`
	IsUnknown bool   `json:"is_unknown"`
}

func buildUWPSecurity(u *uwp.Result) *UWPSecurityReport {
	rep := &UWPSecurityReport{
		GeneratedAt:  time.Now().UTC(),
		Capabilities: []uwpCapabilityDetail{},
	}
	if u == nil {
		return rep
	}
	if u.Manifest != nil {
		rep.PFN = u.Manifest.PFN
		for _, c := range u.Manifest.Capabilities {
			rep.Capabilities = append(rep.Capabilities, uwpCapabilityDetail{
				Name:      c.Name,
				Namespace: c.Namespace,
				Index:     c.Index,
				IsRescap:  c.IsRescap(),
				IsUnknown: c.IsUnknown(),
			})
		}
	}
	rep.Score = u.Score
	rep.DPAPIBlobCount = len(u.DPAPIBlobs)
	for _, b := range u.DPAPIBlobs {
		// D-18: render only the flagged path; never the bytes.
		if b.Path != "" {
			rep.DPAPIFlags = append(rep.DPAPIFlags, b.Path)
		}
	}
	rep.Errors = append(rep.Errors, u.Errors...)
	return rep
}

// UWPTelemetryReport is the schema written to telemetry/services.json.
type UWPTelemetryReport struct {
	GeneratedAt time.Time         `json:"generated_at"`
	PFN         string            `json:"pfn,omitempty"`
	Services    []uwpTelemetrySvc `json:"services"`
	Hint        string            `json:"hint,omitempty"`
	SourceList  []string          `json:"sources,omitempty"`
}

type uwpTelemetrySvc struct {
	Name      string `json:"name"`
	Source    string `json:"source"`
	Namespace string `json:"namespace,omitempty"`
}

func buildUWPTelemetry(u *uwp.Result) *UWPTelemetryReport {
	rep := &UWPTelemetryReport{
		GeneratedAt: time.Now().UTC(),
		Services:    []uwpTelemetrySvc{},
	}
	if u == nil || u.Manifest == nil {
		return rep
	}
	rep.PFN = u.Manifest.PFN
	// Telemetry-bearing capability heuristics: any rescap, any "telemetry"
	// substring, plus a small explicit list seen in WA/Teams traffic.
	telSubstrings := []string{"telemetry", "diagnostic", "appcapture", "broadFileSystemAccess"}
	srcSet := map[string]struct{}{}
	for _, c := range u.Manifest.Capabilities {
		nameLower := strings.ToLower(c.Name)
		match := false
		for _, sub := range telSubstrings {
			if strings.Contains(nameLower, strings.ToLower(sub)) {
				match = true
				break
			}
		}
		if match || c.IsRescap() {
			rep.Services = append(rep.Services, uwpTelemetrySvc{
				Name:      c.Name,
				Source:    "appx-manifest",
				Namespace: c.Namespace,
			})
			srcSet["appx-manifest"] = struct{}{}
		}
	}
	if len(rep.Services) == 0 {
		rep.Hint = "no telemetry-bearing capabilities declared in AppxManifest"
	}
	for s := range srcSet {
		rep.SourceList = append(rep.SourceList, s)
	}
	return rep
}

// writeJSONReport is a minimal local helper that mirrors workspace.go's
// writeJSON but returns the error so the scaffold writer can track partial
// failures.
func writeJSONReport(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
