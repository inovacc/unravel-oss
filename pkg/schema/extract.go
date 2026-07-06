/*
Copyright (c) 2026 Security Research
*/
package schema

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/internal/ai"
	"github.com/inovacc/unravel-oss/pkg/dissect"
)

// Options controls schema extraction behavior.
type Options struct {
	AIAnalysis    bool // call Claude API for AI-enhanced extraction
	AIAnalysisMCP bool // return prompt for Claude Code (no API key needed)
}

// Extract generates an ApplicationSchema from a DissectResult.
func Extract(result *dissect.DissectResult, opts Options) (*ApplicationSchema, error) {
	s := &ApplicationSchema{
		AnalysisDate: time.Now(),
		SourcePath:   result.Path,
	}

	if result.Detection != nil {
		s.Framework = detectFramework(result)
	}

	s.Communication = extractCommunication(result)
	s.Auth = extractAuth(result)
	s.Storage = extractStorage(result)
	s.IPC = extractIPC(result)
	s.Stealth = extractStealth(result)
	s.Telemetry = extractTelemetry(result)
	s.Security = extractSecurity(result)
	s.AppName = extractAppName(result)
	s.Version = extractVersion(result)
	s.Confidence = calculateConfidence(s)

	if opts.AIAnalysisMCP {
		s.AIPrompt = GenerateSchemaPrompt(s, result)
	}

	if opts.AIAnalysis {
		if err := enrichWithAI(context.Background(), s, result); err != nil {
			s.AIRawAnalysis = fmt.Sprintf("AI enrichment failed: %v", err)
		}
	}

	return s, nil
}

func enrichWithAI(ctx context.Context, s *ApplicationSchema, result *dissect.DissectResult) error {
	client, err := ai.NewClient()
	if err != nil {
		return err
	}

	prompt := GenerateSchemaPrompt(s, result)
	dataJSON, err := ai.MarshalDissectForAI(result)
	if err != nil {
		return fmt.Errorf("marshal dissect data: %w", err)
	}

	resp, err := client.Analyze(ctx, prompt, ai.BuildDataSummary(dataJSON))
	if err != nil {
		return err
	}

	s.AIRawAnalysis = resp.Content
	return nil
}

func detectFramework(r *dissect.DissectResult) string {
	if r.AppAnalysis != nil && r.AppAnalysis.AppInfo.Type != "" {
		return r.AppAnalysis.AppInfo.Type
	}

	if r.FrameworkAnalysis != nil && r.FrameworkAnalysis.Framework != "" {
		return r.FrameworkAnalysis.Framework
	}

	ft := string(r.Detection.FileType)
	switch {
	case strings.Contains(ft, "apk"), strings.Contains(ft, "android"):
		return "android"
	case strings.Contains(ft, "asar"), strings.Contains(ft, "electron"):
		return "electron"
	case strings.Contains(ft, "deb"):
		return "debian"
	case strings.Contains(ft, "rpm"):
		return "rpm"
	case strings.Contains(ft, "msi"):
		return "windows-installer"
	default:
		return ft
	}
}

func extractAppName(r *dissect.DissectResult) string {
	if r.AppAnalysis != nil && r.AppAnalysis.AppInfo.Name != "" {
		return r.AppAnalysis.AppInfo.Name
	}
	if r.ManifestInfo != nil && r.ManifestInfo.Package != "" {
		return r.ManifestInfo.Package
	}
	if r.DEBInfo != nil && r.DEBInfo.Control != nil && r.DEBInfo.Control.Package != "" {
		return r.DEBInfo.Control.Package
	}
	if r.RPMInfo != nil && r.RPMInfo.Name != "" {
		return r.RPMInfo.Name
	}
	return r.FileName
}

func extractVersion(r *dissect.DissectResult) string {
	if r.AppAnalysis != nil && r.AppAnalysis.AppInfo.Version != "" {
		return r.AppAnalysis.AppInfo.Version
	}
	if r.ManifestInfo != nil && r.ManifestInfo.VersionName != "" {
		return r.ManifestInfo.VersionName
	}
	return ""
}

func extractCommunication(r *dissect.DissectResult) CommunicationSchema {
	cs := CommunicationSchema{}

	if r.NetworkAnalysis != nil {
		for _, ep := range r.NetworkAnalysis.Endpoints {
			cs.Endpoints = append(cs.Endpoints, Endpoint{
				URL:     ep.URL,
				Purpose: categorizePurpose(ep.URL),
			})
		}
		cs.CertificatePinning = r.NetworkAnalysis.CertPinning != nil
		cs.CleartextAllowed = r.NetworkAnalysis.CleartextAllowed
	}

	if r.AppAnalysis != nil {
		for _, ep := range r.AppAnalysis.Analysis.APIEndpoints {
			cs.Endpoints = append(cs.Endpoints, Endpoint{
				URL:     ep.URL,
				Purpose: ep.Purpose,
			})
		}
	}

	if r.Secrets != nil {
		for _, f := range r.Secrets.Findings {
			if strings.Contains(string(f.Type), "url") || strings.Contains(string(f.Type), "endpoint") {
				cs.Endpoints = append(cs.Endpoints, Endpoint{
					URL:     f.Value,
					Purpose: "discovered",
				})
			}
		}
	}

	protocols := map[string]bool{}
	for _, ep := range cs.Endpoints {
		switch {
		case strings.HasPrefix(ep.URL, "https://"):
			protocols["https"] = true
		case strings.HasPrefix(ep.URL, "http://"):
			protocols["http"] = true
		case strings.HasPrefix(ep.URL, "wss://") || strings.HasPrefix(ep.URL, "ws://"):
			protocols["websocket"] = true
		}
	}
	for p := range protocols {
		cs.Protocols = append(cs.Protocols, p)
	}

	if r.ProtobufAnalysis != nil && r.ProtobufAnalysis.HasProtobuf {
		cs.DataFormats = append(cs.DataFormats, "protobuf")
	}
	if r.ProtobufAnalysis != nil && r.ProtobufAnalysis.HasGRPC {
		cs.DataFormats = append(cs.DataFormats, "grpc")
	}
	if len(cs.Endpoints) > 0 {
		cs.DataFormats = append(cs.DataFormats, "json")
	}

	return cs
}

func extractAuth(r *dissect.DissectResult) AuthSchema {
	as := AuthSchema{}

	if r.Secrets != nil {
		for _, f := range r.Secrets.Findings {
			t := strings.ToLower(string(f.Type))
			switch {
			case strings.Contains(t, "api_key") || strings.Contains(t, "apikey"):
				as.Methods = appendMethodIfNew(as.Methods, AuthMethod{Type: "api_key", Implementation: "custom"})
			case strings.Contains(t, "bearer") || strings.Contains(t, "token"):
				as.Methods = appendMethodIfNew(as.Methods, AuthMethod{Type: "bearer", Implementation: "custom"})
			case strings.Contains(t, "oauth"):
				as.Methods = appendMethodIfNew(as.Methods, AuthMethod{Type: "oauth2", Implementation: "custom"})
			}
		}
	}

	return as
}

func extractStorage(r *dissect.DissectResult) StorageSchema {
	ss := StorageSchema{}

	if r.LevelDB != nil {
		ss.Databases = append(ss.Databases, Database{Type: "leveldb", Purpose: "application data"})
	}
	if r.ResourceAnalysis != nil && r.ResourceAnalysis.HasDatabases {
		ss.Databases = append(ss.Databases, Database{Type: "sqlite", Purpose: "application data"})
	}
	if r.Cache != nil {
		ss.LocalStorage = append(ss.LocalStorage, StorageEntry{Type: "http-cache", Location: "Cache_Data/"})
	}

	return ss
}

func extractIPC(r *dissect.DissectResult) IPCSchema {
	is := IPCSchema{}

	if r.AppAnalysis != nil {
		for _, cmd := range r.AppAnalysis.Analysis.IPCCommands {
			is.Channels = append(is.Channels, IPCChannel{
				Name:      cmd.Channel,
				Direction: cmd.Direction,
			})
		}
		if len(is.Channels) > 0 {
			is.Protocols = append(is.Protocols, "electron-ipc")
		}
	}

	if r.ManifestInfo != nil {
		for _, c := range r.ManifestInfo.Components {
			if c.Exported != nil && *c.Exported {
				is.Channels = append(is.Channels, IPCChannel{
					Name:      c.Name,
					Direction: "bidirectional",
				})
			}
		}
		if len(r.ManifestInfo.Components) > 0 {
			is.Protocols = appendIfNew(is.Protocols, "android-intent")
		}
	}

	return is
}

func extractStealth(r *dissect.DissectResult) StealthSchema {
	ss := StealthSchema{}

	if r.AppAnalysis != nil {
		for _, s := range r.AppAnalysis.Analysis.StealthFeatures {
			lower := strings.ToLower(s.Name)
			switch {
			case strings.Contains(lower, "content protection") || strings.Contains(lower, "screen"):
				ss.ScreenCaptureBlock = true
				ss.ScreenShareHide = true
			case strings.Contains(lower, "debug"):
				ss.AntiDebugging = append(ss.AntiDebugging, s.Name)
			}
		}
	}

	if r.NativeAnalysis != nil {
		for _, f := range r.NativeAnalysis.Findings {
			switch f.Category {
			case "anti-debug":
				ss.AntiDebugging = append(ss.AntiDebugging, f.Description)
			case "frida-detection":
				ss.AntiInstrumentation = append(ss.AntiInstrumentation, f.Description)
			}
		}
	}

	if r.ObfuscationAnalysis != nil {
		ss.CodeObfuscation = string(r.ObfuscationAnalysis.Type)
	} else if r.GarbleDetect != nil && r.GarbleDetect.IsGarbled {
		ss.CodeObfuscation = "garble"
	}

	return ss
}

func extractTelemetry(r *dissect.DissectResult) TelemetrySchema {
	ts := TelemetrySchema{}

	if r.TelemetryAnalysis != nil {
		for _, sdk := range r.TelemetryAnalysis.SDKs {
			ts.Services = append(ts.Services, TelemetryService{Name: sdk.Name})
		}
		ts.EventTracking = r.TelemetryAnalysis.HasAnalytics
	}

	if r.AppAnalysis != nil {
		for _, name := range r.AppAnalysis.AppInfo.Telemetry {
			ts.Services = append(ts.Services, TelemetryService{Name: name})
		}
	}

	return ts
}

func extractSecurity(r *dissect.DissectResult) SecuritySchema {
	ss := SecuritySchema{}

	if r.ManifestInfo != nil {
		ss.Debuggable = r.ManifestInfo.Security.Debuggable
		for _, p := range r.ManifestInfo.Permissions {
			ss.Permissions = append(ss.Permissions, p.Name)
			if p.RiskLevel == "dangerous" {
				ss.DangerousPermissions = append(ss.DangerousPermissions, p.Name)
			}
		}
	}

	if r.ManifestAnalysis != nil {
		ss.RiskScore = r.ManifestAnalysis.SecurityScore
	}

	if r.AppAnalysis != nil {
		ss.RiskScore = r.AppAnalysis.Analysis.RiskScore
		ss.ContentProtection = r.AppAnalysis.AppInfo.HasStealth
	}

	return ss
}

func calculateConfidence(s *ApplicationSchema) float64 {
	score := 0.0
	total := 7.0

	if len(s.Communication.Endpoints) > 0 {
		score++
	}
	if len(s.Auth.Methods) > 0 {
		score++
	}
	if len(s.Storage.Databases) > 0 || len(s.Storage.LocalStorage) > 0 {
		score++
	}
	if len(s.IPC.Channels) > 0 {
		score++
	}
	if s.Stealth.ScreenCaptureBlock || len(s.Stealth.AntiDebugging) > 0 || s.Stealth.CodeObfuscation != "" {
		score++
	}
	if len(s.Telemetry.Services) > 0 {
		score++
	}
	if len(s.Security.Permissions) > 0 || s.Security.RiskScore > 0 {
		score++
	}

	return score / total
}

func categorizePurpose(url string) string {
	lower := strings.ToLower(url)
	switch {
	case strings.Contains(lower, "analytics") || strings.Contains(lower, "telemetry") ||
		strings.Contains(lower, "sentry") || strings.Contains(lower, "mixpanel"):
		return "telemetry"
	case strings.Contains(lower, "auth") || strings.Contains(lower, "login") ||
		strings.Contains(lower, "oauth"):
		return "auth"
	case strings.Contains(lower, "cdn") || strings.Contains(lower, "static") ||
		strings.Contains(lower, "assets"):
		return "cdn"
	case strings.Contains(lower, "ws://") || strings.Contains(lower, "wss://"):
		return "websocket"
	default:
		return "api"
	}
}

func appendMethodIfNew(methods []AuthMethod, m AuthMethod) []AuthMethod {
	for _, existing := range methods {
		if existing.Type == m.Type {
			return methods
		}
	}
	return append(methods, m)
}

func appendIfNew(slice []string, s string) []string {
	if slices.Contains(slice, s) {
		return slice
	}
	return append(slice, s)
}
