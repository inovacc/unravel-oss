package knowledge

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/knowledge/components"
)

// WriteDirectory writes a KnowledgeResult as a structured directory tree.
func WriteDirectory(r *KnowledgeResult, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	// Write the full knowledge result as knowledge.json
	if err := writeJSON(filepath.Join(dir, "knowledge.json"), r); err != nil {
		return fmt.Errorf("write knowledge: %w", err)
	}

	// Manifest is generated up front but written at the very end so we can
	// populate Files[] from the source-emit step below.
	manifest := GenerateManifest(r)

	if c := r.Communication; c != nil {
		sub := filepath.Join(dir, "communication")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(sub, "endpoints.json"), c.Endpoints); err != nil {
			return err
		}
		if err := writeMarkdown(filepath.Join(sub, "protocols.md"), buildProtocolsMD(c)); err != nil {
			return err
		}
	}

	if a := r.Auth; a != nil {
		sub := filepath.Join(dir, "auth")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(sub, "methods.json"), a.Methods); err != nil {
			return err
		}
		if err := writeMarkdown(filepath.Join(sub, "token-storage.md"), buildAuthMD(a)); err != nil {
			return err
		}
	}

	if u := r.UI; u != nil {
		sub := filepath.Join(dir, "ui")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(sub, "framework.json"), u); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(sub, "routes.json"), u.Routes); err != nil {
			return err
		}
		if err := writeMarkdown(filepath.Join(sub, "components.md"), buildComponentsMD(u)); err != nil {
			return err
		}
	}

	if i := r.IPC; i != nil {
		sub := filepath.Join(dir, "ipc")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(sub, "channels.json"), i.Channels); err != nil {
			return err
		}
	}

	if s := r.Security; s != nil {
		sub := filepath.Join(dir, "security")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(sub, "config.json"), s.Settings); err != nil {
			return err
		}
		if err := writeMarkdown(filepath.Join(sub, "risks.md"), buildRisksMD(s)); err != nil {
			return err
		}
	}

	if st := r.Stealth; st != nil {
		sub := filepath.Join(dir, "stealth")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(sub, "features.json"), st); err != nil {
			return err
		}
	}

	if t := r.Telemetry; t != nil {
		sub := filepath.Join(dir, "telemetry")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(sub, "services.json"), t.Services); err != nil {
			return err
		}
	}

	if n := r.NPM; n != nil {
		sub := filepath.Join(dir, "npm")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(sub, "metadata.json"), n); err != nil {
			return err
		}
		if len(n.NetworkCalls) > 0 {
			if err := writeJSON(filepath.Join(sub, "api-calls.json"), n.NetworkCalls); err != nil {
				return err
			}
		}
	}

	if a := r.Android; a != nil {
		sub := filepath.Join(dir, "android")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(sub, "manifest.json"), struct {
			Package     string              `json:"package"`
			VersionCode string              `json:"version_code"`
			VersionName string              `json:"version_name"`
			MinSDK      string              `json:"min_sdk"`
			TargetSDK   string              `json:"target_sdk"`
			Permissions []AndroidPermission `json:"permissions,omitempty"`
			Components  []AndroidComponent  `json:"components,omitempty"`
			DeepLinks   []string            `json:"deep_links,omitempty"`
		}{a.Package, a.VersionCode, a.VersionName, a.MinSDK, a.TargetSDK, a.Permissions, a.Components, a.DeepLinks}); err != nil {
			return err
		}
		if len(a.Secrets) > 0 {
			if err := writeJSON(filepath.Join(sub, "secrets.json"), a.Secrets); err != nil {
				return err
			}
		}
		if len(a.NativeLibs) > 0 {
			if err := writeJSON(filepath.Join(sub, "native-libs.json"), a.NativeLibs); err != nil {
				return err
			}
		}
		if a.Obfuscation != nil {
			if err := writeJSON(filepath.Join(sub, "obfuscation.json"), a.Obfuscation); err != nil {
				return err
			}
		}
		if a.DEXStats != nil {
			if err := writeJSON(filepath.Join(sub, "dex-stats.json"), a.DEXStats); err != nil {
				return err
			}
		}
		if len(a.RiskAPIs) > 0 {
			if err := writeJSON(filepath.Join(sub, "risk-apis.json"), a.RiskAPIs); err != nil {
				return err
			}
		}
		if err := writeMarkdown(filepath.Join(sub, "overview.md"), buildAndroidOverviewMD(a)); err != nil {
			return err
		}
	}

	if g := r.GoBinary; g != nil {
		sub := filepath.Join(dir, "gobinary")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(sub, "metadata.json"), g); err != nil {
			return err
		}
		if err := writeMarkdown(filepath.Join(sub, "overview.md"), buildGoBinaryOverviewMD(g)); err != nil {
			return err
		}
	}

	if p := r.Packaging; p != nil {
		sub := filepath.Join(dir, "packaging")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(sub, "metadata.json"), p); err != nil {
			return err
		}
		if err := writeMarkdown(filepath.Join(sub, "overview.md"), buildPackagingOverviewMD(p)); err != nil {
			return err
		}
	}

	if d := r.DataDir; d != nil {
		if err := writeDataDir(d, filepath.Join(dir, "data")); err != nil {
			return fmt.Errorf("write data dir: %w", err)
		}
	}

	// Source files — component-grouped emission under <dir>/sources/<bucket>/.
	hasSource := false
	for _, sf := range r.SourceFiles {
		if sf.Content != nil {
			hasSource = true
			break
		}
	}
	if hasSource {
		classifierOpts := components.Options{}
		if ovr, _ := components.LoadOverride(filepath.Join(dir, "components.override.yaml")); ovr != nil {
			classifierOpts.Override = ovr
		}
		var inventory []EmittedFile
		for _, sf := range r.SourceFiles {
			if sf.Content == nil {
				continue
			}
			// T-07-01: validate sf.Path before any join.
			if strings.Contains(filepath.ToSlash(sf.Path), "..") {
				return errPathTraversal
			}
			cf := components.SourceFile{Path: sf.Path, Content: sf.Content}
			bucket, conf, source := components.Classify(cf, classifierOpts)
			leaf := filepath.Base(sf.Path)
			dest := filepath.Join(dir, "sources", string(bucket), leaf)
			if err := writeFileAtomic(dest, sf.Content, 0o644); err != nil {
				return fmt.Errorf("write source %s: %w", sf.Path, err)
			}
			// T-07-06: validate raw_source_path is relative + no traversal.
			rsp := sf.RawSourcePath
			if rsp != "" {
				if filepath.IsAbs(rsp) || strings.Contains(filepath.ToSlash(rsp), "..") {
					rsp = ""
				}
			}
			meta := SourceMeta{
				Component:          string(bucket),
				Classifier:         source,
				Confidence:         conf,
				RawSourcePath:      rsp,
				BeautifyProvenance: sf.BeautifyProvenance,
			}
			if err := writeJSONAtomic(dest+"._meta.json", meta); err != nil {
				return fmt.Errorf("write meta %s: %w", sf.Path, err)
			}
			inventory = append(inventory, EmittedFile{
				Path:               filepath.ToSlash(filepath.Join("sources", string(bucket), leaf)),
				Component:          string(bucket),
				SourceLanguage:     detectSourceLanguage(leaf),
				BeautifyProvenance: sf.BeautifyProvenance,
				RawSourcePath:      rsp,
			})
		}
		manifest.Files = inventory
	}

	// Manifest is written last so Files[] reflects the source-emit pass.
	if err := writeJSONAtomic(filepath.Join(dir, "manifest.json"), manifest); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}

	return nil
}

// detectSourceLanguage maps a file leaf to a stable source-language label used
// in the manifest inventory. Returns "" when the extension is not recognized.
func detectSourceLanguage(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".java":
		return "java"
	case ".js", ".mjs", ".cjs":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	case ".cs":
		return "csharp"
	case ".css":
		return "css"
	default:
		return ""
	}
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func writeMarkdown(path string, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}

func buildProtocolsMD(c *CommunicationKnowledge) string {
	var b strings.Builder
	b.WriteString("# Communication Protocols\n\n")

	if len(c.Protocols) > 0 {
		b.WriteString("## Protocols\n\n")
		for _, p := range c.Protocols {
			fmt.Fprintf(&b, "- %s\n", p)
		}
		b.WriteString("\n")
	}

	if len(c.DataFormats) > 0 {
		b.WriteString("## Data Formats\n\n")
		for _, f := range c.DataFormats {
			fmt.Fprintf(&b, "- %s\n", f)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "## Security\n\n")
	fmt.Fprintf(&b, "- Certificate Pinning: %v\n", c.CertificatePinning)
	fmt.Fprintf(&b, "- Cleartext Allowed: %v\n", c.CleartextAllowed)

	return b.String()
}

func buildAuthMD(a *AuthKnowledge) string {
	var b strings.Builder
	b.WriteString("# Authentication\n\n")
	fmt.Fprintf(&b, "## Token Storage\n\n%s\n\n", a.TokenStorage)
	fmt.Fprintf(&b, "## MFA\n\nEnabled: %v\n", a.MFA)
	return b.String()
}

func buildComponentsMD(u *UIKnowledge) string {
	var b strings.Builder
	b.WriteString("# UI Components\n\n")

	if len(u.Components) > 0 {
		b.WriteString("## Components\n\n")
		for _, c := range u.Components {
			fmt.Fprintf(&b, "- %s\n", c)
		}
		b.WriteString("\n")
	}

	if u.CSSFramework != "" {
		fmt.Fprintf(&b, "## CSS Framework\n\n%s\n\n", u.CSSFramework)
	}
	if u.BuildTool != "" {
		fmt.Fprintf(&b, "## Build Tool\n\n%s\n", u.BuildTool)
	}

	return b.String()
}

func buildRisksMD(s *SecurityKnowledge) string {
	var b strings.Builder
	b.WriteString("# Security Risk Report\n\n")
	fmt.Fprintf(&b, "**Risk Score:** %d\n\n", s.RiskScore)
	fmt.Fprintf(&b, "**Risk Level:** %s\n\n", s.RiskLevel)

	if len(s.Vulnerabilities) > 0 {
		b.WriteString("## Vulnerabilities\n\n")
		for _, v := range s.Vulnerabilities {
			fmt.Fprintf(&b, "- %s\n", v)
		}
		b.WriteString("\n")
	}

	unsafe := 0
	for _, st := range s.Settings {
		if !st.Safe {
			unsafe++
		}
	}
	if unsafe > 0 {
		b.WriteString("## Unsafe Settings\n\n")
		b.WriteString("| Setting | Value | Comment |\n")
		b.WriteString("|---------|-------|---------|\n")
		for _, st := range s.Settings {
			if !st.Safe {
				fmt.Fprintf(&b, "| %s | %s | %s |\n", st.Name, st.Value, st.Comment)
			}
		}
	}

	return b.String()
}

func writeDataDir(d *DataDirKnowledge, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	if d.LocalStorage != nil {
		if err := writeJSON(filepath.Join(dir, "local-storage.json"), d.LocalStorage); err != nil {
			return err
		}
	}

	if d.SessionStorage != nil {
		if err := writeJSON(filepath.Join(dir, "session-storage.json"), d.SessionStorage); err != nil {
			return err
		}
	}

	if d.Cache != nil {
		if err := writeJSON(filepath.Join(dir, "cache-summary.json"), d.Cache); err != nil {
			return err
		}
	}

	if d.Cookies != nil {
		if err := writeJSON(filepath.Join(dir, "cookies.json"), d.Cookies); err != nil {
			return err
		}
	}

	if d.IndexedDB != nil {
		if err := writeJSON(filepath.Join(dir, "indexeddb.json"), d.IndexedDB); err != nil {
			return err
		}
	}

	if d.DIPS != nil {
		if err := writeJSON(filepath.Join(dir, "dips.json"), d.DIPS); err != nil {
			return err
		}
	}

	if d.Preferences != nil {
		if err := writeJSON(filepath.Join(dir, "preferences.json"), d.Preferences); err != nil {
			return err
		}
	}

	if d.AppState != nil {
		if err := writeJSON(filepath.Join(dir, "app-state.json"), d.AppState); err != nil {
			return err
		}
	}

	if err := writeMarkdown(filepath.Join(dir, "overview.md"), buildDataDirOverviewMD(d)); err != nil {
		return err
	}

	return nil
}

func buildDataDirOverviewMD(d *DataDirKnowledge) string {
	var b strings.Builder
	b.WriteString("# Runtime Data Directory\n\n")
	fmt.Fprintf(&b, "**Path:** `%s`\n\n", d.Path)

	if ls := d.LocalStorage; ls != nil {
		b.WriteString("## Local Storage\n\n")
		fmt.Fprintf(&b, "- Origins: %d\n", ls.Stats.OriginCount)
		fmt.Fprintf(&b, "- Total Entries: %d\n\n", ls.Stats.TotalEntries)

		for _, o := range ls.Origins {
			fmt.Fprintf(&b, "### %s\n\n", o.Origin)
			fmt.Fprintf(&b, "| Key | Value |\n|-----|-------|\n")
			for _, e := range o.Entries {
				val := e.Value
				if len(val) > 80 {
					val = val[:80] + "..."
				}
				fmt.Fprintf(&b, "| %s | %s |\n", e.Key, val)
			}
			b.WriteString("\n")
		}
	}

	if c := d.Cache; c != nil {
		b.WriteString("## HTTP Cache\n\n")
		fmt.Fprintf(&b, "- Format: %s\n", c.Format)
		fmt.Fprintf(&b, "- Entries: %d\n", c.EntryCount)
		fmt.Fprintf(&b, "- Total Size: %d bytes\n\n", c.TotalSize)

		if len(c.Domains) > 0 {
			b.WriteString("### Domains\n\n")
			b.WriteString("| Domain | Entries |\n|--------|--------|\n")
			for domain, count := range c.Domains {
				fmt.Fprintf(&b, "| %s | %d |\n", domain, count)
			}
			b.WriteString("\n")
		}
	}

	if c := d.Cookies; c != nil {
		b.WriteString("## Cookies\n\n")
		fmt.Fprintf(&b, "- Total: %d\n", c.Stats.Total)
		fmt.Fprintf(&b, "- Secure: %d\n", c.Stats.Secure)
		fmt.Fprintf(&b, "- HttpOnly: %d\n", c.Stats.HttpOnly)
		fmt.Fprintf(&b, "- Domains: %d\n\n", c.Stats.DomainCount)
		if len(c.Domains) > 0 {
			b.WriteString("| Domain | Count |\n|--------|-------|\n")
			for domain, count := range c.Domains {
				fmt.Fprintf(&b, "| %s | %d |\n", domain, count)
			}
			b.WriteString("\n")
		}
	}

	if idb := d.IndexedDB; idb != nil {
		b.WriteString("## IndexedDB\n\n")
		fmt.Fprintf(&b, "- Databases: %d\n", idb.Stats.DatabaseCount)
		fmt.Fprintf(&b, "- Total Entries: %d\n\n", idb.Stats.TotalEntries)
		for _, db := range idb.Databases {
			name := db.Name
			if name == "" {
				name = "(default)"
			}
			fmt.Fprintf(&b, "### %s — %s\n\n", db.Origin, name)
			fmt.Fprintf(&b, "- Entries: %d\n\n", db.EntryCount)
		}
	}

	if dips := d.DIPS; dips != nil {
		b.WriteString("## DIPS (Storage Access)\n\n")
		fmt.Fprintf(&b, "- Sites: %d\n\n", dips.Total)
		if len(dips.Sites) > 0 {
			b.WriteString("| Site | First Storage | Last Storage |\n|------|--------------|-------------|\n")
			for _, s := range dips.Sites {
				fmt.Fprintf(&b, "| %s | %s | %s |\n", s.Site, s.FirstSiteStorage, s.LastSiteStorage)
			}
			b.WriteString("\n")
		}
	}

	if d.Preferences != nil {
		b.WriteString("## Preferences\n\nSee `preferences.json` for full content.\n\n")
	}

	if d.AppState != nil {
		b.WriteString("## App State Files\n\n")
		for name := range d.AppState {
			fmt.Fprintf(&b, "- `%s`\n", name)
		}
		b.WriteString("\nSee `app-state.json` for full content.\n")
	}

	return b.String()
}

func buildGoBinaryOverviewMD(g *GoBinaryKnowledge) string {
	var b strings.Builder
	b.WriteString("# Go Binary Analysis\n\n")
	if g.ModulePath != "" {
		fmt.Fprintf(&b, "**Module:** `%s`\n", g.ModulePath)
	}
	if g.GoVersion != "" {
		fmt.Fprintf(&b, "**Go Version:** %s\n", g.GoVersion)
	}
	fmt.Fprintf(&b, "**OS/Arch:** %s/%s\n", g.OS, g.Arch)
	fmt.Fprintf(&b, "**Static:** %v\n", g.IsStatic)
	fmt.Fprintf(&b, "**Symbol Table:** %v\n", g.HasSymbolTable)
	fmt.Fprintf(&b, "**DWARF:** %v\n\n", g.HasDWARF)

	if g.IsGarbled {
		fmt.Fprintf(&b, "## Obfuscation (garble)\n\n")
		fmt.Fprintf(&b, "- Confidence: %.0f%%\n", g.GarbleConfidence*100)
		if g.HighEntropyStrings > 0 {
			fmt.Fprintf(&b, "- High Entropy Strings: %d\n", g.HighEntropyStrings)
		}
		b.WriteString("\n")
	}

	if len(g.StringCategories) > 0 {
		b.WriteString("## String Categories\n\n")
		b.WriteString("| Category | Count |\n|----------|-------|\n")
		for cat, count := range g.StringCategories {
			fmt.Fprintf(&b, "| %s | %d |\n", cat, count)
		}
		b.WriteString("\n")
	}

	if len(g.BuildSettings) > 0 {
		b.WriteString("## Build Settings\n\n")
		b.WriteString("| Key | Value |\n|-----|-------|\n")
		for k, v := range g.BuildSettings {
			fmt.Fprintf(&b, "| %s | %s |\n", k, v)
		}
		b.WriteString("\n")
	}

	return b.String()
}

func buildPackagingOverviewMD(p *PackagingKnowledge) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Package: %s\n\n", p.Name)
	fmt.Fprintf(&b, "**Format:** %s\n", p.Format)
	if p.Version != "" {
		fmt.Fprintf(&b, "**Version:** %s\n", p.Version)
	}
	if p.Arch != "" {
		fmt.Fprintf(&b, "**Arch:** %s\n", p.Arch)
	}
	if p.Maintainer != "" {
		fmt.Fprintf(&b, "**Maintainer:** %s\n", p.Maintainer)
	}
	if p.Description != "" {
		fmt.Fprintf(&b, "**Description:** %s\n", p.Description)
	}
	fmt.Fprintf(&b, "**Files:** %d\n", p.FileCount)
	fmt.Fprintf(&b, "**Total Size:** %d bytes\n", p.TotalSize)
	fmt.Fprintf(&b, "**Signed:** %v\n\n", p.HasSignature)

	if len(p.Dependencies) > 0 {
		b.WriteString("## Dependencies\n\n")
		for _, d := range p.Dependencies {
			fmt.Fprintf(&b, "- %s\n", d)
		}
		b.WriteString("\n")
	}

	if len(p.Scripts) > 0 {
		b.WriteString("## Scripts\n\n")
		for _, s := range p.Scripts {
			fmt.Fprintf(&b, "- %s\n", s)
		}
		b.WriteString("\n")
	}

	if len(p.Capabilities) > 0 {
		b.WriteString("## Capabilities\n\n")
		for _, c := range p.Capabilities {
			fmt.Fprintf(&b, "- %s\n", c)
		}
		b.WriteString("\n")
	}

	return b.String()
}

func buildAndroidOverviewMD(a *AndroidKnowledge) string {
	var b strings.Builder
	b.WriteString("# Android Application\n\n")
	fmt.Fprintf(&b, "**Package:** `%s`\n", a.Package)
	fmt.Fprintf(&b, "**Version:** %s (code: %s)\n", a.VersionName, a.VersionCode)
	fmt.Fprintf(&b, "**SDK:** min=%s target=%s\n\n", a.MinSDK, a.TargetSDK)

	if len(a.Permissions) > 0 {
		dangerous := 0
		for _, p := range a.Permissions {
			if p.Dangerous {
				dangerous++
			}
		}
		fmt.Fprintf(&b, "## Permissions (%d total, %d dangerous)\n\n", len(a.Permissions), dangerous)
		b.WriteString("| Permission | Risk |\n|------------|------|\n")
		for _, p := range a.Permissions {
			fmt.Fprintf(&b, "| %s | %s |\n", p.Name, p.Risk)
		}
		b.WriteString("\n")
	}

	if len(a.Components) > 0 {
		exported := 0
		for _, c := range a.Components {
			if c.Exported {
				exported++
			}
		}
		fmt.Fprintf(&b, "## Components (%d total, %d exported)\n\n", len(a.Components), exported)
	}

	if len(a.DeepLinks) > 0 {
		b.WriteString("## Deep Links\n\n")
		for _, dl := range a.DeepLinks {
			fmt.Fprintf(&b, "- `%s`\n", dl)
		}
		b.WriteString("\n")
	}

	if len(a.Secrets) > 0 {
		fmt.Fprintf(&b, "## Secrets (%d findings)\n\n", len(a.Secrets))
	}

	if len(a.NativeLibs) > 0 {
		fmt.Fprintf(&b, "## Native Libraries (%d)\n\n", len(a.NativeLibs))
	}

	if o := a.Obfuscation; o != nil {
		fmt.Fprintf(&b, "## Obfuscation\n\n- Type: %s\n- Confidence: %d%%\n", o.Type, o.Confidence)
		if o.Packer != "" {
			fmt.Fprintf(&b, "- Packer: %s\n", o.Packer)
		}
		b.WriteString("\n")
	}

	if d := a.DEXStats; d != nil {
		b.WriteString("## DEX Analysis\n\n")
		fmt.Fprintf(&b, "- Files: %d\n- Classes: %d\n- Methods: %d\n- MultiDex: %v\n\n", d.FileCount, d.TotalClasses, d.TotalMethods, d.MultiDex)
	}

	if len(a.RiskAPIs) > 0 {
		fmt.Fprintf(&b, "## Risk APIs (%d)\n\n", len(a.RiskAPIs))
		b.WriteString("| Category | API | Severity |\n|----------|-----|----------|\n")
		for _, ra := range a.RiskAPIs {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", ra.Category, ra.API, ra.Severity)
		}
		b.WriteString("\n")
	}

	if f := a.Framework; f != nil {
		fmt.Fprintf(&b, "## Framework: %s\n\n", f.Name)
		if f.Version != "" {
			fmt.Fprintf(&b, "- Version: %s\n", f.Version)
		}
		if f.Engine != "" {
			fmt.Fprintf(&b, "- Engine: %s\n", f.Engine)
		}
		b.WriteString("\n")
	}

	return b.String()
}
