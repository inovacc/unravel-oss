package analysis

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/transpile/languages/cpp/prompt"
)

// SubsystemDef defines a subsystem by name and filename patterns.
type SubsystemDef struct {
	Name     string   `json:"name"`
	Patterns []string `json:"patterns"`
}

// Subsystem holds categorized files and their aggregate metrics.
type Subsystem struct {
	Name  string        `json:"name"`
	Files []*SourceFile `json:"files"`
	LOC   LOCStats      `json:"loc"`
}

// DefaultSubsystems provides general-purpose subsystem definitions
// inspired by the aria2 codebase categorization.
var DefaultSubsystems = []*SubsystemDef{
	{Name: "HTTP", Patterns: []string{"Http"}},
	{Name: "FTP", Patterns: []string{"Ftp"}},
	{Name: "BitTorrent", Patterns: []string{"Bt", "Peer", "Torrent"}},
	{Name: "DHT", Patterns: []string{"DHT"}},
	{Name: "Metalink", Patterns: []string{"Metal"}},
	{Name: "XML-RPC", Patterns: []string{"Xml", "Rpc", "JsonRpc"}},
	{Name: "Disk I/O", Patterns: []string{"Disk", "File", "MultiDisk"}},
	{Name: "Download Engine", Patterns: []string{"Download", "RequestGroup"}},
	{Name: "Request", Patterns: []string{"Request", "Uri"}},
	{Name: "Pieces", Patterns: []string{"Piece", "Segment"}},
	{Name: "Commands", Patterns: []string{"Command", "Abstract"}},
	{Name: "Socket/Network", Patterns: []string{"Socket"}},
	{Name: "Parsers", Patterns: []string{"Parser", "Decoder"}},
	{Name: "Crypto/TLS", Patterns: []string{"Message", "TLS", "Tls", "crypto", "Crypt"}},
}

// Categorizer assigns source files to subsystems based on filename patterns
// and detected libraries.
type Categorizer struct {
	Subsystems []*SubsystemDef
}

// NewCategorizer creates a categorizer with the given subsystem definitions.
func NewCategorizer(defs []*SubsystemDef) *Categorizer {
	if defs == nil {
		defs = DefaultSubsystems
	}

	return &Categorizer{Subsystems: defs}
}

// Categorize assigns each file to matching subsystems.
// A file can appear in multiple subsystems if it matches multiple patterns.
// Files matching no pattern go into an "Uncategorized" subsystem.
func (c *Categorizer) Categorize(files []*SourceFile) []*Subsystem {
	subsystemMap := make(map[string]*Subsystem, len(c.Subsystems)+1)
	for _, def := range c.Subsystems {
		subsystemMap[def.Name] = &Subsystem{Name: def.Name}
	}

	uncategorized := &Subsystem{Name: "Uncategorized"}
	categorized := make(map[string]bool)

	for _, f := range files {
		baseName := fileBaseName(f.RelPath)

		for _, def := range c.Subsystems {
			for _, pat := range def.Patterns {
				if strings.Contains(baseName, pat) {
					sub := subsystemMap[def.Name]
					sub.Files = append(sub.Files, f)
					categorized[f.RelPath] = true

					break
				}
			}
		}

		if !categorized[f.RelPath] {
			uncategorized.Files = append(uncategorized.Files, f)
		}
	}

	var result []*Subsystem

	for _, def := range c.Subsystems {
		sub := subsystemMap[def.Name]
		if len(sub.Files) > 0 {
			result = append(result, sub)
		}
	}

	if len(uncategorized.Files) > 0 {
		result = append(result, uncategorized)
	}

	return result
}

// DetectLibraries returns a deduplicated, sorted list of library names
// detected across all files by scanning their includes.
func DetectLibraries(files []*SourceFile) []string {
	seen := make(map[string]struct{})

	for _, f := range files {
		data, err := os.ReadFile(f.Path)
		if err != nil {
			continue
		}

		includes := prompt.DetectIncludes(string(data))
		for _, inc := range includes {
			lib := prompt.MapIncludeToRule(inc)
			if lib != "" {
				seen[lib] = struct{}{}
			}
		}
	}

	libs := make([]string, 0, len(seen))
	for lib := range seen {
		libs = append(libs, lib)
	}

	sortStrings(libs)

	return libs
}

// fileBaseName returns the filename without directory or extension.
func fileBaseName(path string) string {
	base := filepath.Base(path)
	ext := filepath.Ext(base)

	return strings.TrimSuffix(base, ext)
}

// sortStrings sorts a string slice in place using insertion sort.
// Avoids importing sort for a trivial operation.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
