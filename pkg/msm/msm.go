/*
Copyright (c) 2026 Security Research
*/
package msm

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/msi"
)

// InfoResult contains metadata extracted from a Windows Installer Merge Module
// (.msm). A merge module is an OLE2/CFBF container holding an MSI relational
// database — the same format as an .msi — but identified by a ModuleSignature
// table instead of product properties. Merge modules are meant to be merged
// into a parent .msi at build time and frequently bundle kernel drivers
// (OpenVPN DCO, WireGuard, etc.).
type InfoResult struct {
	Path     string `json:"path"`
	FileName string `json:"file_name"`
	Size     int64  `json:"size"`

	// ModuleID is the merge-module identifier from the ModuleSignature table,
	// typically "<Name>.<GUID-with-dots>".
	ModuleID string `json:"module_id,omitempty"`
	// Language is the numeric language id from ModuleSignature.
	Language int `json:"language,omitempty"`
	// Version is the merge-module version from ModuleSignature.
	Version string `json:"version,omitempty"`

	// IsMergeModule is true when the ModuleSignature table is present — the
	// strong signal distinguishing an .msm from a plain .msi.
	IsMergeModule bool `json:"is_merge_module"`

	// Tables lists the MSI database tables declared in the module.
	Tables []string `json:"tables"`
	// Streams lists the decoded OLE stream names in the container.
	Streams []string `json:"streams,omitempty"`

	// Components lists the rows of the Component table.
	Components []Component `json:"components,omitempty"`
	// Files lists the rows of the File table, with driver classification.
	Files []FileEntry `json:"files,omitempty"`
	// DriverFiles is the subset of Files whose extension marks them as a
	// driver payload (.sys/.cat/.inf) or a likely native library (.dll).
	DriverFiles []FileEntry `json:"driver_files,omitempty"`

	// EmbeddedCabinets lists cabinet streams referenced by the Media table
	// (driver payloads are packed inside these).
	EmbeddedCabinets []string `json:"embedded_cabinets,omitempty"`

	// HasSignature reports whether an Authenticode signature stream is present.
	HasSignature bool `json:"has_signature"`

	// Warnings collects non-fatal parse issues so the caller can surface an
	// honest, partial result rather than failing outright.
	Warnings []string `json:"warnings,omitempty"`
}

// Component represents a row of the MSI Component table.
type Component struct {
	Component   string `json:"component"`
	ComponentID string `json:"component_id,omitempty"`
	Directory   string `json:"directory,omitempty"`
	KeyPath     string `json:"key_path,omitempty"`
}

// FileEntry represents a row of the MSI File table.
type FileEntry struct {
	File      string `json:"file"`
	Name      string `json:"name"`
	Component string `json:"component,omitempty"`
	FileSize  int64  `json:"file_size,omitempty"`
	Version   string `json:"version,omitempty"`
	IsDriver  bool   `json:"is_driver,omitempty"`
}

// database is the minimal surface of an MSI database the merge-module builder
// needs. It is satisfied by *msi.Database in production and by fakes in tests,
// which keeps buildInfo decoupled from CFBF byte parsing.
type database interface {
	Tables() []string
	HasTable(name string) bool
	StreamNames() []string
	HasStream(name string) bool
	ReadTable(name string) ([]map[string]any, error)
}

// Parse is an alias for Info, mirroring the naming used elsewhere in the
// codebase (some analyzers expose Parse, others Info).
func Parse(path string) (*InfoResult, error) {
	return Info(path)
}

// Info parses a merge module from disk and returns its metadata.
func Info(path string) (*InfoResult, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	f, err := os.Open(absPath)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}

	defer func() { _ = f.Close() }()

	stat, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}

	db, err := msi.OpenDatabase(f, stat.Size())
	if err != nil {
		return nil, fmt.Errorf("parse merge module: %w", err)
	}

	result := buildInfo(db)
	result.Path = absPath
	result.FileName = filepath.Base(absPath)
	result.Size = stat.Size()

	return result, nil
}

// IsMergeModule reports whether the CFBF container at path is a merge module
// (i.e. an MSI database carrying a ModuleSignature table). It returns false on
// any read error so detection callers can treat it as a cheap predicate.
func IsMergeModule(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}

	defer func() { _ = f.Close() }()

	stat, err := f.Stat()
	if err != nil {
		return false
	}

	db, err := msi.OpenDatabase(f, stat.Size())
	if err != nil {
		return false
	}

	return db.HasTable("ModuleSignature")
}

// signatureStreams are the OLE streams that carry an Authenticode signature.
var signatureStreams = []string{"\x05DigitalSignature", "\x05MsiDigitalSignatureEx"}

// buildInfo assembles an InfoResult from a parsed MSI database. It is the pure,
// table-driven core of the analyzer and never touches the filesystem, so it is
// unit-testable with synthetic table data.
func buildInfo(db database) *InfoResult {
	result := &InfoResult{
		Tables: db.Tables(),
	}

	result.Streams = db.StreamNames()
	result.IsMergeModule = db.HasTable("ModuleSignature")
	if !result.IsMergeModule {
		result.Warnings = append(result.Warnings,
			"no ModuleSignature table: file is a CFBF/MSI database but not a merge module")
	}

	readModuleSignature(db, result)
	readComponents(db, result)
	readFiles(db, result)
	readMedia(db, result)

	for _, s := range signatureStreams {
		if db.HasStream(s) {
			result.HasSignature = true
			break
		}
	}

	return result
}

// readModuleSignature pulls ModuleID/Language/Version from the ModuleSignature
// table when present.
func readModuleSignature(db database, result *InfoResult) {
	if !db.HasTable("ModuleSignature") {
		return
	}

	rows, err := db.ReadTable("ModuleSignature")
	if err != nil {
		result.Warnings = append(result.Warnings, "read ModuleSignature: "+err.Error())
		return
	}

	if len(rows) == 0 {
		return
	}

	row := rows[0]
	result.ModuleID = msi.StringFromRow(row, "ModuleID")
	result.Language = msi.IntFromRow(row, "Language")
	result.Version = msi.StringFromRow(row, "Version")
}

// readComponents pulls the Component table.
func readComponents(db database, result *InfoResult) {
	if !db.HasTable("Component") {
		return
	}

	rows, err := db.ReadTable("Component")
	if err != nil {
		result.Warnings = append(result.Warnings, "read Component: "+err.Error())
		return
	}

	for _, row := range rows {
		result.Components = append(result.Components, Component{
			Component:   msi.StringFromRow(row, "Component"),
			ComponentID: msi.StringFromRow(row, "ComponentId"),
			Directory:   msi.StringFromRow(row, "Directory_"),
			KeyPath:     msi.StringFromRow(row, "KeyPath"),
		})
	}
}

// readFiles pulls the File table and classifies driver payloads.
func readFiles(db database, result *InfoResult) {
	if !db.HasTable("File") {
		return
	}

	rows, err := db.ReadTable("File")
	if err != nil {
		result.Warnings = append(result.Warnings, "read File: "+err.Error())
		return
	}

	for _, row := range rows {
		entry := FileEntry{
			File:      msi.StringFromRow(row, "File"),
			Name:      shortLongName(msi.StringFromRow(row, "FileName")),
			Component: msi.StringFromRow(row, "Component_"),
			FileSize:  int64(msi.IntFromRow(row, "FileSize")),
			Version:   msi.StringFromRow(row, "Version"),
		}
		entry.IsDriver = isDriverFile(entry.Name)

		result.Files = append(result.Files, entry)
		if entry.IsDriver {
			result.DriverFiles = append(result.DriverFiles, entry)
		}
	}
}

// readMedia lists embedded cabinet streams referenced by the Media table. In a
// merge module the cabinet is embedded and the Cabinet value is prefixed with
// '#'; we record the decoded stream name a consumer would extract.
func readMedia(db database, result *InfoResult) {
	if !db.HasTable("Media") {
		return
	}

	rows, err := db.ReadTable("Media")
	if err != nil {
		result.Warnings = append(result.Warnings, "read Media: "+err.Error())
		return
	}

	seen := map[string]struct{}{}
	for _, row := range rows {
		cab := msi.StringFromRow(row, "Cabinet")
		if cab == "" {
			continue
		}
		// '#' marks a cabinet embedded as an OLE stream of the same name.
		cab = strings.TrimPrefix(cab, "#")
		if _, ok := seen[cab]; ok {
			continue
		}
		seen[cab] = struct{}{}
		result.EmbeddedCabinets = append(result.EmbeddedCabinets, cab)
	}
}

// shortLongName extracts the long file name from an MSI "Short|Long" pair.
func shortLongName(name string) string {
	if parts := strings.SplitN(name, "|", 2); len(parts) == 2 {
		return parts[1]
	}

	return name
}

// driverExtensions marks payloads that indicate a bundled driver.
var driverExtensions = map[string]bool{
	".sys": true, // kernel-mode driver
	".cat": true, // signed catalog
	".inf": true, // driver install manifest
	".dll": true, // user-mode driver / coinstaller / native lib
}

// isDriverFile reports whether a file name carries a driver-related extension.
func isDriverFile(name string) bool {
	return driverExtensions[strings.ToLower(filepath.Ext(name))]
}

// FormatBytes formats a byte count as a human-readable string.
func FormatBytes(size int64) string {
	const (
		kb = 1024
		mb = 1024 * kb
		gb = 1024 * mb
	)

	switch {
	case size >= gb:
		return fmt.Sprintf("%.1f GB", float64(size)/float64(gb))
	case size >= mb:
		return fmt.Sprintf("%.1f MB", float64(size)/float64(mb))
	case size >= kb:
		return fmt.Sprintf("%.1f KB", float64(size)/float64(kb))
	default:
		return fmt.Sprintf("%d bytes", size)
	}
}
