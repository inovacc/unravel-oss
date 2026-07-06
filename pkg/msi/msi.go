/*
Copyright (c) 2026 Security Research
*/
package msi

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/richardlehane/mscfb"
)

// InfoResult contains metadata about an MSI package.
type InfoResult struct {
	Path            string            `json:"path"`
	FileName        string            `json:"file_name"`
	Size            int64             `json:"size"`
	ProductName     string            `json:"product_name"`
	ProductVersion  string            `json:"product_version"`
	Manufacturer    string            `json:"manufacturer"`
	UpgradeCode     string            `json:"upgrade_code,omitempty"`
	ProductCode     string            `json:"product_code,omitempty"`
	ProductLanguage string            `json:"product_language,omitempty"`
	HasSignature    bool              `json:"has_signature"`
	Tables          []string          `json:"tables"`
	FileCount       int               `json:"file_count"`
	CustomActions   []CustomAction    `json:"custom_actions,omitempty"`
	Properties      map[string]string `json:"properties,omitempty"`
	Files           []FileEntry       `json:"files,omitempty"`
	RegistryEntries []RegistryEntry   `json:"registry_entries,omitempty"`
}

// CustomAction represents an MSI CustomAction table entry.
type CustomAction struct {
	Action string `json:"action"`
	Type   int    `json:"type"`
	Source string `json:"source"`
	Target string `json:"target"`
}

// FileEntry represents a file listed in the MSI File table.
type FileEntry struct {
	Name      string `json:"name"`
	Component string `json:"component"`
	FileSize  int64  `json:"file_size"`
	Version   string `json:"version,omitempty"`
	Sequence  int    `json:"sequence"`
}

// RegistryEntry represents a row from the MSI Registry table.
type RegistryEntry struct {
	Root      int    `json:"root"`
	Key       string `json:"key"`
	Name      string `json:"name"`
	Value     string `json:"value"`
	Component string `json:"component"`
}

// ExtractReport summarizes an MSI extraction.
type ExtractReport struct {
	Source      string   `json:"source"`
	Output      string   `json:"output"`
	Files       int      `json:"files"`
	Directories int      `json:"directories"`
	Streams     int      `json:"streams"`
	TotalSize   int64    `json:"total_size"`
	Errors      []string `json:"errors,omitempty"`
}

// VerifyResult contains signature verification results.
type VerifyResult struct {
	Path         string `json:"path"`
	FileName     string `json:"file_name"`
	HasSignature bool   `json:"has_signature"`
}

// Info parses an MSI package and returns metadata.
func Info(msiPath string) (*InfoResult, error) {
	absPath, err := filepath.Abs(msiPath)
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

	tr, err := newTableReader(f, stat.Size())
	if err != nil {
		return nil, fmt.Errorf("parse MSI: %w", err)
	}

	result := &InfoResult{
		Path:       absPath,
		FileName:   filepath.Base(absPath),
		Size:       stat.Size(),
		Tables:     tr.tables,
		Properties: make(map[string]string),
	}

	// Read Property table
	propRows, err := tr.readTable("Property")
	if err == nil && len(propRows) > 0 {
		result.ProductName = tr.getPropertyValue(propRows, "ProductName")
		result.ProductVersion = tr.getPropertyValue(propRows, "ProductVersion")
		result.Manufacturer = tr.getPropertyValue(propRows, "Manufacturer")
		result.UpgradeCode = tr.getPropertyValue(propRows, "UpgradeCode")
		result.ProductCode = tr.getPropertyValue(propRows, "ProductCode")
		result.ProductLanguage = tr.getPropertyValue(propRows, "ProductLanguage")

		for _, row := range propRows {
			prop := fmt.Sprint(row["Property"])
			val := fmt.Sprint(row["Value"])

			if prop != "" && prop != "0" {
				result.Properties[prop] = val
			}
		}
	}

	// Read File table
	fileRows, err := tr.readTable("File")
	if err == nil {
		result.FileCount = len(fileRows)

		for _, row := range fileRows {
			entry := FileEntry{
				Name:      stringVal(row, "FileName"),
				Component: stringVal(row, "Component_"),
				Version:   stringVal(row, "Version"),
			}

			if sz, ok := row["FileSize"]; ok {
				entry.FileSize = int64(intVal(sz))
			}

			if seq, ok := row["Sequence"]; ok {
				entry.Sequence = intVal(seq)
			}

			// MSI FileName format: "ShortName|LongName"
			if parts := strings.SplitN(entry.Name, "|", 2); len(parts) == 2 {
				entry.Name = parts[1]
			}

			result.Files = append(result.Files, entry)
		}
	}

	// Read CustomAction table
	caRows, err := tr.readTable("CustomAction")
	if err == nil {
		for _, row := range caRows {
			ca := CustomAction{
				Action: stringVal(row, "Action"),
				Source: stringVal(row, "Source"),
				Target: stringVal(row, "Target"),
			}

			if t, ok := row["Type"]; ok {
				ca.Type = intVal(t)
			}

			result.CustomActions = append(result.CustomActions, ca)
		}
	}

	// Read Registry table
	regRows, err := tr.readTable("Registry")
	if err == nil {
		for _, row := range regRows {
			entry := RegistryEntry{
				Key:       stringVal(row, "Key"),
				Name:      stringVal(row, "Name"),
				Value:     stringVal(row, "Value"),
				Component: stringVal(row, "Component_"),
			}

			if r, ok := row["Root"]; ok {
				entry.Root = intVal(r)
			}

			result.RegistryEntries = append(result.RegistryEntries, entry)
		}
	}

	// Check for digital signature stream
	result.HasSignature = tr.streams["\x05DigitalSignature"] != nil || tr.streams["_Streams"] != nil && hasDigitalSignature(tr)

	return result, nil
}

// Extract dumps all OLE streams from the MSI to a directory.
func Extract(msiPath, outputDir string) (*ExtractReport, error) {
	absPath, err := filepath.Abs(msiPath)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	f, err := os.Open(absPath)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}

	defer func() { _ = f.Close() }()

	doc, err := mscfb.New(f)
	if err != nil {
		return nil, fmt.Errorf("open CFBF: %w", err)
	}

	if outputDir == "" {
		base := filepath.Base(absPath)
		outputDir = strings.TrimSuffix(base, filepath.Ext(base)) + "_extracted"
	}

	const (
		// maxStreamBytes caps each OLE stream read at 128 MiB.
		maxStreamBytes = 128 << 20 // 128 MiB
		// maxMSITotalBytes caps cumulative extracted bytes at 4 GiB.
		maxMSITotalBytes = 4 * 1024 << 20 // 4 GiB
	)

	report := &ExtractReport{
		Source: absPath,
		Output: outputDir,
	}

	for entry, err := doc.Next(); err == nil; entry, err = doc.Next() {
		report.Streams++

		// Sanitize name for filesystem
		safeName := sanitizeStreamName(entry.Name)
		targetPath := filepath.Join(outputDir, safeName)

		// Prevent path traversal
		if !strings.HasPrefix(filepath.Clean(targetPath), filepath.Clean(outputDir)+string(os.PathSeparator)) &&
			filepath.Clean(targetPath) != filepath.Clean(outputDir) {
			report.Errors = append(report.Errors, fmt.Sprintf("skipped (path traversal): %s", entry.Name))
			continue
		}

		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("mkdir: %v", err))
			continue
		}

		// Cap per-stream reads to prevent decompression/allocation bombs.
		data, err := io.ReadAll(io.LimitReader(entry, maxStreamBytes))
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("read %s: %v", entry.Name, err))
			continue
		}

		if err := os.WriteFile(targetPath, data, 0o644); err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("write %s: %v", safeName, err))
			continue
		}

		report.Files++
		report.TotalSize += int64(len(data))

		// Cumulative cap across all streams.
		if report.TotalSize > maxMSITotalBytes {
			report.Errors = append(report.Errors, fmt.Sprintf("cumulative extracted size exceeds %d-byte cap; aborting", maxMSITotalBytes))
			break
		}
	}

	return report, nil
}

// Verify checks an MSI package for digital signatures.
func Verify(msiPath string) (*VerifyResult, error) {
	absPath, err := filepath.Abs(msiPath)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	f, err := os.Open(absPath)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}

	defer func() { _ = f.Close() }()

	doc, err := mscfb.New(f)
	if err != nil {
		return nil, fmt.Errorf("open CFBF: %w", err)
	}

	result := &VerifyResult{
		Path:     absPath,
		FileName: filepath.Base(absPath),
	}

	for entry, err := doc.Next(); err == nil; entry, err = doc.Next() {
		if entry.Name == "\x05DigitalSignature" || entry.Name == "\x05MsiDigitalSignatureEx" {
			result.HasSignature = true
			break
		}
	}

	return result, nil
}

// hasDigitalSignature checks for Authenticode signature in MSI.
func hasDigitalSignature(tr *tableReader) bool {
	return tr.streams["\x05DigitalSignature"] != nil ||
		tr.streams["\x05MsiDigitalSignatureEx"] != nil
}

// sanitizeStreamName replaces characters that are invalid in file paths.
func sanitizeStreamName(name string) string {
	replacer := strings.NewReplacer(
		"\x05", "_",
		"\x01", "_",
		"\x00", "",
		"/", "_",
		"\\", "_",
		":", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
	)

	result := replacer.Replace(name)
	if result == "" {
		result = "_unnamed"
	}

	return result
}

// stringVal safely extracts a string from a row map.
func stringVal(row map[string]any, key string) string {
	if v, ok := row[key]; ok {
		return fmt.Sprint(v)
	}

	return ""
}

// intVal converts an any to int.
func intVal(v any) int {
	switch val := v.(type) {
	case int:
		return val
	case int64:
		return int(val)
	case uint32:
		return int(val)
	default:
		return 0
	}
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
