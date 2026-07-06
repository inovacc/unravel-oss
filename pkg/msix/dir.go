/*
Copyright (c) 2026 Security Research

dir.go — directory-mode AppxManifest reader for installed UWP apps.

Closes 999.12. Installed UWP packages live as plain directories under
C:\Program Files\WindowsApps\<PackageFullName>\ with an AppxManifest.xml
at the root. Info(path) only handles .msix archives (zip + manifest); this
helper handles the unpacked layout so capture pipelines can populate
MSIXInfo for installed apps without needing the original .msix file.
*/

package msix

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// InfoFromDir reads <dir>/AppxManifest.xml and populates an InfoResult
// with the same identity-relevant fields as Info() does for archives.
// Returns os.ErrNotExist if AppxManifest.xml is missing.
//
// Dir-mode skips: .msix-specific signature/block-map/content-types
// inspection (those live in the archive only — the unpacked dir doesn't
// retain them), and per-file enumeration (FileCount / Files / TotalSize
// stay zero — analyst can walk the dir separately if needed).
func InfoFromDir(dir string) (*InfoResult, error) {
	manifestPath := filepath.Join(dir, "AppxManifest.xml")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read AppxManifest.xml: %w", err)
	}

	parsed, err := ParseAppxManifest(data)
	if err != nil {
		return nil, err
	}

	info, statErr := os.Stat(dir)
	var size int64
	if statErr == nil {
		size = info.Size()
	}

	result := &InfoResult{
		Path:     dir,
		FileName: filepath.Base(dir),
		Size:     size,
		// ManifestPath is the absolute on-disk path to AppxManifest.xml so
		// SCRG-05 can use it directly as Citation.File for capability +
		// URL-pattern Evidence. Added in P64 64-00b.
		ManifestPath:          manifestPath,
		PackageName:           parsed.Identity.Name,
		PackageVersion:        parsed.Identity.Version,
		Publisher:             parsed.Identity.Publisher,
		ProcessorArchitecture: parsed.Identity.ProcessorArchitecture,
		DisplayName:           parsed.Properties.DisplayName,
		Description:           parsed.Properties.Description,
		PublisherDisplayName:  parsed.Properties.PublisherDisplayName,
	}

	for _, dep := range parsed.Dependencies.TargetDeviceFamily {
		d := Dependency{
			Name:             dep.Name,
			MinVersion:       dep.MinVersion,
			MaxVersionTested: dep.MaxVersionTested,
		}
		result.Dependencies = append(result.Dependencies, d)
		if result.MinOSVersion == "" || dep.MinVersion < result.MinOSVersion {
			result.MinOSVersion = dep.MinVersion
		}
	}

	for _, app := range parsed.Applications.Application {
		result.Applications = append(result.Applications, Application{
			ID:         app.ID,
			Executable: app.Executable,
			EntryPoint: app.EntryPoint,
		})
		flattenApplicationExtensions(app.ID, app.Extensions.Extension, result)
		ve := app.VisualElements
		if ve.DisplayName != "" || ve.Description != "" || ve.BackgroundColor != "" ||
			ve.Square150x150Logo != "" || ve.Square44x44Logo != "" {
			result.VisualElements = append(result.VisualElements, VisualElements{
				AppName:           app.ID,
				DisplayName:       ve.DisplayName,
				Description:       ve.Description,
				BackgroundColor:   ve.BackgroundColor,
				Square150x150Logo: ve.Square150x150Logo,
				Square44x44Logo:   ve.Square44x44Logo,
			})
		}
	}

	// Walk the dir for file count + total size (best-effort; permission
	// errors on individual files are skipped so the analyzer succeeds
	// even on partially-readable WindowsApps dirs). Files of forensic
	// interest are also captured (capped at maxFilesCaptured) so the
	// knowledge layer can populate kr.SourceFiles without re-walking.
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		result.FileCount++
		result.TotalSize += fi.Size()
		if len(result.Files) < maxFilesCaptured && isInterestingForensicFile(path) {
			rel, rerr := filepath.Rel(dir, path)
			if rerr != nil {
				rel = filepath.Base(path)
			}
			result.Files = append(result.Files, FileEntry{
				Name: rel,
				Size: fi.Size(),
			})
		}
		return nil
	})

	return result, nil
}

const maxFilesCaptured = 250

// isInterestingForensicFile returns true for files the knowledge layer wants
// to inventory: code, web assets, manifests, configs. Excludes localized
// satellite assemblies, image scaling variants, and resource binaries that
// add noise without forensic value.
func isInterestingForensicFile(path string) bool {
	base := filepath.Base(path)
	lower := strings.ToLower(base)
	// Skip locale satellites and DPI-scaled resource variants.
	if strings.Contains(path, "\\Microsoft.NET\\") || strings.Contains(path, "/Microsoft.NET/") {
		return false
	}
	if strings.Contains(lower, ".scale-") || strings.Contains(lower, ".targetsize-") {
		return false
	}
	switch filepath.Ext(lower) {
	case ".exe", ".dll", ".so", ".node":
		return true
	case ".html", ".htm", ".js", ".mjs", ".css", ".wasm":
		return true
	case ".json", ".xml", ".yaml", ".yml", ".toml", ".ini", ".manifest":
		return true
	case ".xaml", ".xbf":
		return true
	case ".pri", ".dat", ".bin":
		return true
	}
	return false
}

// IsInstalledUWPDir reports whether path is a directory that contains an
// AppxManifest.xml at its root. Cheap probe used by detectors that need
// to disambiguate UWP installs from plain Electron / Tauri layouts.
func IsInstalledUWPDir(path string) bool {
	info, err := os.Stat(filepath.Join(path, "AppxManifest.xml"))
	if err != nil {
		return false
	}
	return !info.IsDir() && info.Size() > 0
}

// ErrNoManifest is returned when InfoFromDir cannot locate AppxManifest.xml.
var ErrNoManifest = errors.New("msix: no AppxManifest.xml in directory")
