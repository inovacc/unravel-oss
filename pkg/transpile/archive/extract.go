package archive

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxExtractSize = 500 * 1024 * 1024 // 500 MB safety limit per file
	maxTotalFiles  = 50000             // safety limit on total extracted files
)

// Extract opens the archive at the given path, extracts its contents to a
// temporary directory, classifies extracted files, and parses metadata files.
func (e *Extractor) Extract(ctx context.Context, archivePath string) (*ArchiveInfo, error) {
	archiveType := DetectType(archivePath)
	if archiveType == ArchiveUnknown {
		return nil, fmt.Errorf("not a recognized Java archive: %s", archivePath)
	}

	tmpDir, err := os.MkdirTemp("", "togo-archive-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}

	info := &ArchiveInfo{
		Type:       archiveType,
		Path:       archivePath,
		ExtractDir: tmpDir,
	}

	if err := e.extractZip(ctx, archivePath, tmpDir); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("extract archive: %w", err)
	}

	// Classify extracted files
	e.classifyFiles(info, tmpDir)

	// Parse metadata files
	e.parseMetadata(info, tmpDir)

	// Extract nested JARs (one level deep)
	e.extractNestedJARs(ctx, info, tmpDir, 1)

	return info, nil
}

// Cleanup removes the temporary extraction directory.
func (info *ArchiveInfo) Cleanup() error {
	if info.ExtractDir == "" {
		return nil
	}

	return os.RemoveAll(info.ExtractDir)
}

// extractZip extracts all entries from a ZIP archive to the destination directory.
func (e *Extractor) extractZip(ctx context.Context, archivePath, destDir string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}

	defer func() { _ = r.Close() }()

	fileCount := 0

	for _, f := range r.File {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if fileCount >= maxTotalFiles {
			e.logger.Warn("extraction limit reached", "max_files", maxTotalFiles)
			break
		}

		if err := e.extractZipEntry(f, destDir); err != nil {
			e.logger.Warn("failed to extract entry", "name", f.Name, "error", err)
			continue
		}

		fileCount++
	}

	return nil
}

// extractZipEntry extracts a single ZIP entry to the destination directory.
func (e *Extractor) extractZipEntry(f *zip.File, destDir string) error {
	// Sanitize path to prevent zip slip
	name := filepath.FromSlash(f.Name)
	destPath := filepath.Join(destDir, name)

	if !strings.HasPrefix(filepath.Clean(destPath), filepath.Clean(destDir)+string(os.PathSeparator)) {
		return fmt.Errorf("illegal file path: %s", f.Name)
	}

	if f.FileInfo().IsDir() {
		return os.MkdirAll(destPath, 0o755)
	}

	if f.UncompressedSize64 > maxExtractSize {
		return fmt.Errorf("file too large: %s (%d bytes)", f.Name, f.UncompressedSize64)
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("open entry: %w", err)
	}

	defer func() { _ = rc.Close() }()

	out, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}

	defer func() { _ = out.Close() }()

	if _, err := io.Copy(out, io.LimitReader(rc, maxExtractSize)); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	return nil
}

// classifyFiles walks the extracted directory and categorizes files.
func (e *Extractor) classifyFiles(info *ArchiveInfo, baseDir string) {
	_ = filepath.WalkDir(baseDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}

		rel, err := filepath.Rel(baseDir, path)
		if err != nil {
			return nil
		}

		rel = filepath.ToSlash(rel)
		ext := strings.ToLower(filepath.Ext(path))

		switch ext {
		case ".java":
			info.JavaFiles = append(info.JavaFiles, rel)
		case ".class":
			info.ClassFiles = append(info.ClassFiles, rel)
		case ".jar":
			info.NestedJARs = append(info.NestedJARs, rel)
		}

		return nil
	})
}

// parseMetadata looks for known metadata files and parses them.
func (e *Extractor) parseMetadata(info *ArchiveInfo, baseDir string) {
	// MANIFEST.MF
	manifestPath := filepath.Join(baseDir, "META-INF", "MANIFEST.MF")
	if data, err := os.ReadFile(manifestPath); err == nil {
		if m, err := ParseManifest(data); err == nil {
			info.Manifest = m
		} else {
			e.logger.Warn("failed to parse MANIFEST.MF", "error", err)
		}
	}

	// web.xml (WAR)
	webXMLPath := filepath.Join(baseDir, "WEB-INF", "web.xml")
	if data, err := os.ReadFile(webXMLPath); err == nil {
		if w, err := ParseWebXML(data); err == nil {
			info.WebXML = w
		} else {
			e.logger.Warn("failed to parse web.xml", "error", err)
		}
	}

	// application.xml (EAR)
	appXMLPath := filepath.Join(baseDir, "META-INF", "application.xml")
	if data, err := os.ReadFile(appXMLPath); err == nil {
		if a, err := ParseAppXML(data); err == nil {
			info.AppXML = a
		} else {
			e.logger.Warn("failed to parse application.xml", "error", err)
		}
	}

	// pom.xml
	pomPath := filepath.Join(baseDir, "META-INF", "maven")
	if entries, err := os.ReadDir(pomPath); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}

			subEntries, err := os.ReadDir(filepath.Join(pomPath, entry.Name()))
			if err != nil {
				continue
			}

			for _, sub := range subEntries {
				if !sub.IsDir() {
					continue
				}

				pom := filepath.Join(pomPath, entry.Name(), sub.Name(), "pom.xml")
				if data, err := os.ReadFile(pom); err == nil {
					if p, err := ParsePOM(data); err == nil {
						info.POM = p
					}
				}
			}
		}
	}
	// Also check root pom.xml
	if info.POM == nil {
		if data, err := os.ReadFile(filepath.Join(baseDir, "pom.xml")); err == nil {
			if p, err := ParsePOM(data); err == nil {
				info.POM = p
			}
		}
	}

	// Spring config
	e.parseSpringConfigs(info, baseDir)
}

// parseSpringConfigs looks for Spring configuration files in common locations.
func (e *Extractor) parseSpringConfigs(info *ArchiveInfo, baseDir string) {
	paths := []string{
		filepath.Join(baseDir, "application.properties"),
		filepath.Join(baseDir, "WEB-INF", "classes", "application.properties"),
		filepath.Join(baseDir, "BOOT-INF", "classes", "application.properties"),
	}

	for _, p := range paths {
		if data, err := os.ReadFile(p); err == nil {
			if sc, err := ParseSpringProperties(data); err == nil {
				info.SpringConfig = sc
				return
			}
		}
	}

	// Try YAML
	yamlPaths := []string{
		filepath.Join(baseDir, "application.yml"),
		filepath.Join(baseDir, "application.yaml"),
		filepath.Join(baseDir, "WEB-INF", "classes", "application.yml"),
		filepath.Join(baseDir, "BOOT-INF", "classes", "application.yml"),
	}

	for _, p := range yamlPaths {
		if data, err := os.ReadFile(p); err == nil {
			if sc, err := ParseSpringYAML(data); err == nil {
				info.SpringConfig = sc
				return
			}
		}
	}
}

// extractNestedJARs extracts nested JAR files found within the archive.
func (e *Extractor) extractNestedJARs(ctx context.Context, info *ArchiveInfo, baseDir string, depth int) {
	if depth >= e.maxNestedDepth || len(info.NestedJARs) == 0 {
		return
	}

	for _, jarRel := range info.NestedJARs {
		select {
		case <-ctx.Done():
			return
		default:
		}

		jarPath := filepath.Join(baseDir, filepath.FromSlash(jarRel))
		jarDir := strings.TrimSuffix(jarPath, filepath.Ext(jarPath)) + "_extracted"

		if err := os.MkdirAll(jarDir, 0o755); err != nil {
			e.logger.Warn("failed to create nested jar dir", "jar", jarRel, "error", err)
			continue
		}

		if err := e.extractZip(ctx, jarPath, jarDir); err != nil {
			e.logger.Warn("failed to extract nested jar", "jar", jarRel, "error", err)
			continue
		}

		// Classify files from nested JAR
		_ = filepath.WalkDir(jarDir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}

			rel, err := filepath.Rel(baseDir, path)
			if err != nil {
				return nil
			}

			rel = filepath.ToSlash(rel)
			ext := strings.ToLower(filepath.Ext(path))

			switch ext {
			case ".java":
				info.JavaFiles = append(info.JavaFiles, rel)
			case ".class":
				info.ClassFiles = append(info.ClassFiles, rel)
			}

			return nil
		})
	}
}
