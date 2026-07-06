package archive

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/safeio"
)

const (
	maxTotalFiles = 50000 // safety limit on total extracted files
)

// maxExtractSize is the per-file decompressed cap. An entry exceeding it is
// SKIPPED (dropped + warned), never written as a silently truncated partial. A
// var (not a const) so tests can inject a small cap.
var maxExtractSize int64 = 500 * 1024 * 1024 // 500 MB safety limit per file

// maxArchiveTotalBytes caps the aggregate uncompressed bytes written across an
// entire archive AND its nested JARs. Without it, maxTotalFiles*maxExtractSize
// permits a ~24 TB write ceiling from a tiny zip bomb. 2 GiB is far above any
// legitimate JAR/WAR/EAR while stopping the bomb. Package-level var so tests
// can inject a small cap without writing gigabytes.
var maxArchiveTotalBytes int64 = 2 << 30 // 2 GiB

// Extract opens the archive at the given path, extracts its contents to a
// temporary directory, classifies extracted files, and parses metadata files.
func (e *Extractor) Extract(ctx context.Context, archivePath string) (*ArchiveInfo, error) {
	archiveType := DetectType(archivePath)
	if archiveType == ArchiveUnknown {
		return nil, fmt.Errorf("not a recognized Java archive: %s", archivePath)
	}

	tmpDir, err := os.MkdirTemp("", "unravel-archive-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}

	info := &ArchiveInfo{
		Type:       archiveType,
		Path:       archivePath,
		ExtractDir: tmpDir,
	}

	// Shared extraction budget across this archive AND its nested JARs, so a
	// bomb cannot evade the aggregate cap by hiding in nested entries.
	budget := safeio.NewBudget()
	budget.MaxTotalBytes = maxArchiveTotalBytes

	if err := e.extractZip(ctx, archivePath, tmpDir, budget); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("extract archive: %w", err)
	}

	// Classify extracted files
	e.classifyFiles(info, tmpDir)

	// Parse metadata files
	e.parseMetadata(info, tmpDir)

	// Extract nested JARs (one level deep)
	e.extractNestedJARs(ctx, info, tmpDir, 1, budget)

	return info, nil
}

// Cleanup removes the temporary extraction directory.
func (info *ArchiveInfo) Cleanup() error {
	if info.ExtractDir == "" {
		return nil
	}

	return os.RemoveAll(info.ExtractDir)
}

// extractZip extracts all entries from a ZIP archive to the destination
// directory. The shared budget bounds the aggregate uncompressed bytes written
// across this archive and any nested archives that reuse it.
func (e *Extractor) extractZip(ctx context.Context, archivePath, destDir string, budget *safeio.Budget) error {
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

		if err := e.extractZipEntry(f, destDir, budget); err != nil {
			// SEC: an aggregate-budget breach is a hard stop for the whole
			// archive — one bomb entry must abort, not just skip-and-continue.
			if errors.Is(err, safeio.ErrBudgetExceeded) {
				return fmt.Errorf("extraction budget exceeded: %w", err)
			}
			e.logger.Warn("failed to extract entry", "name", f.Name, "error", err)
			continue
		}

		fileCount++
	}

	return nil
}

// extractZipEntry extracts a single ZIP entry to the destination directory.
func (e *Extractor) extractZipEntry(f *zip.File, destDir string, budget *safeio.Budget) error {
	// Sanitize path to prevent zip slip
	name := filepath.FromSlash(f.Name)
	destPath := filepath.Join(destDir, name)

	if !strings.HasPrefix(filepath.Clean(destPath), filepath.Clean(destDir)+string(os.PathSeparator)) {
		return fmt.Errorf("illegal file path: %s", f.Name)
	}

	if f.FileInfo().IsDir() {
		return os.MkdirAll(destPath, 0o755)
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

	// SEC: CopyLimit errors (rather than silently truncating) once an entry
	// exceeds the per-file cap. On an over-cap entry, drop the partial file and
	// SKIP the entry (warn, return nil) so analysis output is never corrupted by
	// a truncated partial — the whole archive must not abort for one bad entry.
	written, err := safeio.CopyLimit(out, rc, maxExtractSize)
	if err != nil {
		if errors.Is(err, safeio.ErrLimitExceeded) {
			_ = out.Close()
			_ = os.Remove(destPath)
			e.logger.Warn("skipping over-cap entry (would truncate)", "name", f.Name, "cap_bytes", maxExtractSize)
			return nil
		}
		return fmt.Errorf("write file: %w", err)
	}

	// SEC: account the bytes actually written against the shared aggregate
	// budget (defeats the many-entries zip-bomb) and trip on egregious
	// compression ratios. Use the real written count, not the declared size.
	if budget != nil {
		if err := budget.Add(written); err != nil {
			return fmt.Errorf("aggregate extraction limit: %w", err)
		}
		if err := budget.CheckRatio(written, int64(f.CompressedSize64)); err != nil {
			return fmt.Errorf("compression bomb: %w", err)
		}
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

// extractNestedJARs extracts nested JAR files found within the archive. The
// shared budget is reused so nested entries count against the same aggregate
// cap as the parent archive.
func (e *Extractor) extractNestedJARs(ctx context.Context, info *ArchiveInfo, baseDir string, depth int, budget *safeio.Budget) {
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

		if err := e.extractZip(ctx, jarPath, jarDir, budget); err != nil {
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
