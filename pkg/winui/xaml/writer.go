/*
Copyright (c) 2026 Security Research
*/

package xaml

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/winui"
)

// WriteXAML serializes a recovered XAML body to <outputDir>/<sanitized>.xaml
// using an atomic write (os.CreateTemp + os.Rename). Path-traversal in
// entry.Path is rejected.
//
// For Kind=="raw", entry.Recovered may be empty; the writer falls back to
// reading the source file at filepath.Join(sourceRoot, entry.Path) and
// copying its bytes. For Kind=="pe-embedded" (and similar), entry.Recovered
// is required and sourceRoot is unused.
func WriteXAML(entry winui.XAMLEntry, sourceRoot, outputDir string) error {
	if outputDir == "" {
		return errors.New("outputDir empty")
	}
	cleanOut := filepath.Clean(outputDir)
	if strings.Contains(cleanOut, "..") {
		return fmt.Errorf("outputDir contains '..': %q", outputDir)
	}
	absOut, err := filepath.Abs(cleanOut)
	if err != nil {
		return fmt.Errorf("resolve outputDir: %w", err)
	}
	st, err := os.Stat(absOut)
	if err != nil {
		return fmt.Errorf("stat outputDir: %w", err)
	}
	if !st.IsDir() {
		return fmt.Errorf("outputDir is not a directory: %q", absOut)
	}

	name, err := sanitizeOutputName(entry.Path)
	if err != nil {
		return err
	}

	final := uniquePath(absOut, name)
	// Defense-in-depth: ensure final path is inside absOut.
	rel, rerr := filepath.Rel(absOut, final)
	if rerr != nil || strings.HasPrefix(rel, "..") || strings.Contains(rel, string(filepath.Separator)+"..") {
		return fmt.Errorf("output path escapes outputDir: %q", final)
	}

	// Resolve content.
	var data []byte
	if entry.Recovered != "" {
		data = []byte(entry.Recovered)
	} else if entry.Kind == "raw" {
		if sourceRoot == "" {
			return errors.New("raw entry: sourceRoot required when Recovered is empty")
		}
		cleanRoot := filepath.Clean(sourceRoot)
		if strings.Contains(cleanRoot, "..") {
			return fmt.Errorf("sourceRoot contains '..': %q", sourceRoot)
		}
		absRoot, aerr := filepath.Abs(cleanRoot)
		if aerr != nil {
			return fmt.Errorf("resolve sourceRoot: %w", aerr)
		}
		src := filepath.Join(absRoot, entry.Path)
		// Confirm src is inside absRoot after join.
		srel, srerr := filepath.Rel(absRoot, src)
		if srerr != nil || strings.HasPrefix(srel, "..") {
			return fmt.Errorf("source path escapes sourceRoot: %q", src)
		}
		b, rerr := os.ReadFile(src) //nolint:gosec // path verified above
		if rerr != nil {
			return fmt.Errorf("read source: %w", rerr)
		}
		data = b
	} else {
		return fmt.Errorf("entry has no recovered content (kind=%q)", entry.Kind)
	}

	tmp, err := os.CreateTemp(absOut, "._xaml_tmp_*.xaml")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := io.Copy(tmp, strings.NewReader(string(data))); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, final); err != nil {
		cleanup()
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// sanitizeOutputName converts an entry.Path into a safe basename suitable for
// joining with outputDir. Rejects any traversal segments outright.
func sanitizeOutputName(p string) (string, error) {
	if p == "" {
		return "", errors.New("entry.Path empty")
	}
	// Reject traversal segments before normalisation (catches `..` and
	// `subdir/../..`).
	parts := strings.FieldsFunc(p, func(r rune) bool {
		return r == '/' || r == '\\'
	})
	if slices.Contains(parts, "..") {
		return "", fmt.Errorf("path traversal rejected: %q", p)
	}
	// Replace any remaining separators with `_` to flatten subdir paths into
	// a single basename.
	flat := strings.ReplaceAll(p, "/", "_")
	flat = strings.ReplaceAll(flat, "\\", "_")
	flat = strings.TrimLeft(flat, "._")
	if flat == "" {
		return "", fmt.Errorf("sanitized name empty: %q", p)
	}
	if !strings.HasSuffix(strings.ToLower(flat), ".xaml") {
		flat += ".xaml"
	}
	return flat, nil
}

// uniquePath returns a non-colliding path under dir for name. If name exists,
// inserts `.1`, `.2`, ... before the `.xaml` suffix.
func uniquePath(dir, name string) string {
	candidate := filepath.Join(dir, name)
	if _, err := os.Stat(candidate); os.IsNotExist(err) {
		return candidate
	}
	base := strings.TrimSuffix(name, ".xaml")
	for i := 1; i < 10000; i++ {
		c := filepath.Join(dir, fmt.Sprintf("%s.%d.xaml", base, i))
		if _, err := os.Stat(c); os.IsNotExist(err) {
			return c
		}
	}
	// Extreme fallback — should never hit in practice.
	return filepath.Join(dir, fmt.Sprintf("%s.collide.xaml", base))
}
