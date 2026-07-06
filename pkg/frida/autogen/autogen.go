/*
Copyright (c) 2026 Security Research
*/
package autogen

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/inovacc/unravel-oss/pkg/inject"
)

// ErrUnknownPlatform is returned when a seam cannot be mapped to a template.
var ErrUnknownPlatform = errors.New("autogen: unknown target platform")

// Generate emits one Frida JS file + criteria.json sidecar per seam in the
// ScanResult. Output filenames are deterministic per D-12/D-13 so reruns
// are idempotent.
//
// On any error after files have been written this run, generated outputs are
// removed (best-effort cleanup) so the output directory does not contain
// half-baked artifacts.
func Generate(report inject.ScanResult, outDir string, opts Options) (GenerateResult, error) {
	result := GenerateResult{OutDir: outDir, Scripts: []GeneratedScript{}}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return result, fmt.Errorf("mkdir out: %w", err)
	}

	written := make([]string, 0, 16)
	cleanup := func() {
		for _, p := range written {
			_ = os.Remove(p)
		}
	}

	seams := flattenSeams(report)
	for _, s := range seams {
		plat, err := derivePlatform(s)
		if err != nil {
			cleanup()
			return result, fmt.Errorf("seam %q: %w", s.Kind, err)
		}
		if opts.Platform != "" && opts.Platform != plat {
			result.Skipped++
			continue
		}
		path, tag := extractTargetPathTag(s)
		id := seamID(plat, path, tag)
		js, criteria, err := renderSeam(s, plat, id)
		if err != nil {
			cleanup()
			return result, fmt.Errorf("render %s: %w", id, err)
		}
		if err := lintJS(id, js); err != nil {
			cleanup()
			return result, err
		}
		jsName := fmt.Sprintf("%s-%s-%s.js", platShort(plat), sanitizeTag(tag), id)
		critName := fmt.Sprintf("%s-%s-%s.criteria.json", platShort(plat), sanitizeTag(tag), id)
		jsPath := filepath.Join(outDir, jsName)
		critPath := filepath.Join(outDir, critName)
		if err := os.WriteFile(jsPath, js, 0o644); err != nil {
			cleanup()
			return result, fmt.Errorf("write js: %w", err)
		}
		written = append(written, jsPath)
		if err := os.WriteFile(critPath, criteria, 0o644); err != nil {
			cleanup()
			return result, fmt.Errorf("write criteria: %w", err)
		}
		written = append(written, critPath)
		result.Scripts = append(result.Scripts, GeneratedScript{
			SeamID: id, Platform: plat, ScriptPath: jsPath, CriteriaPath: critPath,
		})
	}
	return result, nil
}

// flattenSeams returns the union of report.Seams and report.Arches[*].Seams.
// macOS scanners populate Arches; other scanners populate the top-level
// Seams field. Combined reports may use both.
func flattenSeams(r inject.ScanResult) []inject.Seam {
	out := make([]inject.Seam, 0, len(r.Seams))
	out = append(out, r.Seams...)
	for _, a := range r.Arches {
		out = append(out, a.Seams...)
	}
	return out
}

// platShort returns the 3-letter prefix used in filenames per D-12.
func platShort(p string) string {
	switch p {
	case "windows":
		return "win"
	case "macos":
		return "mac"
	case "linux":
		return "lin"
	}
	return p
}

// sanitizeTag strips characters illegal in filenames; keeps alnum + dash + underscore.
func sanitizeTag(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "seam"
	}
	return string(out)
}

// renderSeam dispatches to platform template + criteria builder. The actual
// template execution lives in templates.go and criteria.go.
func renderSeam(s inject.Seam, platform, id string) (js, criteria []byte, err error) {
	js, err = renderJS(s, platform, id)
	if err != nil {
		return nil, nil, err
	}
	criteria, err = renderCriteria(s, platform, id)
	if err != nil {
		return nil, nil, err
	}
	return js, criteria, nil
}
