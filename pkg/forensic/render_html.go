/*
Copyright (c) 2026 Security Research
*/
package forensic

import (
	"bytes"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"

	"github.com/inovacc/unravel-oss/pkg/knowledge"
)

//go:embed templates/report.html.tmpl
var tmplFS embed.FS

// HTMLOptions controls renderHTML behavior.
//
// NOTE: ExecSummary, TopRisk, RegressionSection are defined in 10-00's
// pkg/forensic/exec_summary_types.go. They are NOT redeclared here.
type HTMLOptions struct {
	// KBDir is the <kb> root used to discover screenshots under visual/latest
	// for inline base64 embedding (D-18). Empty disables image embedding.
	KBDir string
	// IncludeImages, when false, suppresses base64 image embedding even when
	// KBDir is set (useful for headless CI / golden tests).
	IncludeImages bool
	// ExecSummary is populated by --ai (10-02). Type defined in 10-00.
	ExecSummary *ExecSummary
	// Regression is populated by --diff-old/--diff-new (10-03). Type from 10-00.
	Regression *RegressionSection
}

// cweN returns the CWE number for findingType, or 0 if absent. Single-return
// helper for html/template; the multi-return CWEFor (int, bool) cannot be
// consumed directly in template expressions.
func cweN(findingType string) int {
	n, ok := CWEFor(findingType)
	if !ok {
		return 0
	}
	return n
}

// badgeClass maps severity to CSS class per D-04 (text-only, no emojis).
func badgeClass(severity string) string {
	switch severity {
	case "BLOCK":
		return "badge-block"
	case "FLAG":
		return "badge-flag"
	case "PASS":
		return "badge-pass"
	}
	return "badge-info"
}

// base64Image reads a PNG/JPG and returns "data:image/<mime>;base64,..." per D-18.
// Returns "" on any read error (graceful degradation; report still renders).
// Per D-27, recovers from any panic during decode.
func base64Image(path string) (s string) {
	defer func() {
		if rec := recover(); rec != nil {
			s = ""
		}
	}()
	if path == "" {
		return ""
	}
	clean := filepath.Clean(path)
	body, err := os.ReadFile(clean)
	if err != nil {
		return ""
	}
	mime := "image/png"
	switch filepath.Ext(clean) {
	case ".jpg", ".jpeg":
		mime = "image/jpeg"
	}
	return fmt.Sprintf("data:%s;base64,%s", mime, base64.StdEncoding.EncodeToString(body))
}

var reportTmpl = template.Must(template.New("report.html.tmpl").
	Funcs(template.FuncMap{
		"matrixCell":  func(l Likelihood, i Impact) string { return MatrixCell(l, i) },
		"cweLink":     CWELink,
		"cweN":        cweN,
		"base64Image": base64Image,
		"badgeClass":  badgeClass,
	}).
	ParseFS(tmplFS, "templates/report.html.tmpl"))

// scanScreenshots returns sorted absolute paths of PNG/JPG files under
// <kbDir>/visual/latest. Returns nil on any error or empty result.
func scanScreenshots(kbDir string) []string {
	if kbDir == "" {
		return nil
	}
	dir := filepath.Join(kbDir, "visual", "latest")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		switch filepath.Ext(e.Name()) {
		case ".png", ".jpg", ".jpeg":
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	return out
}

// templateData is the struct passed to report.html.tmpl execution.
type templateData struct {
	Report      *Report
	Options     HTMLOptions
	Screenshots []string
}

// renderHTML produces a polished single-file HTML report (D-02).
// Section order per D-03: ExecSummary -> RiskMatrix -> Findings -> Replay -> CWE -> Regression.
// Per D-27 a panic in template execution is converted to an error.
func renderHTML(r *Report, opts HTMLOptions) (out []byte, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("render html template panic: %v", rec)
		}
	}()
	var screenshots []string
	if opts.IncludeImages {
		screenshots = scanScreenshots(opts.KBDir)
	}
	data := templateData{
		Report:      r,
		Options:     opts,
		Screenshots: screenshots,
	}
	var buf bytes.Buffer
	if err := reportTmpl.ExecuteTemplate(&buf, "report.html.tmpl", data); err != nil {
		return nil, fmt.Errorf("execute template: %w", err)
	}
	return buf.Bytes(), nil
}

// WriteHTMLReport renders a report and atomically writes it to
// <outDir>/report.html via knowledge.WriteFileAtomic (D-22).
func WriteHTMLReport(r *Report, opts HTMLOptions, outDir string) error {
	body, err := renderHTML(r, opts)
	if err != nil {
		return err
	}
	target := filepath.Join(outDir, "report.html")
	return knowledge.WriteFileAtomic(target, body, 0o644)
}
