/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/jsdeob/bundle"
)

// PrintBundleReport prints a structured summary of a bundle
// reconstruction run including bundle_kind, module counts, and
// manifest/index paths. 06-04 Task 1.
func PrintBundleReport(report *bundle.RunReport, w io.Writer) {
	if report == nil {
		_, _ = fmt.Fprintln(w, "bundle reconstruct: nil report")
		return
	}
	width := 66
	border := strings.Repeat("=", width)

	fmt.Fprintf(w, "%s\n", border)
	fmt.Fprintf(w, "  BUNDLE RECONSTRUCT REPORT\n")
	fmt.Fprintf(w, "%s\n", border)
	fmt.Fprintf(w, "  Bundle Kind:  %s\n", report.BundleKind)
	fmt.Fprintf(w, "  Modules:      %d (named=%d, unnamed=%d)\n",
		report.ModulesCount, report.NamedCount, report.UnnamedCount)
	fmt.Fprintf(w, "  Used MCP:     %v\n", report.UsedMCP)
	if report.BeautifyCount > 0 {
		fmt.Fprintf(w, "  Beautified:   %d modules\n", report.BeautifyCount)
	}
	fmt.Fprintf(w, "  Output Dir:   %s\n", Truncate(report.OutputDir, width-16))
	fmt.Fprintf(w, "  Manifest:     %s\n", Truncate(report.ManifestPath, width-16))
	fmt.Fprintf(w, "  Index:        %s\n", Truncate(report.IndexPath, width-16))
	fmt.Fprintf(w, "%s\n", border)
}
