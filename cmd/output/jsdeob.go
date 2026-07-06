/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/jsdeob"
)

// PrintBeautifyAIReport prints a structured single-file summary of a
// jsdeob.BeautifyAIReport including detected frameworks and the reason
// the structural-preservation guard rejected output (when applicable).
// 06-04 Task 1.
func PrintBeautifyAIReport(report *jsdeob.BeautifyAIReport, w io.Writer) {
	if report == nil {
		_, _ = fmt.Fprintln(w, "jsdeob beautify: nil report")
		return
	}
	width := 66
	border := strings.Repeat("=", width)

	fmt.Fprintf(w, "%s\n", border)
	fmt.Fprintf(w, "  JS BEAUTIFY (AI) REPORT\n")
	fmt.Fprintf(w, "%s\n", border)
	fmt.Fprintf(w, "  Beautified:   %v\n", report.Beautified)
	fmt.Fprintf(w, "  Chunks:       %d\n", report.ChunkCount)
	fmt.Fprintf(w, "  Raw Size:     %d bytes\n", report.RawSize)
	fmt.Fprintf(w, "  Out Size:     %d bytes\n", report.OutSize)

	if report.Reason != "" {
		fmt.Fprintf(w, "  Reason:       %s\n", Truncate(report.Reason, width-16))
	}

	if len(report.FrameworkDetected) > 0 {
		fmt.Fprintf(w, "  Frameworks (%d):\n", len(report.FrameworkDetected))
		for _, fw := range report.FrameworkDetected {
			fmt.Fprintf(w, "    - %s %s (confidence=%.2f)\n", fw.Name, fw.Version, fw.Confidence)
		}
	}
	fmt.Fprintf(w, "%s\n", border)
}
