/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"fmt"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/asar"
)

// PrintASARList prints a tabular listing of ASAR archive contents.
func PrintASARList(header *asar.Header, headerSize int) {
	fmt.Printf("ASAR Archive Contents (header: %d bytes)\n", headerSize)
	fmt.Println(strings.Repeat("-", 70))
	fmt.Printf("%-50s %10s %s\n", "PATH", "SIZE", "FLAGS")
	fmt.Println(strings.Repeat("-", 70))

	files := asar.CollectFiles(header.Files, "")

	var (
		totalSize           int64
		fileCount, dirCount int
	)

	for _, f := range files {
		flags := ""
		if f.Executable {
			flags += "X"
		}

		if f.Unpacked {
			flags += "U"
		}

		if f.IsDir {
			flags = "DIR"
			dirCount++

			fmt.Printf("%-50s %10s %s\n", f.Path+"/", "-", flags)
		} else {
			fileCount++
			totalSize += f.Size
			fmt.Printf("%-50s %10d %s\n", f.Path, f.Size, flags)
		}
	}

	fmt.Println(strings.Repeat("-", 70))
	fmt.Printf("Total: %d files, %d directories, %s\n", fileCount, dirCount, asar.FormatBytes(totalSize))
}

// PrintASARSummary prints the ASAR extraction completion report.
func PrintASARSummary(report *asar.ExtractReport) {
	fmt.Println("\nExtraction Complete")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("Source:      %s\n", report.Source)
	fmt.Printf("Output:      %s\n", report.Output)
	fmt.Printf("Files:       %d\n", report.Files)
	fmt.Printf("Directories: %d\n", report.Directories)
	fmt.Printf("Total Size:  %s\n", asar.FormatBytes(report.TotalSize))

	if len(report.Errors) > 0 {
		fmt.Printf("\nErrors (%d):\n", len(report.Errors))

		for _, e := range report.Errors {
			fmt.Printf("  - %s\n", e)
		}
	}

	fmt.Println(strings.Repeat("=", 50))
}
