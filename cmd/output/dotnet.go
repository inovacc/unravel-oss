/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/dotnet/decompile"
)

// DisplayDecompileReport renders a human-readable summary of a Phase 5 .NET
// decompile run. Prints ilspycmd version, assembly count, file totals, and a
// (truncated) error list. Used by `unravel dotnet decompile`.
func DisplayDecompileReport(r *decompile.Result, b *decompile.BeautifyReport) {
	if r == nil {
		fmt.Println("(no decompile result)")
		return
	}

	fmt.Printf("ilspycmd version : %s\n", r.ILSpyVersion)
	fmt.Printf("assemblies       : %d\n", len(r.Assemblies))

	totalFiles := 0
	decompiled := 0
	for _, a := range r.Assemblies {
		totalFiles += a.FileCount
		if a.Decompiled {
			decompiled++
		}
	}

	fmt.Printf("decompiled       : %d / %d\n", decompiled, len(r.Assemblies))
	fmt.Printf("emitted .cs files: %d\n", totalFiles)

	if b != nil {
		fmt.Printf("run id           : %s\n", b.RunID)
		fmt.Printf("raw tree         : %s\n", b.RawTree)
		if b.BeautifiedTree != "" {
			fmt.Printf("beautified tree  : %s\n", b.BeautifiedTree)
		}
		fmt.Printf("beautify entries : %d\n", len(b.Assemblies))
	}

	if len(r.Errors) > 0 {
		fmt.Printf("\nErrors (%d):\n", len(r.Errors))
		const maxShown = 10
		for i, e := range r.Errors {
			if i >= maxShown {
				fmt.Printf("  ... (%d more)\n", len(r.Errors)-maxShown)
				break
			}
			fmt.Printf("  - %s\n", Truncate(e, 200))
		}
	}

	if b != nil && len(b.Errors) > 0 {
		fmt.Printf("\nBeautify errors (%d):\n", len(b.Errors))
		const maxShown = 10
		for i, e := range b.Errors {
			if i >= maxShown {
				fmt.Printf("  ... (%d more)\n", len(b.Errors)-maxShown)
				break
			}
			fmt.Printf("  - %s\n", Truncate(e, 200))
		}
	}
}
