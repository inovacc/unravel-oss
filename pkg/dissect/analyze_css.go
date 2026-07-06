/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"path/filepath"

	"github.com/inovacc/unravel-oss/pkg/css"
	"github.com/inovacc/unravel-oss/pkg/debug"
	"github.com/inovacc/unravel-oss/pkg/detect"
)

func init() {
	RegisterSupplementalAnalyzer(analyzeCSS, detect.TypeElectronApp, detect.TypeTauriApp, detect.TypeASAR)
}

func analyzeCSS(r *DissectResult, path string, opts Options) {
	if opts.OutputDir == "" {
		return // CSS extraction needs an output directory
	}

	r.runStep("css extract", func(sr *debug.StepRecorder) error {
		cssOpts := css.Options{
			OutputDir:      filepath.Join(opts.OutputDir, "css"),
			Normalize:      true,
			Deduplicate:    true,
			ResolveImports: true,
			Verbose:        opts.Verbose,
		}

		result, err := css.Extract(path, cssOpts)
		if err != nil {
			return err
		}

		r.CSSExtraction = result

		// Write manifest alongside extracted CSS.
		if result != nil && cssOpts.OutputDir != "" {
			_ = css.WriteManifest(result, cssOpts.OutputDir)
		}

		sr.RecordOutput(result)
		return nil
	})
}
