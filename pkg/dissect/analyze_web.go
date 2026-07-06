/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"os"
	"path/filepath"

	"github.com/inovacc/unravel-oss/pkg/debug"
	"github.com/inovacc/unravel-oss/pkg/detect"
	"github.com/inovacc/unravel-oss/pkg/extension"
	"github.com/inovacc/unravel-oss/pkg/jsdeob"
	"github.com/inovacc/unravel-oss/pkg/manifest"
	"github.com/inovacc/unravel-oss/pkg/npm"
	"github.com/inovacc/unravel-oss/pkg/sourcemap"
)

func init() {
	RegisterAnalyzer(analyzeNPM, detect.TypeNPMPackage, detect.TypeNodeModule, detect.TypeMCPServer)
	RegisterAnalyzer(analyzeJavaScript, detect.TypeJavaScript)
	RegisterAnalyzer(analyzeSourceMap, detect.TypeSourceMap)
	RegisterAnalyzer(analyzeBrowserExtension, detect.TypeBrowserExtPkg)
}

func analyzeNPM(r *DissectResult, path string, opts Options) {
	r.runStep("npm analyze", func(sr *debug.StepRecorder) error {
		result, err := npm.Analyze(path)
		if err != nil {
			return err
		}
		r.NPMAnalysis = result
		sr.RecordOutput(result)
		return nil
	})

	// Run jsdeob on main entry point if obfuscation was detected
	if r.NPMAnalysis != nil && len(r.NPMAnalysis.ObfuscationIndicators) > 0 {
		r.runStep("jsdeob analyze", func(sr *debug.StepRecorder) error {
			pkg, err := npm.ParsePackageJSON(filepath.Join(path, "package.json"))
			if err != nil {
				return nil // non-fatal
			}

			mainFile := pkg.Main
			if mainFile == "" {
				mainFile = "index.js"
			}

			mainPath := filepath.Join(path, mainFile)
			if _, err := os.Stat(mainPath); err != nil {
				return nil // non-fatal
			}

			jsResult, err := analyzeJS(mainPath)
			if err != nil {
				return nil // non-fatal
			}

			r.JSAnalysis = jsResult

			sr.RecordOutput(jsResult)
			return nil
		})
	}
}

func analyzeJavaScript(r *DissectResult, path string, opts Options) {
	r.runStep("js analyze", func(sr *debug.StepRecorder) error {
		res, err := analyzeJS(path)
		if err != nil {
			return err
		}

		r.JSAnalysis = res

		sr.RecordOutput(res)
		return nil
	})

	if opts.Beautify {
		r.runStep("js beautify", func(sr *debug.StepRecorder) error {
			code, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			r.BeautifiedJS = jsdeob.Beautify(string(code))

			sr.RecordOutput(r.BeautifiedJS)
			return nil
		})
	}
}

func analyzeSourceMap(r *DissectResult, path string, opts Options) {
	r.runStep("sourcemap parse", func(sr *debug.StepRecorder) error {
		result, err := sourcemap.Parse(path)
		if err != nil {
			return err
		}
		r.SourceMapInfo = result
		sr.RecordOutput(result)
		return nil
	})

	// Resolve bundled npm dependencies from source map paths
	r.runStep("sourcemap resolve", func(sr *debug.StepRecorder) error {
		result, err := sourcemap.ResolveDependencies(path)
		if err != nil {
			return nil // non-fatal: resolution is best-effort
		}
		if len(result.Dependencies) > 0 {
			r.SourceMapDeps = result
			sr.RecordOutput(result)
		}
		return nil
	})
}

func analyzeBrowserExtension(r *DissectResult, path string, opts Options) {
	r.runStep("extension analysis", func(sr *debug.StepRecorder) error {
		m, err := manifest.LoadDefault()
		if err != nil {
			m = manifest.Default()
		}

		info, err := extension.AnalyzeSingleExtension(m, path, "", opts.Verbose)
		if err != nil {
			return err
		}

		r.ExtAnalysis = info

		sr.RecordOutput(info)
		return nil
	})

	if opts.OutputDir != "" {
		extractDir := filepath.Join(opts.OutputDir, "extension")

		r.runStep("extension extract", func(sr *debug.StepRecorder) error {
			m, err := manifest.LoadDefault()
			if err != nil {
				m = manifest.Default()
			}

			res, err := extension.ExtractExtensionData(m, path, "", extractDir, opts.Verbose)
			if err != nil {
				return err
			}

			r.ExtExtract = res

			sr.RecordOutput(res)
			return nil
		})
	}
}
