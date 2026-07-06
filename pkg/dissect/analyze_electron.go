/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"path/filepath"

	"github.com/inovacc/unravel-oss/pkg/asar"
	"github.com/inovacc/unravel-oss/pkg/cert"
	"github.com/inovacc/unravel-oss/pkg/debug"
	"github.com/inovacc/unravel-oss/pkg/detect"
	"github.com/inovacc/unravel-oss/pkg/disasm"
	"github.com/inovacc/unravel-oss/pkg/electron/app"
	"github.com/inovacc/unravel-oss/pkg/manifest"
	"github.com/inovacc/unravel-oss/pkg/sourcemap"
)

func init() {
	RegisterAnalyzer(analyzeElectronApp, detect.TypeElectronApp)
	RegisterAnalyzer(analyzeTauriApp, detect.TypeTauriApp)
	RegisterAnalyzer(analyzeASAR, detect.TypeASAR)
}

func analyzeElectronApp(r *DissectResult, path string, opts Options) {
	r.runStep("app analysis", func(sr *debug.StepRecorder) error {
		m, err := manifest.LoadDefault()
		if err != nil {
			m = manifest.Default()
		}

		res, err := app.RunAnalysis(path, m, "electron", opts.Verbose)
		if err != nil {
			return err
		}

		r.AppAnalysis = res

		sr.RecordOutput(res)
		return nil
	})

	// Scan the Electron app directory for source maps
	scanDir := path
	if opts.OutputDir != "" {
		scanDir = opts.OutputDir
	}
	r.runStep("sourcemap scan", func(sr *debug.StepRecorder) error {
		scanResult, err := sourcemap.ScanDir(scanDir)
		if err != nil {
			return err
		}
		if scanResult.TotalMaps > 0 {
			sr.RecordOutput(scanResult)

			// Parse the first source map for detailed info
			if len(scanResult.Maps) > 0 {
				parsed, parseErr := sourcemap.Parse(scanResult.Maps[0].Path)
				if parseErr == nil {
					r.SourceMapInfo = parsed
				}
			}
		}
		return nil
	})
}

func analyzeTauriApp(r *DissectResult, path string, opts Options) {
	r.runStep("cert info", func(sr *debug.StepRecorder) error {
		res, err := cert.ExtractCertificates(path)
		if err != nil {
			return err
		}

		r.CertInfo = res

		sr.RecordOutput(res)
		return nil
	})

	if opts.Disassemble {
		r.runStep("disassemble", func(sr *debug.StepRecorder) error {
			res, err := disasm.Disassemble(path, disasm.Options{MaxInstructions: 1000})
			if err != nil {
				return err
			}

			r.Disassembly = res

			sr.RecordOutput(res)
			return nil
		})
	}

	r.runStep("app analysis", func(sr *debug.StepRecorder) error {
		m, err := manifest.LoadDefault()
		if err != nil {
			m = manifest.Default()
		}

		res, err := app.RunAnalysis(path, m, "tauri", opts.Verbose)
		if err != nil {
			return err
		}

		r.AppAnalysis = res

		sr.RecordOutput(res)
		return nil
	})
}

func analyzeASAR(r *DissectResult, path string, opts Options) {
	r.runStep("asar parse", func(sr *debug.StepRecorder) error {
		f, header, headerSize, _, err := asar.OpenAndParse(path)
		if err != nil {
			return err
		}

		defer func() { _ = f.Close() }()

		files := asar.CollectFiles(header.Files, "")
		fileCount := 0
		dirCount := 0

		var totalSize int64

		for _, ef := range files {
			if ef.IsDir {
				dirCount++
			} else {
				fileCount++
				totalSize += ef.Size
			}
		}

		r.ASARFiles = files
		r.ASARStats = &ASARSummary{
			HeaderSize: headerSize,
			FileCount:  fileCount,
			DirCount:   dirCount,
			TotalSize:  totalSize,
		}

		sr.RecordOutput(r.ASARStats)
		return nil
	})

	// Extract ASAR and scan for source maps when output dir is set
	if opts.OutputDir != "" {
		extractDir := filepath.Join(opts.OutputDir, "asar_extracted")

		r.runStep("asar extract", func(sr *debug.StepRecorder) error {
			f, header, _, dataOffset, err := asar.OpenAndParse(path)
			if err != nil {
				return err
			}
			defer func() { _ = f.Close() }()

			report := asar.Extract(f, header, dataOffset, extractDir, path, opts.Verbose)
			sr.RecordOutput(report)
			return nil
		})

		r.runStep("sourcemap scan", func(sr *debug.StepRecorder) error {
			scanResult, err := sourcemap.ScanDir(extractDir)
			if err != nil {
				return err
			}
			if scanResult.TotalMaps > 0 {
				sr.RecordOutput(scanResult)

				// Parse the first source map for detailed info
				if len(scanResult.Maps) > 0 {
					parsed, parseErr := sourcemap.Parse(scanResult.Maps[0].Path)
					if parseErr == nil {
						r.SourceMapInfo = parsed
					}
				}
			}
			return nil
		})
	}
}
