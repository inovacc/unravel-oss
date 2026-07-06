/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/inovacc/unravel-oss/pkg/cert"
	"github.com/inovacc/unravel-oss/pkg/debug"
	"github.com/inovacc/unravel-oss/pkg/detect"
	"github.com/inovacc/unravel-oss/pkg/disasm"
	"github.com/inovacc/unravel-oss/pkg/dotnet"
	"github.com/inovacc/unravel-oss/pkg/electron/binary"
	"github.com/inovacc/unravel-oss/pkg/garble"
	"github.com/inovacc/unravel-oss/pkg/garble/goresym"
	"github.com/inovacc/unravel-oss/pkg/upx"
)

func init() {
	RegisterAnalyzer(analyzeNativeBinary, detect.TypePE, detect.TypeELF, detect.TypeMachO, detect.TypeMachOFat)
	RegisterAnalyzer(analyzeGoBinary, detect.TypeGoBinary)
	RegisterAnalyzer(analyzeUPXPacked, detect.TypeUPXPacked)
}

func analyzeGoBinary(r *DissectResult, path string, opts Options) {
	r.runStep("garble detect", func(sr *debug.StepRecorder) error {
		res, err := garble.Detect(path)
		if err != nil {
			return err
		}

		r.GarbleDetect = res

		sr.RecordOutput(res)
		return nil
	})
	r.runStep("garble info", func(sr *debug.StepRecorder) error {
		res, err := garble.ExtractInfo(path)
		if err != nil {
			return err
		}

		r.GarbleInfo = res

		sr.RecordOutput(res)
		return nil
	})
	r.runStep("go symbols", func(sr *debug.StepRecorder) error {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		var gv string
		if r.GarbleInfo != nil {
			gv = r.GarbleInfo.GoVersion
		}

		res, err := goresym.Recover(ctx, path, goresym.Options{GoVersion: gv})
		if err != nil {
			// Tool absent / backend stubbed is the normal default-build
			// state — skip silently and never pollute r.Errors. Any other
			// error (e.g. PE-stripped pclntab miss) is recorded once and
			// never blocks the pipeline. Returning nil keeps runStep from
			// double-recording into r.Errors.
			if errors.Is(err, goresym.ErrNotImplemented) {
				return nil
			}
			r.Errors = append(r.Errors, fmt.Sprintf("go symbol recovery: %v", err))
			return nil
		}

		r.GoSymbols = res

		sr.RecordOutput(res)
		return nil
	})
	// Recover the communication surface (hosts, gRPC/proto RPCs, config refs) by
	// streaming the binary — deliberately NOT gated by maxStringsFileSize, since
	// Go agent binaries routinely exceed it and the scan is bounded-memory. This
	// is the primary RE signal for stripped standalone Go apps.
	r.runStep("go surface", func(sr *debug.StepRecorder) error {
		res, err := scanGoSurface(path)
		if err != nil {
			return err
		}

		r.GoSurface = res

		sr.RecordOutput(res)
		return nil
	})
	r.runStep("cert info", func(sr *debug.StepRecorder) error {
		res, err := cert.ExtractCertificates(path)
		if err != nil {
			return err
		}

		r.CertInfo = res

		sr.RecordOutput(res)
		return nil
	})
	r.runStep("binary info", func(sr *debug.StepRecorder) error {
		res, err := binary.AnalyzeSingleFile(path, opts.Verbose)
		if err != nil {
			return err
		}

		r.BinaryInfo = res

		sr.RecordOutput(res)
		return nil
	})
	if r.Size <= maxStringsFileSize {
		r.runStep("garble strings", func(sr *debug.StepRecorder) error {
			res, err := garble.ExtractStrings(path, 6)
			if err != nil {
				return err
			}

			r.GarbleStrings = res

			sr.RecordOutput(res)
			return nil
		})
	}
	r.runStep("garble symbols", func(sr *debug.StepRecorder) error {
		res, err := garble.AnalyzeSymbols(path)
		if err != nil {
			return err
		}

		r.GarbleSymbols = res

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
}

func analyzeUPXPacked(r *DissectResult, path string, opts Options) {
	r.runStep("upx info", func(sr *debug.StepRecorder) error {
		res, err := upx.Info(path)
		if err != nil {
			return err
		}

		r.UPXInfo = res

		sr.RecordOutput(res)
		return nil
	})
	r.runStep("cert info", func(sr *debug.StepRecorder) error {
		res, err := cert.ExtractCertificates(path)
		if err != nil {
			return err
		}

		r.CertInfo = res

		sr.RecordOutput(res)
		return nil
	})
	r.runStep("binary info", func(sr *debug.StepRecorder) error {
		res, err := binary.AnalyzeSingleFile(path, opts.Verbose)
		if err != nil {
			return err
		}

		r.BinaryInfo = res

		sr.RecordOutput(res)
		return nil
	})
	if r.Size <= maxStringsFileSize {
		r.runStep("garble strings", func(sr *debug.StepRecorder) error {
			res, err := garble.ExtractStrings(path, 6)
			if err != nil {
				return err
			}

			r.GarbleStrings = res

			sr.RecordOutput(res)
			return nil
		})
	}
	r.runStep("garble symbols", func(sr *debug.StepRecorder) error {
		res, err := garble.AnalyzeSymbols(path)
		if err != nil {
			return err
		}

		r.GarbleSymbols = res

		sr.RecordOutput(res)
		return nil
	})

	// Unpack and re-analyze if output dir is set
	if opts.OutputDir != "" {
		unpackedPath := filepath.Join(opts.OutputDir, "unpacked_"+filepath.Base(path))

		r.runStep("upx unpack", func(sr *debug.StepRecorder) error {
			return upx.Unpack(path, unpackedPath)
		})

		// Re-run dispatch on unpacked binary if unpack succeeded
		if _, err := os.Stat(unpackedPath); err == nil {
			unpackedDr, dErr := detect.Detect(unpackedPath)
			if dErr == nil {
				dispatch(r, unpackedPath, unpackedDr.FileType, Options{
					Verbose:     opts.Verbose,
					Disassemble: opts.Disassemble,
				})
			}
		}
	}
}

func analyzeNativeBinary(r *DissectResult, path string, opts Options) {
	r.runStep("cert info", func(sr *debug.StepRecorder) error {
		res, err := cert.ExtractCertificates(path)
		if err != nil {
			return err
		}

		r.CertInfo = res

		sr.RecordOutput(res)
		return nil
	})
	r.runStep("binary info", func(sr *debug.StepRecorder) error {
		res, err := binary.AnalyzeSingleFile(path, opts.Verbose)
		if err != nil {
			return err
		}

		r.BinaryInfo = res

		sr.RecordOutput(res)
		return nil
	})
	if r.Size <= maxStringsFileSize {
		r.runStep("garble strings", func(sr *debug.StepRecorder) error {
			res, err := garble.ExtractStrings(path, 6)
			if err != nil {
				return err
			}

			r.GarbleStrings = res

			sr.RecordOutput(res)
			return nil
		})
	}
	r.runStep("garble symbols", func(sr *debug.StepRecorder) error {
		res, err := garble.AnalyzeSymbols(path)
		if err != nil {
			return err
		}

		r.GarbleSymbols = res

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

	// Check for .NET sibling files
	dir := filepath.Dir(path)
	if depsFiles := dotnet.FindDepsJSON(dir); len(depsFiles) > 0 {
		r.runStep("dotnet deps", func(sr *debug.StepRecorder) error {
			result, err := dotnet.ParseDeps(depsFiles[0])
			if err != nil {
				return err
			}

			r.DotnetDeps = result

			sr.RecordOutput(result)
			return nil
		})
	}
	if rcFiles := dotnet.FindRuntimeConfig(dir); len(rcFiles) > 0 {
		r.runStep("dotnet runtime", func(sr *debug.StepRecorder) error {
			result, err := dotnet.ParseRuntimeConfig(rcFiles[0])
			if err != nil {
				return err
			}

			r.DotnetRuntime = result

			sr.RecordOutput(result)
			return nil
		})
	}

	// Filter .NET strings: use garble strings if available, otherwise use binary info strings.
	// Trigger on either sibling .deps.json or binary-level .NET detection.
	isDotNet := r.DotnetDeps != nil || (r.BinaryInfo != nil && r.BinaryInfo.IsDotNet)
	if isDotNet {
		r.runStep("dotnet strings", func(sr *debug.StepRecorder) error {
			var rawStrings []string

			if r.GarbleStrings != nil {
				for _, s := range r.GarbleStrings.Strings {
					rawStrings = append(rawStrings, s.Value)
				}
			} else if r.BinaryInfo != nil && len(r.BinaryInfo.SampleStrings) > 0 {
				// Fall back to BinaryInfo sample strings (already .NET-filtered
				// if BinaryInfo detected .NET, but re-filter for consistency)
				rawStrings = r.BinaryInfo.SampleStrings
			}

			if len(rawStrings) > 0 {
				r.DotnetStrings = dotnet.FilterStrings(rawStrings)
				sr.RecordOutput(r.DotnetStrings)
			}
			return nil
		})
	}
}
