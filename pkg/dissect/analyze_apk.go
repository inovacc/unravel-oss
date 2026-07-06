/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	rtdebug "runtime/debug"

	"github.com/inovacc/unravel-oss/pkg/android/apk"
	"github.com/inovacc/unravel-oss/pkg/android/dex"
	"github.com/inovacc/unravel-oss/pkg/android/dex2class"
	"github.com/inovacc/unravel-oss/pkg/android/framework"
	"github.com/inovacc/unravel-oss/pkg/android/kotlin"
	androidmanifest "github.com/inovacc/unravel-oss/pkg/android/manifest"
	"github.com/inovacc/unravel-oss/pkg/android/native"
	"github.com/inovacc/unravel-oss/pkg/android/network"
	"github.com/inovacc/unravel-oss/pkg/android/obfuscation"
	"github.com/inovacc/unravel-oss/pkg/android/protobuf"
	"github.com/inovacc/unravel-oss/pkg/android/resources"
	"github.com/inovacc/unravel-oss/pkg/android/secret"
	"github.com/inovacc/unravel-oss/pkg/android/telemetry"
	"github.com/inovacc/unravel-oss/pkg/android/tools"
	"github.com/inovacc/unravel-oss/pkg/debug"
	"github.com/inovacc/unravel-oss/pkg/detect"
	javadecompiler "github.com/inovacc/unravel-oss/pkg/java/decompiler"
)

func init() {
	RegisterAnalyzer(analyzeAndroid,
		detect.TypeAPK, detect.TypeAAB, detect.TypeXAPK,
		detect.TypeAPKS, detect.TypeAPKM,
	)
}

// gcFlush forces a garbage collection and returns memory to the OS.
// Called between heavy analysis steps in ATS mode to keep RSS low.
func gcFlush() {
	runtime.GC()
	rtdebug.FreeOSMemory()
}

func analyzeAndroid(r *DissectResult, path string, opts Options) {
	tw := r.teardown // nil when ATS is disabled — all steps fall back to in-memory

	// ─── Phase 1: Independent lightweight steps (flush each immediately) ───

	// Don't clear APKInfo here: manifest_info / kotlin_detection /
	// native_analysis (below) call reconcileAPKInfo to fold their richer
	// Permissions/Components/NativeLibs/HasKotlin onto it. In ATS mode
	// runStepATS flushes the step's return value to disk immediately, so if
	// we nil'd (and thus stopped updating) APKInfo here, the flushed
	// "apk_info" JSON would forever be the thin pre-reconcile snapshot — the
	// reconcile calls would fold their data onto a struct that was already
	// written to disk and about to be discarded. Instead APKInfo is kept
	// alive across the reconcile sites and explicitly re-flushed +
	// nil'd once native_analysis (the last reconcile trigger) finishes.
	r.runStepATS("apk_info", tw, func(sr *debug.StepRecorder) (any, error) {
		res, err := apk.Info(path, false)
		if err != nil {
			return nil, err
		}
		r.APKInfo = res
		sr.RecordOutput(res)
		return res, nil
	}, nil)

	r.runStepATS("apk_verify", tw, func(sr *debug.StepRecorder) (any, error) {
		res, err := apk.Verify(path)
		if err != nil {
			return nil, err
		}
		r.APKVerify = res
		sr.RecordOutput(res)
		return res, nil
	}, func() { r.APKVerify = nil })

	r.runStepATS("apk_cert", tw, func(sr *debug.StepRecorder) (any, error) {
		res, err := apk.ExtractCertificates(path)
		if err != nil {
			return nil, err
		}
		r.APKCert = res
		sr.RecordOutput(res)
		return res, nil
	}, func() { r.APKCert = nil })

	// Manifest analysis (binary XML decode + security analysis)
	// Keep ManifestInfo alive — telemetry detection needs it in Phase 3.
	r.runStepATS("manifest_info", tw, func(sr *debug.StepRecorder) (any, error) {
		res, err := androidmanifest.ParseAPK(path)
		if err != nil {
			return nil, err
		}
		r.ManifestInfo = res
		r.ManifestAnalysis = androidmanifest.Analyze(res)
		reconcileAPKInfo(r) // fold Permissions/Components onto APKInfo before ATS truncates ManifestInfo below
		sr.RecordOutput(r.ManifestAnalysis)

		if opts.OutputDir != "" {
			xmlData := androidmanifest.ToXML(res)
			if xmlData != "" {
				xmlPath := filepath.Join(opts.OutputDir, "AndroidManifest.decoded.xml")
				_ = os.WriteFile(xmlPath, []byte(xmlData), 0o644)
			}
		}
		return res, nil
	}, nil) // don't nil — telemetry needs it

	// Flush manifest analysis separately (it's a derived result)
	if r.ManifestAnalysis != nil && tw != nil {
		_ = tw.Flush("manifest_analysis", r.ManifestAnalysis, 0, "ok")
		r.ManifestAnalysis = nil
	}

	// Secret scanning (heavy: reads all ZIP entries)
	r.runStepATS("secret_scan", tw, func(sr *debug.StepRecorder) (any, error) {
		res, err := secret.Scan(path)
		if err != nil {
			return nil, err
		}
		r.Secrets = res
		sr.RecordOutput(res)
		return res, nil
	}, func() { r.Secrets = nil })

	if tw != nil {
		gcFlush()
	}

	// ─── Phase 2: DEX analysis (keep alive for Phase 3 dependents) ───

	r.runStepATS("dex_analysis", tw, func(sr *debug.StepRecorder) (any, error) {
		res, err := dex.ScanAPK(path)
		if err != nil {
			return nil, err
		}
		r.DEXAnalysis = res
		sr.RecordOutput(res)
		return res, nil
	}, nil) // don't nil yet — Phase 3 needs it

	// ─── Phase 3: DEX-dependent steps (flush each, then flush DEX) ───

	if r.DEXAnalysis != nil {
		r.runStepATS("kotlin_detection", tw, func(sr *debug.StepRecorder) (any, error) {
			res := kotlin.ScanDEX(r.DEXAnalysis)
			r.KotlinAnalysis = res
			reconcileAPKInfo(r) // fold HasKotlin onto APKInfo before ATS nils KotlinAnalysis
			sr.RecordOutput(res)
			return res, nil
		}, func() { r.KotlinAnalysis = nil })

		r.runStepATS("framework_detection", tw, func(sr *debug.StepRecorder) (any, error) {
			res, err := framework.ScanAPK(path, r.DEXAnalysis)
			if err != nil {
				return nil, err
			}
			r.FrameworkAnalysis = res
			sr.RecordOutput(res)
			return res, nil
		}, func() { r.FrameworkAnalysis = nil })

		r.runStepATS("network_analysis", tw, func(sr *debug.StepRecorder) (any, error) {
			res, err := network.ScanAPK(path, r.DEXAnalysis)
			if err != nil {
				return nil, err
			}
			r.NetworkAnalysis = res
			sr.RecordOutput(res)
			return res, nil
		}, func() { r.NetworkAnalysis = nil })

		r.runStepATS("obfuscation_detection", tw, func(sr *debug.StepRecorder) (any, error) {
			result := obfuscation.Analyze(r.DEXAnalysis)
			result.HasMapping = obfuscation.DetectMapping(path)
			result.Packer = obfuscation.DetectPacker(path)
			if result.Packer != nil {
				result.Type = obfuscation.ObfPacker
			}
			if result.HasMapping && result.Type == obfuscation.ObfUnknown {
				result.Type = obfuscation.ObfProGuard
			}
			r.ObfuscationAnalysis = result
			sr.RecordOutput(result)
			return result, nil
		}, func() { r.ObfuscationAnalysis = nil })

		r.runStepATS("protobuf_analysis", tw, func(sr *debug.StepRecorder) (any, error) {
			res, err := protobuf.ScanAPK(path, r.DEXAnalysis)
			if err != nil {
				return nil, err
			}
			r.ProtobufAnalysis = res
			sr.RecordOutput(res)
			return res, nil
		}, func() { r.ProtobufAnalysis = nil })

		r.runStepATS("telemetry_detection", tw, func(sr *debug.StepRecorder) (any, error) {
			res := telemetry.ScanAPK(r.DEXAnalysis, r.ManifestInfo)
			r.TelemetryAnalysis = res
			sr.RecordOutput(res)
			return res, nil
		}, func() { r.TelemetryAnalysis = nil })
	}

	// All DEX dependents done — flush DEX and ManifestInfo now
	if tw != nil && r.DEXAnalysis != nil {
		// DEX was already flushed by runStepATS but not nilled — nil it now
		r.DEXAnalysis = nil
		// Preserve identity-relevant scalar fields on ManifestInfo so
		// downstream consumers (knowledge.extractIdentity, P35-01) can still
		// derive platform=android + package_id after ATS flush. Drop the
		// large slices (Permissions, Components, Features) to keep memory
		// bounded — those have already been consumed by ManifestAnalysis /
		// telemetry above.
		if r.ManifestInfo != nil {
			r.ManifestInfo = &androidmanifest.Manifest{
				Package:     r.ManifestInfo.Package,
				VersionCode: r.ManifestInfo.VersionCode,
				VersionName: r.ManifestInfo.VersionName,
				MinSDK:      r.ManifestInfo.MinSDK,
				TargetSDK:   r.ManifestInfo.TargetSDK,
				Security:    r.ManifestInfo.Security,
			}
		}
		gcFlush()
	}

	// ─── Phase 4: Independent heavy steps (flush + GC each) ───

	r.runStepATS("native_analysis", tw, func(sr *debug.StepRecorder) (any, error) {
		res, err := native.ScanAPK(path)
		if err != nil {
			return nil, err
		}
		r.NativeAnalysis = res
		reconcileAPKInfo(r) // fold NativeLibs onto APKInfo before ATS nils NativeAnalysis
		sr.RecordOutput(res)
		return res, nil
	}, func() {
		r.NativeAnalysis = nil
		// native_analysis is the last reconcileAPKInfo trigger (after
		// manifest_info and kotlin_detection above) — re-flush "apk_info" now
		// so the on-disk snapshot reflects the fully reconciled
		// Permissions/Components/NativeLibs/HasKotlin, overwriting the thin
		// pre-reconcile snapshot written when the apk_info step itself ran.
		// Only then is it safe to nil APKInfo and let the GC reclaim it.
		if tw != nil && r.APKInfo != nil {
			_ = tw.Flush("apk_info", r.APKInfo, 0, "ok")
		}
		r.APKInfo = nil
		gcFlush()
	})

	r.runStepATS("resource_analysis", tw, func(sr *debug.StepRecorder) (any, error) {
		res, err := resources.ScanAPK(path)
		if err != nil {
			return nil, err
		}
		r.ResourceAnalysis = res
		sr.RecordOutput(res)
		return res, nil
	}, func() {
		r.ResourceAnalysis = nil
		gcFlush()
	})

	// Tools status (lightweight, no flush needed)
	r.runStep("tools_status", func(sr *debug.StepRecorder) error {
		registry := tools.NewRegistry()
		r.ToolsStatus = registry.DetectAll()
		sr.RecordOutput(r.ToolsStatus)
		return nil
	})

	// Auto-enable .NET decompilation for Xamarin apps
	// Note: FrameworkAnalysis may have been flushed. Load it back briefly if needed.
	if tw != nil && r.FrameworkAnalysis == nil {
		var fa framework.ScanResult
		if loadErr := tw.Load("framework_detection", &fa); loadErr == nil {
			if fa.Xamarin != nil {
				opts.DecompileDotnet = true
			}
		}
	} else if r.FrameworkAnalysis != nil && r.FrameworkAnalysis.Xamarin != nil {
		opts.DecompileDotnet = true
	}

	// ─── Phase 5: Extraction and decompilation (only when -o is set) ───

	if opts.OutputDir != "" {
		extractDir := filepath.Join(opts.OutputDir, "extracted")

		r.runStepATS("apk_extract", tw, func(sr *debug.StepRecorder) (any, error) {
			res, err := apk.Extract(path, extractDir, opts.Verbose)
			if err != nil {
				return nil, err
			}
			r.APKExtract = res
			sr.RecordOutput(res)
			return res, nil
		}, func() {
			r.APKExtract = nil
			gcFlush()
		})

		decompileDir := filepath.Join(opts.OutputDir, "decompiled")

		r.runStepATS("decompile", tw, func(sr *debug.StepRecorder) (any, error) {
			ctx := context.Background()
			res, err := tools.Decompile(ctx, tools.DecompileOptions{
				InputPath:       path,
				OutputDir:       decompileDir,
				Deobfuscate:     opts.Deobfuscate,
				DecompileNative: opts.DecompileNative,
				DecompileDotnet: opts.DecompileDotnet,
				Verbose:         opts.Verbose,
			})
			if err != nil {
				return nil, err
			}
			r.Decompile = res
			sr.RecordOutput(res)
			return res, nil
		}, func() {
			r.Decompile = nil
			gcFlush()
		})

		// Pure Go DEX→Java decompilation (no external tools required)
		nativeJavaDir := filepath.Join(opts.OutputDir, "java-source")
		r.runStep("dex2java (native)", func(sr *debug.StepRecorder) error {
			parseResult, err := dex.ScanAPK(path)
			if err != nil {
				return err
			}

			translator := &dex2class.Translator{}
			nativeDecomp := javadecompiler.NewHybridDecompiler()
			translated, decompiled := 0, 0

			for _, df := range parseResult.DexFiles {
				rawDEX, err := readAPKEntry(path, df.Name)
				if err != nil {
					continue
				}

				_, _ = translator.TranslateStreaming(&df, rawDEX, func(cf *dex2class.ClassOutput) error {
					translated++
					if len(cf.Data) == 0 {
						return nil
					}

					source, err := nativeDecomp.DecompileBytes(cf.Data)
					cf.Data = nil
					if err != nil {
						return nil
					}

					decompiled++
					javaPath := filepath.Join(nativeJavaDir, cf.ClassName+".java")
					if err := os.MkdirAll(filepath.Dir(javaPath), 0o755); err == nil {
						_ = os.WriteFile(javaPath, []byte(source), 0o644)
					}

					if translated%200 == 0 {
						gcFlush()
					}
					return nil
				})
				rawDEX = nil
			}

			// Free the parse result immediately
			parseResult = nil
			gcFlush()

			sr.RecordOutput(map[string]int{"translated": translated, "decompiled": decompiled})
			return nil
		})

		// Post-decompile secret scan
		if _, err := os.Stat(decompileDir); err == nil {
			r.runStepATS("decompile_secret_scan", tw, func(sr *debug.StepRecorder) (any, error) {
				dirResult, err := secret.ScanDirectory(decompileDir)
				if err != nil {
					return nil, err
				}

				// In ATS mode, secrets were flushed earlier — load them back to merge
				if tw != nil && r.Secrets == nil {
					var prev secret.ScanResult
					if loadErr := tw.Load("secret_scan", &prev); loadErr == nil {
						secret.MergeResults(&prev, dirResult)
						r.Secrets = &prev
					} else {
						r.Secrets = dirResult
					}
				} else if r.Secrets != nil {
					secret.MergeResults(r.Secrets, dirResult)
				} else {
					r.Secrets = dirResult
				}

				sr.RecordOutput(r.Secrets)
				return r.Secrets, nil
			}, func() { r.Secrets = nil })
		}
	}
}

// reconcileAPKInfo fills in APKInfo's thin dissect-time fields (Permissions,
// Components, NativeLibs, HasKotlin) from the richer per-analyzer results
// (ManifestInfo, NativeAnalysis, KotlinAnalysis) once those analyzers have
// run. apk.Info (the "apk_info" step) only inspects the ZIP central
// directory — it never decodes the binary AndroidManifest.xml or does a
// real native-library/Kotlin scan, so on its own APKInfo.Permissions and
// APKInfo.Components are always empty and APKInfo.NativeLibs/.HasKotlin can
// under-report. Consumers that read the typed APKInfo fields directly
// (MCP tools, JSON output, downstream reports) would otherwise see
// incomplete data even though the dedicated analyzers found the full
// picture — e.g. on a real app (Picsart) the manifest analyzer extracted 38
// permissions / 310 components while APKInfo.Permissions/.Components
// stayed empty.
//
// This is additive/defensive only: it never removes or shrinks data
// already on APKInfo, a nil APKInfo is a no-op, and an absent analyzer
// result leaves the corresponding thin value untouched (no regression on
// non-APK paths or older result shapes).
func reconcileAPKInfo(r *DissectResult) {
	if r.APKInfo == nil {
		return
	}

	if r.ManifestInfo != nil {
		if len(r.APKInfo.Permissions) == 0 && len(r.ManifestInfo.Permissions) > 0 {
			r.APKInfo.Permissions = r.ManifestInfo.Permissions
		}
		if len(r.APKInfo.Components) == 0 && len(r.ManifestInfo.Components) > 0 {
			r.APKInfo.Components = r.ManifestInfo.Components
		}
	}

	if r.NativeAnalysis != nil && r.NativeAnalysis.TotalLibs > 0 && len(r.APKInfo.NativeLibs) == 0 {
		libs := make(map[string]int, len(r.NativeAnalysis.ABIs))
		for _, abi := range r.NativeAnalysis.ABIs {
			libs[abi.ABI] = abi.Count
		}
		if len(libs) == 0 {
			// Analyzer confirms libs exist but has no per-ABI breakdown
			// (e.g. ABI detection failed) — still surface the total.
			libs["unknown"] = r.NativeAnalysis.TotalLibs
		}
		r.APKInfo.NativeLibs = libs
	}

	if !r.APKInfo.HasKotlin && r.KotlinAnalysis != nil && r.KotlinAnalysis.HasKotlin {
		r.APKInfo.HasKotlin = true
	}
}

// readAPKEntry reads a ZIP entry from an APK file.
func readAPKEntry(apkPath, entryName string) ([]byte, error) {
	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = zr.Close() }()

	for _, f := range zr.File {
		if f.Name == entryName {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			data, err := io.ReadAll(rc)
			_ = rc.Close()
			return data, err
		}
	}
	return nil, fmt.Errorf("entry %q not found", entryName)
}
