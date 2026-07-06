/*
Copyright (c) 2026 Security Research
*/

// Package orchestrator implements the heavy-lifting body of
// winui.Analyze. It lives in a child package to break the import cycle
// between pkg/winui and pkg/winui/xaml (which already imports
// pkg/winui for the canonical type set).
//
// On import, init() registers the implementation into
// winui.AnalyzeImpl / winui.QuickImpl. Callers blank-import this
// package (typically via pkg/winui/runtime) to enable the full
// pipeline.
package orchestrator

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/dotnet"
	"github.com/inovacc/unravel-oss/pkg/electron/binary"
	"github.com/inovacc/unravel-oss/pkg/winui"
	xaml "github.com/inovacc/unravel-oss/pkg/winui/xaml"
	"github.com/inovacc/unravel-oss/pkg/winui/xaml/embed"
	"github.com/inovacc/unravel-oss/pkg/winui/xaml/pri"
	"github.com/inovacc/unravel-oss/pkg/winui/xaml/xbf"
)

func init() {
	winui.AnalyzeImpl = Run
	winui.QuickImpl = RunQuick
}

// applyDefaults resolves zero-valued options to their canonical defaults.
func applyDefaults(o winui.Options) winui.Options {
	// Treat the zero-value of every bool as "use default true" so that
	// callers passing winui.Options{} get the documented behaviour.
	if !o.DecodeXBF {
		o.DecodeXBF = true
	}
	if !o.ScanPEEmbedded {
		o.ScanPEEmbedded = true
	}
	if !o.ParsePRI {
		o.ParsePRI = true
	}
	if !o.RejectSymlinks {
		o.RejectSymlinks = true
	}
	return o
}

// Run is the registered AnalyzeImpl. Best-effort: per-step failures are
// appended to res.Errors and never abort the orchestrator.
func Run(path string, opts winui.Options) (*winui.Result, error) {
	if path == "" {
		return nil, fmt.Errorf("winui path empty")
	}
	if containsTraversal(path) {
		return nil, fmt.Errorf("winui path rejected: %s", path)
	}
	cleaned := filepath.Clean(path)
	if containsTraversal(cleaned) {
		return nil, fmt.Errorf("winui path rejected: %s", path)
	}
	abs, err := filepath.Abs(cleaned)
	if err != nil {
		return nil, fmt.Errorf("resolve winui path: %w", err)
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("stat winui path: %w", err)
	}
	opts = applyDefaults(opts)

	res := &winui.Result{XAMLIndex: &winui.XAMLIndex{Entries: []winui.XAMLEntry{}}}

	if st.IsDir() {
		analyzeDirectory(abs, opts, res)
	} else {
		analyzeFile(abs, opts, res)
	}

	for _, fi := range res.Frameworks {
		if fi.Name == "WinUI 3" {
			res.IsWinUI = true
			break
		}
	}

	if opts.WriteXAMLDir != "" && res.XAMLIndex != nil {
		writeXAMLEntries(res, opts.WriteXAMLDir)
	}

	return res, nil
}

// RunQuick is the registered QuickImpl. The body matches winui's
// quickFallback so that calling AnalyzeQuick with or without the
// orchestrator imported produces equivalent output.
func RunQuick(_ string, deps *dotnet.DepsResult, imports []string) *winui.Result {
	res := &winui.Result{}
	if deps != nil {
		res.Frameworks = append(res.Frameworks, winui.DetectFromDepsLocal(deps)...)
	}
	if len(imports) > 0 {
		res.Signals = append(res.Signals, winui.DetectFromImportsLocal(imports)...)
	}
	for _, fi := range res.Frameworks {
		if fi.Name == "WinUI 3" {
			res.IsWinUI = true
			break
		}
	}
	return res
}

func analyzeDirectory(abs string, opts winui.Options, res *winui.Result) {
	idx, err := xaml.WalkDirectory(abs, xaml.WalkOptions{RejectSymlinks: opts.RejectSymlinks})
	if err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("walk: %v", err))
	} else if idx != nil {
		if opts.DecodeXBF {
			for i := range idx.Entries {
				e := &idx.Entries[i]
				if e.Kind != "xbf" {
					continue
				}
				data, rerr := os.ReadFile(filepath.Join(abs, e.Path))
				if rerr != nil {
					e.Errors = append(e.Errors, fmt.Sprintf("xbf read: %v", rerr))
					continue
				}
				// Use the unified helper so failures emit kind=xbf-raw with
				// RawBytesHex + AssembliesSizeHint instead of just an error
				// string (D-04 / BUG-04 graceful-fail contract).
				updated := xbf.DecodeXBFForEntry(data, e.Path)
				e.Kind = updated.Kind
				e.Recovered = updated.Recovered
				e.RawBytesHex = updated.RawBytesHex
				e.AssembliesSizeHint = updated.AssembliesSizeHint
				e.SourceBytes = updated.SourceBytes
				if len(updated.Errors) > 0 {
					e.Errors = append(e.Errors, updated.Errors...)
				}
			}
		}
		mergeXAMLIndex(res.XAMLIndex, idx)
	}

	if depsList := dotnet.FindDepsJSON(abs); len(depsList) > 0 {
		for _, dp := range depsList {
			deps, derr := dotnet.ParseDeps(dp)
			if derr != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("parse deps %s: %v", filepath.Base(dp), derr))
				continue
			}
			if deps == nil {
				continue
			}
			res.Frameworks = winui.MergeFrameworksDedup(res.Frameworks, winui.DetectFromDepsLocal(deps))
		}
	}

	if opts.ParsePRI {
		priPath := filepath.Join(abs, "resources.pri")
		if _, err := os.Stat(priPath); err == nil {
			pres, perr := pri.Parse(priPath)
			if perr != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("pri parse: %v", perr))
			} else if pres != nil {
				appendPRIEntries(res.XAMLIndex, pres)
			}
		}
	}

	if opts.ScanPEEmbedded {
		matches, _ := filepath.Glob(filepath.Join(abs, "*.exe"))
		for _, exe := range matches {
			scanPEEmbedded(exe, res)
		}
	}
}

func analyzeFile(abs string, opts winui.Options, res *winui.Result) {
	bi, err := binary.AnalyzeSingleFile(abs, false)
	if err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("binary analyze: %v", err))
	} else if bi != nil && len(bi.Imports) > 0 {
		signals := winui.DetectFromImportsLocal(bi.Imports)
		res.Signals = append(res.Signals, signals...)
		for _, sig := range signals {
			switch sig.Detail {
			case dllMUX:
				res.Frameworks = append(res.Frameworks, winui.FrameworkInfo{
					Name:       "WinUI 3",
					Confidence: sig.Confidence,
					Evidence:   []string{sig.Detail},
					Source:     "pe-import",
				})
			case dllWUX:
				res.Frameworks = append(res.Frameworks, winui.FrameworkInfo{
					Name:       "UWP/WinUI 2",
					Confidence: sig.Confidence,
					Evidence:   []string{sig.Detail},
					Source:     "pe-import",
				})
			}
		}
	}
	if opts.ScanPEEmbedded {
		scanPEEmbedded(abs, res)
	}
}

const (
	dllMUX = "Microsoft.UI.Xaml.dll"
	dllWUX = "Windows.UI.Xaml.dll"
)

func scanPEEmbedded(exePath string, res *winui.Result) {
	resources, err := embed.ScanPE(exePath)
	if err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("pe embed scan %s: %v", filepath.Base(exePath), err))
		return
	}
	for _, er := range resources {
		entry := winui.XAMLEntry{
			Path:        fmt.Sprintf("%s#rsrc:%d", filepath.Base(exePath), er.ResourceID),
			SourceBytes: int64(len(er.Bytes)),
		}
		switch er.Kind {
		case "xml":
			entry.Kind = "pe-embedded"
			entry.Recovered = string(er.Bytes)
		case "xbf":
			entry.Kind = "pe-embedded-xbf"
			dec, derr := xbf.DecodeXBFBytes(er.Bytes)
			if derr != nil {
				entry.Errors = append(entry.Errors, fmt.Sprintf("xbf decode: %v", derr))
			} else if dec != nil {
				entry.Recovered = dec.Recovered
			}
		default:
			continue
		}
		res.XAMLIndex.Entries = append(res.XAMLIndex.Entries, entry)
	}
}

func appendPRIEntries(idx *winui.XAMLIndex, pres *pri.PRIResult) {
	if idx == nil || pres == nil {
		return
	}
	const cap = 10000
	added := 0
	for _, r := range pres.Resources {
		if added >= cap {
			idx.Errors = append(idx.Errors, fmt.Sprintf("pri entries truncated at %d", cap))
			break
		}
		idx.Entries = append(idx.Entries, winui.XAMLEntry{
			Path:         "resources.pri#" + r.Name,
			Kind:         "pri",
			ResourceKeys: []string{r.Name},
			Recovered:    r.Value,
		})
		added++
	}
	for _, w := range pres.Warnings {
		idx.Errors = append(idx.Errors, "pri: "+w)
	}
}

func mergeXAMLIndex(dst, src *winui.XAMLIndex) {
	if dst == nil || src == nil {
		return
	}
	dst.Entries = append(dst.Entries, src.Entries...)
	dst.Errors = append(dst.Errors, src.Errors...)
}

func writeXAMLEntries(res *winui.Result, outDir string) {
	if res == nil || res.XAMLIndex == nil {
		return
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("mkdir %s: %v", outDir, err))
		return
	}
	for _, e := range res.XAMLIndex.Entries {
		if e.Recovered == "" {
			continue
		}
		if err := xaml.WriteXAML(e, "", outDir); err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("write %s: %v", e.Path, err))
		}
	}
}

func containsTraversal(p string) bool {
	parts := strings.FieldsFunc(p, func(r rune) bool {
		return r == '/' || r == '\\'
	})
	return slices.Contains(parts, "..")
}
