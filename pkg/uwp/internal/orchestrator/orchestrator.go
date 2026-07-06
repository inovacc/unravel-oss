/*
Copyright (c) 2026 Security Research
*/

// Package orchestrator implements the heavy-lifting body of
// uwp.Analyze. Cycle-break: same pattern as pkg/winui/internal/orchestrator.
//
// D-18 enforcement: this package MUST NOT import pkg/dpapi. DPAPI blobs
// are flagged via byte-magic comparison (DPAPIMagic) and reported with
// provenance only. The acceptance grep targets pkg/uwp/uwp.go (the
// public API surface), so even this implementation file does not import
// the dpapi decrypt surface to keep the contract clean across the entire
// uwp package tree.
package orchestrator

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/msix"
	"github.com/inovacc/unravel-oss/pkg/uwp"
	uwpdetect "github.com/inovacc/unravel-oss/pkg/uwp/detect"
	uwpmanifest "github.com/inovacc/unravel-oss/pkg/uwp/manifest"
	"github.com/inovacc/unravel-oss/pkg/uwp/risk"
	"github.com/inovacc/unravel-oss/pkg/winui"
	_ "github.com/inovacc/unravel-oss/pkg/winui/runtime" // wire winui orchestrator
)

func init() {
	uwp.AnalyzeImpl = Run
}

func applyDefaults(o uwp.Options) uwp.Options {
	if !o.ExtractIfArchive {
		o.ExtractIfArchive = true
	}
	if !o.ScoreCapabilities {
		o.ScoreCapabilities = true
	}
	if !o.AnalyzeXAML {
		o.AnalyzeXAML = true
	}
	if !o.DPAPIFlagOnly {
		o.DPAPIFlagOnly = true
	}
	if !o.RejectSymlinks {
		o.RejectSymlinks = true
	}
	return o
}

// Run is the registered AnalyzeImpl.
func Run(path string, opts uwp.Options) (*uwp.Result, error) {
	if path == "" {
		return nil, fmt.Errorf("uwp path empty")
	}
	if containsTraversal(path) {
		return nil, fmt.Errorf("uwp path rejected: %s", path)
	}
	cleaned := filepath.Clean(path)
	if containsTraversal(cleaned) {
		return nil, fmt.Errorf("uwp path rejected: %s", path)
	}
	abs, err := filepath.Abs(cleaned)
	if err != nil {
		return nil, fmt.Errorf("resolve uwp path: %w", err)
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("stat uwp path: %w", err)
	}
	opts = applyDefaults(opts)

	res := &uwp.Result{}

	// Resolve to a "working directory" containing AppxManifest.xml.
	workDir := abs
	cleanup := func() {}
	if !st.IsDir() {
		ext := strings.ToLower(filepath.Ext(abs))
		if (ext == ".msix" || ext == ".appx" || ext == ".appxbundle") && opts.ExtractIfArchive {
			tmp, err := os.MkdirTemp("", "unravel-uwp-*")
			if err != nil {
				return nil, fmt.Errorf("mkdir tmp: %w", err)
			}
			cleanup = func() { _ = os.RemoveAll(tmp) }
			rep, eerr := msix.Extract(abs, tmp)
			if eerr != nil {
				cleanup()
				return nil, fmt.Errorf("msix extract: %w", eerr)
			}
			if rep != nil && len(rep.Errors) > 0 {
				res.Errors = append(res.Errors, rep.Errors...)
			}
			workDir = tmp
		} else {
			return nil, fmt.Errorf("uwp input is not a directory and not an archive: %s", abs)
		}
	}
	defer cleanup()

	// Manifest detection + parsing.
	manifestPath := filepath.Join(workDir, "AppxManifest.xml")
	if _, err := os.Stat(manifestPath); err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("AppxManifest.xml missing: %v", err))
	} else {
		fws, err := uwpdetect.DetectFromManifest(manifestPath)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("detect manifest: %v", err))
		}
		res.Frameworks = winui.MergeFrameworksDedup(res.Frameworks, fws)
		// Parse the full manifest for the summary.
		data, rerr := os.ReadFile(manifestPath)
		if rerr == nil {
			parsed, perr := msix.ParseAppxManifest(data)
			if perr == nil && parsed != nil {
				res.Manifest = uwpmanifest.Summarize(parsed)
			} else if perr != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("parse manifest: %v", perr))
			}
		}
	}

	// Capability scoring.
	if opts.ScoreCapabilities && res.Manifest != nil {
		var rubric *uwp.Rubric
		if opts.RubricPath != "" {
			r, err := risk.LoadRubric(opts.RubricPath)
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				res.Errors = append(res.Errors, fmt.Sprintf("load rubric: %v", err))
			} else if r != nil {
				rubric = r
			}
		}
		if rubric == nil {
			rubric = risk.DefaultRubric()
		}
		// Inspect signature on the original archive when available.
		var sig uwp.SignatureInfo
		if !st.IsDir() {
			s, _ := risk.InspectSignature(abs)
			sig = s
		} else {
			s, _ := risk.InspectSignature(workDir)
			sig = s
		}
		score := risk.Score(res.Manifest.Capabilities, sig, rubric)
		res.Score = &score
	}

	// XAML analysis via pkg/winui.
	if opts.AnalyzeXAML {
		wres, werr := winui.Analyze(workDir, winui.Options{
			DecodeXBF:      true,
			ScanPEEmbedded: true,
			ParsePRI:       true,
			RejectSymlinks: true,
		})
		if werr != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("winui analyze: %v", werr))
		} else if wres != nil {
			res.XAMLIndex = wres.XAMLIndex
			res.Frameworks = winui.MergeFrameworksDedup(res.Frameworks, wres.Frameworks)
		}
	}

	// DPAPI flag-only scan.
	if opts.DPAPIFlagOnly {
		flagDPAPIBlobs(workDir, res)
	}

	// Resolve IsUWP from accumulated framework signals.
	for _, fi := range res.Frameworks {
		if fi.Name == "UWP" {
			res.IsUWP = true
			break
		}
	}

	return res, nil
}

// flagDPAPIBlobs walks LocalState/ and RoamingState/ subdirectories
// (when present) and records any file whose first 8 bytes match the
// DPAPI magic header. NEVER decrypts.
func flagDPAPIBlobs(root string, res *uwp.Result) {
	for _, sub := range []string{"LocalState", "RoamingState"} {
		base := filepath.Join(root, sub)
		_ = filepath.WalkDir(base, func(path string, d fs.DirEntry, werr error) error {
			if werr != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			f, err := os.Open(path) //nolint:gosec // path constrained to root subtree
			if err != nil {
				return nil
			}
			head := make([]byte, len(uwp.DPAPIMagic))
			n, _ := f.Read(head)
			_ = f.Close()
			if n < len(uwp.DPAPIMagic) {
				return nil
			}
			if !equalBytes(head, uwp.DPAPIMagic) {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			res.DPAPIBlobs = append(res.DPAPIBlobs, uwp.DPAPIBlob{
				Path:  rel,
				Bytes: append([]byte{}, head...),
				Note:  "DPAPI-wrapped; use 'unravel dpapi' to decrypt",
			})
			res.Errors = append(res.Errors, fmt.Sprintf("dpapi:flagged: %s", rel))
			return nil
		})
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func containsTraversal(p string) bool {
	parts := strings.FieldsFunc(p, func(r rune) bool {
		return r == '/' || r == '\\'
	})
	return slices.Contains(parts, "..")
}
