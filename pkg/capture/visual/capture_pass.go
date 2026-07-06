/*
Copyright (c) 2026 Security Research
*/
package visual

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/inovacc/unravel-oss/pkg/capture"
	"github.com/inovacc/unravel-oss/pkg/capture/cdp"
	"github.com/inovacc/unravel-oss/pkg/jsdeob/framework"
	"github.com/inovacc/unravel-oss/pkg/knowledge"
	"github.com/inovacc/unravel-oss/pkg/knowledge/components"
)

// captureState performs a per-state capture across all configured viewports.
// Each (state, viewport) tuple writes 4 sibling files atomically:
//
//	<kb>/visual/<run-id>/<component>/<state-slug>[/<viewport>]/
//	  screenshot.png
//	  tree.json
//	  layout.json
//	  _meta.json
//
// (+ tree-<fw>.json when Phase 6 detector confidence ≥ 0.5)
//
// All paths flow through knowledge.WriteFileAtomic which enforces path-traversal
// rejection (T-08-01) and symlink-target rejection (T-08-02).
func (o *Orchestrator) captureState(ctx context.Context, s StateEvent) error {
	viewports := o.opts.Viewports
	if len(viewports) == 0 {
		viewports = []Viewport{{W: 0, H: 0, Scale: 1.0}} // sentinel: natural viewport
	}
	for _, vp := range viewports {
		if err := o.captureOne(ctx, s, vp); err != nil {
			o.opts.Logger.Error("capture state failed", "slug", s.Slug, "vp", fmt.Sprintf("%dx%d", vp.W, vp.H), "err", err)
		}
	}
	return nil
}

// captureOne writes a single (state, viewport) tuple. Errors per artifact are
// accumulated into _meta.errors so partial captures still produce metadata.
func (o *Orchestrator) captureOne(ctx context.Context, s StateEvent, vp Viewport) error {
	defer func() { _ = recover() }() // D-22

	// 1. Component classification (Phase 7).
	component := o.opts.Component
	if component == "" {
		bucket, _, _ := components.Classify(components.SourceFile{Path: s.Slug, Content: nil}, components.Options{})
		component = string(bucket)
		if component == "" {
			component = string(components.BucketUnknown)
		}
	}

	// 2. Compose state directory.
	stateDir := filepath.Join(o.opts.KBDir, "visual", o.opts.RunID, component, slugForViewport(s.Slug, vp))

	// 3. Detect framework — relies on caller injecting via Options for now;
	// passes through nil if no detector data available.
	fwInfos := o.opts.FrameworkInfo

	// 4. Capture artifacts.
	meta := &Meta{
		RunID:               o.opts.RunID,
		Component:           component,
		StateSlug:           s.Slug,
		Route:               s.Slug, // route slugs ARE state slugs in routing-only states
		Viewport:            vp,
		Framework:           "unknown",
		FrameworkConfidence: 0,
		FrameworkEvidence:   []string{},
		CapturedAt:          time.Now().UTC().Format(time.RFC3339),
		Mode:                string(o.opts.Mode),
	}

	// Screenshot via CDP (D-20: no OS capture for content-protected windows).
	if pngBytes, err := o.cli.CaptureScreenshot(ctx, cdp.ScreenshotOpts{Format: "png", FromSurface: true}); err == nil {
		// T-08-07: detect uniform-pixel content-protection silent failure
		// (PNG of a single colour ≈ ~250 bytes). The carry-forward from 08-01
		// emits a stderr WARNING when the captured PNG looks suspiciously small.
		if len(pngBytes) < 1024 {
			meta.ContentProtectionWarned = true
			fmt.Fprintln(stderr, "WARNING: target window has content-protection enabled (setContentProtection or equivalent); OS capture may produce a blank image. Use --cdp for guaranteed capture via DevTools.")
		}
		if err := knowledge.WriteFileAtomic(filepath.Join(stateDir, "screenshot.png"), pngBytes, 0o644); err != nil {
			meta.Errors = append(meta.Errors, "screenshot: "+err.Error())
		} else {
			meta.ImageSHA256 = sha256Hex(pngBytes)
		}
	} else {
		meta.Errors = append(meta.Errors, "screenshot: "+err.Error())
	}

	// JSON DOM tree.
	if root, err := o.cli.GetDocument(ctx, -1, true); err == nil && root != nil {
		tree := BuildJSONTree(root)
		if treeBytes, err := json.MarshalIndent(tree, "", "  "); err == nil {
			if err := knowledge.WriteFileAtomic(filepath.Join(stateDir, "tree.json"), treeBytes, 0o644); err != nil {
				meta.Errors = append(meta.Errors, "tree: "+err.Error())
			} else {
				meta.TreeSHA256 = sha256Hex(treeBytes)
			}
		}
	}

	// Framework-aware tree (D-05 dual output).
	if fwTree, fwName, err := ExtractFrameworkTree(ctx, o.cli, fwInfos); err == nil && fwTree != nil {
		if fwBytes, mErr := json.MarshalIndent(fwTree, "", "  "); mErr == nil {
			if wErr := knowledge.WriteFileAtomic(filepath.Join(stateDir, "tree-"+fwName+".json"), fwBytes, 0o644); wErr == nil {
				meta.FrameworkAwareTree = true
				meta.Framework = fwName
				if len(fwInfos) > 0 {
					meta.FrameworkConfidence = fwInfos[0].Confidence
					meta.FrameworkEvidence = fwInfos[0].Evidence
				}
			}
		}
	} else if fwName != "" {
		// detector hit but hook absent: record framework name without tree.
		meta.Framework = fwName
		if len(fwInfos) > 0 {
			meta.FrameworkConfidence = fwInfos[0].Confidence
			meta.FrameworkEvidence = fwInfos[0].Evidence
		}
	}

	// Layout snapshot.
	if layout, err := ExtractLayout(ctx, o.cli); err == nil && layout != nil {
		if layoutBytes, mErr := json.MarshalIndent(layout, "", "  "); mErr == nil {
			if wErr := knowledge.WriteFileAtomic(filepath.Join(stateDir, "layout.json"), layoutBytes, 0o644); wErr != nil {
				meta.Errors = append(meta.Errors, "layout: "+wErr.Error())
			} else {
				meta.LayoutSHA256 = sha256Hex(layoutBytes)
			}
		}
	} else if err != nil {
		meta.Errors = append(meta.Errors, "layout: "+err.Error())
	}

	// _meta.json.
	if err := writeMeta(stateDir, meta); err != nil {
		return fmt.Errorf("write meta: %w", err)
	}

	// Record into the run's CapturedState index for later manifest extension.
	o.recordCapture(component, s.Slug, vp, stateDir, meta.FrameworkAwareTree, meta.Framework)
	return nil
}

// slugForViewport produces the per-viewport state directory suffix. Empty
// suffix when only a single natural viewport is configured.
func slugForViewport(stateSlug string, vp Viewport) string {
	if vp.W == 0 && vp.H == 0 {
		return stateSlug
	}
	return fmt.Sprintf("%s-%dx%d", stateSlug, vp.W, vp.H)
}

// recordCapture appends one CapturedState to the orchestrator's running index.
func (o *Orchestrator) recordCapture(component, stateSlug string, vp Viewport, stateDir string, fwTree bool, fwName string) {
	rel := func(name string) string {
		// store relative-to-KB-root paths so manifest is portable.
		if r, err := filepath.Rel(o.opts.KBDir, filepath.Join(stateDir, name)); err == nil {
			return filepath.ToSlash(r)
		}
		return filepath.ToSlash(filepath.Join(stateDir, name))
	}
	cs := capture.CapturedState{
		RunID:          o.opts.RunID,
		Component:      component,
		StateSlug:      stateSlug,
		Viewport:       capture.ViewportSpec{W: vp.W, H: vp.H, Scale: vp.Scale},
		ScreenshotPath: rel("screenshot.png"),
		TreePath:       rel("tree.json"),
		LayoutPath:     rel("layout.json"),
		MetaPath:       rel("_meta.json"),
	}
	if fwTree {
		cs.FrameworkTreePath = rel("tree-" + fwName + ".json")
	}
	o.muCaptures.Lock()
	o.captures = append(o.captures, cs)
	o.muCaptures.Unlock()
}

// classifyForBucket exposes the components classifier for state-slug → bucket
// resolution from outside (kept narrow to avoid leaking implementation details).
func classifyForBucket(slug string) components.Bucket {
	b, _, _ := components.Classify(components.SourceFile{Path: slug}, components.Options{})
	return b
}

// frameworkInfoFromOpts is a stub helper to satisfy a future wiring (kept so
// the static type matches the orchestrator field).
var _ = framework.Detect
