/*
Copyright (c) 2026 Security Research
*/
package visual

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/inovacc/unravel-oss/pkg/capture"
	"github.com/inovacc/unravel-oss/pkg/capture/cdp"
	"github.com/inovacc/unravel-oss/pkg/jsdeob/framework"
)

// stderr is the shim used by per-state warning messages (T-08-07). Tests
// override via SetStderr to capture warning output.
var stderr io.Writer = os.Stderr

// SetStderr swaps the warning sink. Test-only.
func SetStderr(w io.Writer) { stderr = w }

// Mode selects the visual-capture strategy.
type Mode string

const (
	ModeAuto        Mode = "auto"
	ModeInteractive Mode = "interactive"
	ModeScripted    Mode = "scripted"
)

// Viewport describes a logical capture viewport (CSS pixels + DPR).
type Viewport struct {
	W, H  int
	Scale float64
}

// Options configures Orchestrator behaviour.
type Options struct {
	Mode           Mode
	KBDir          string
	RunID          string
	Component      string // optional override; default auto-classified by Phase 7 components classifier
	Viewports      []Viewport
	MaxStates      int // default 50
	ScenarioPath   string
	ModalSettleMs  int // default 300
	PHashThreshold int // default 5
	Logger         *slog.Logger
	// FrameworkInfo carries the Phase 6 detector output for tree-extractor
	// dispatch (D-05). Empty slice → tree.json only (D-06 fallback).
	FrameworkInfo []framework.FrameworkInfo
	// ContentProtected is an optional probe; when it returns true, the per-state
	// _meta.content_protection_warned flag is set and a stderr warning is emitted
	// before the first capture (T-08-07).
	ContentProtected func() bool
}

// Orchestrator drives the per-mode capture loop. Bodies for runEventDriven /
// runScripted are Wave-1 stubs — 08-02 fills them with the actual capture
// passes (state detector, tree extractor dispatch, layout extractor).
type Orchestrator struct {
	cli        *cdp.Client
	opts       Options
	muCaptures sync.Mutex
	captures   []capture.CapturedState
}

// Captures returns the captured-state index built up over the run. Read after
// Run() returns; the manifest extension is built from this slice.
func (o *Orchestrator) Captures() []capture.CapturedState {
	o.muCaptures.Lock()
	defer o.muCaptures.Unlock()
	out := make([]capture.CapturedState, len(o.captures))
	copy(out, o.captures)
	return out
}

// New constructs an Orchestrator and validates required options.
func New(cli *cdp.Client, opts Options) (*Orchestrator, error) {
	if cli == nil {
		return nil, fmt.Errorf("nil cdp client")
	}
	if opts.Mode == "" {
		opts.Mode = ModeAuto
	}
	if opts.MaxStates <= 0 {
		opts.MaxStates = 50
	}
	if opts.ModalSettleMs <= 0 {
		opts.ModalSettleMs = 300
	}
	if opts.PHashThreshold <= 0 {
		opts.PHashThreshold = 5
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Orchestrator{cli: cli, opts: opts}, nil
}

// Run executes the configured mode until ctx is done or MaxStates is reached.
// Defer/recover boundary per D-22 — a malformed CDP event MUST NOT panic the
// orchestrator. 08-02 fills the per-mode bodies; this skeleton wires the
// outer loop and panic guard only.
func (o *Orchestrator) Run(ctx context.Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("orchestrator panic: %v", r)
		}
	}()
	switch o.opts.Mode {
	case ModeAuto, ModeInteractive:
		return o.runEventDriven(ctx)
	case ModeScripted:
		return o.runScripted(ctx)
	default:
		return fmt.Errorf("unknown mode: %q", o.opts.Mode)
	}
}

// runEventDriven wires Page.frameNavigated + the injected MutationObserver,
// captures the initial root state, then drains state events until ctx is done
// or MaxStates is reached. Captured count includes the initial root.
func (o *Orchestrator) runEventDriven(ctx context.Context) error {
	if o.opts.ContentProtected != nil && o.opts.ContentProtected() {
		fmt.Fprintln(stderr, "WARNING: target window has content-protection enabled (setContentProtection or equivalent); OS capture may produce a blank image. Use --cdp for guaranteed capture via DevTools.")
	}
	stateCh := make(chan StateEvent, 16)
	if err := RegisterStateDetectors(ctx, o.cli, func(s StateEvent) {
		select {
		case stateCh <- s:
		default:
		}
	}); err != nil {
		return fmt.Errorf("register state detectors: %w", err)
	}
	if err := o.captureState(ctx, StateEvent{Type: "route", Slug: "root"}); err != nil {
		o.opts.Logger.Error("initial capture failed", "err", err)
	}
	captured := 1
	for captured < o.opts.MaxStates {
		select {
		case <-ctx.Done():
			return nil
		case s := <-stateCh:
			if s.Type == "modal_close" {
				continue // pop, no capture
			}
			if s.Type == "modal_open" {
				time.Sleep(time.Duration(o.opts.ModalSettleMs) * time.Millisecond)
			}
			if err := o.captureState(ctx, s); err != nil {
				o.opts.Logger.Error("capture state failed", "slug", s.Slug, "err", err)
			}
			captured++
		}
	}
	o.opts.Logger.Warn("max-states reached", "limit", o.opts.MaxStates)
	return nil
}

// runScripted reads the scripted scenario file and walks the closed step set
// {click, type, wait, capture}. Unknown action verbs are rejected (T-08-03).
func (o *Orchestrator) runScripted(ctx context.Context) error {
	if o.opts.ScenarioPath == "" {
		return fmt.Errorf("scripted mode requires ScenarioPath")
	}
	steps, err := loadScenario(o.opts.ScenarioPath)
	if err != nil {
		return err
	}
	captured := 0
	for i, step := range steps {
		if captured >= o.opts.MaxStates {
			o.opts.Logger.Warn("max-states reached", "limit", o.opts.MaxStates)
			break
		}
		if err := o.runScriptedStep(ctx, step); err != nil {
			return fmt.Errorf("step %d (%s): %w", i, step.Action, err)
		}
		if step.Action == "capture" {
			captured++
		}
	}
	return nil
}
