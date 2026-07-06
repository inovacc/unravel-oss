/*
Copyright (c) 2026 Security Research
*/

// Package electron implements active-injection backends for Electron apps.
// Plan 46-02 ships the CDP attach path; Plan 46-01 ships the ASAR repatch
// path in pkg/inject/asar.
package electron

import (
	"context"
	"errors"
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/inject"

	"github.com/inovacc/unravel-oss/pkg/capture/cdp"
)

// AttachOpts controls one CDP attach call.
type AttachOpts struct {
	// Persistent uses Page.addScriptToEvaluateOnNewDocument so the script
	// re-runs on every navigation. Non-persistent runs Runtime.evaluate
	// once against the currently attached target.
	Persistent bool

	// World controls the JS world the script runs in. "isolated" maps to
	// addScriptToEvaluateOnNewDocument's worldName parameter; "main" (or
	// any other value) leaves it unset so the script runs in the page's
	// main world.
	World string
}

// CDPInjectResult mirrors inject.CDPInjectResult so callers can take this
// package's return type without importing the parent.
type CDPInjectResult = inject.CDPInjectResult

// ErrNoTarget is returned when DiscoverTargets returns an empty list.
var ErrNoTarget = errors.New("electron cdp: no debuggable targets on port (is --remote-debugging-port set?)")

// AttachAndInject dials a running Electron app's DevTools Protocol on
// 127.0.0.1:port, picks the first 'page' target, enables Page domain, and
// either persistent-installs or one-shot-evaluates the supplied script.
//
// The function always closes the websocket cleanly before returning.
//
// On Persistent + World=="isolated" the script is registered with a
// worldName so it cannot reach the page's main-world JS state.
func AttachAndInject(ctx context.Context, port int, script []byte, opts AttachOpts) (CDPInjectResult, error) {
	host := fmt.Sprintf("127.0.0.1:%d", port)
	c := cdp.New(host, nil, nil)

	targets, err := c.DiscoverTargets(ctx)
	if err != nil {
		return CDPInjectResult{}, err
	}
	var picked cdp.Target
	for _, t := range targets {
		if t.Type == "page" && t.WebSocketDebugURL != "" {
			picked = t
			break
		}
	}
	if picked.WebSocketDebugURL == "" {
		return CDPInjectResult{}, ErrNoTarget
	}

	if err := c.Connect(ctx, picked.WebSocketDebugURL); err != nil {
		return CDPInjectResult{}, err
	}
	defer func() { _ = c.Close() }()

	listenCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = c.Listen(listenCtx) }()

	if _, err := c.SendAndWait(ctx, "Page.enable", nil); err != nil {
		return CDPInjectResult{}, err
	}

	src := string(script)
	if opts.Persistent {
		params := map[string]any{"source": src}
		if opts.World == "isolated" {
			params["worldName"] = "UnravelInjectedWorld"
		}
		if _, err := c.SendAndWait(ctx, "Page.addScriptToEvaluateOnNewDocument", params); err != nil {
			return CDPInjectResult{}, err
		}
	} else {
		params := map[string]any{
			"expression":    src,
			"returnByValue": true,
		}
		if _, err := c.SendAndWait(ctx, "Runtime.evaluate", params); err != nil {
			return CDPInjectResult{}, err
		}
	}

	return CDPInjectResult{TargetURL: picked.URL}, nil
}

// init wires AttachAndInject into the parent package's CDP injector hook.
// This is the only side-effecting init in pkg/inject/electron/cdp_attach.go.
func init() {
	inject.RegisterCDPInjector(func(ctx context.Context, port int, script []byte, opts inject.CDPInjectOpts) (inject.CDPInjectResult, error) {
		return AttachAndInject(ctx, port, script, AttachOpts{
			Persistent: opts.Persistent,
			World:      opts.World,
		})
	})
}
