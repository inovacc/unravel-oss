/*
Copyright (c) 2026 Security Research
*/

// Package tauri carries the Tauri-side active-injection stub. Phase 46
// known gap: Tauri does not expose a remote-debug endpoint comparable to
// Electron's CDP, and its bundled WebView is not patchable like an asar
// archive. See ROADMAP backlog (Phase 46-02) for the deferred design.
package tauri

import (
	"context"

	"github.com/inovacc/unravel-oss/pkg/inject"
)

// InjectActive always returns inject.ErrTauriUnsupported. It exists so that
// callers can dispatch by framework symmetrically (electron + tauri) and so
// future plans can swap the body in without changing call sites.
//
// Phase 46 known gap: Tauri active injection deferred — see ROADMAP backlog.
func InjectActive(_ context.Context, _ string, _ inject.InjectOpts) (inject.InjectResult, error) {
	return inject.InjectResult{}, inject.ErrTauriUnsupported
}
