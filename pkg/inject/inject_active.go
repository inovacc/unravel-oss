/*
Copyright (c) 2026 Security Research
*/
package inject

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// ASARRepatcher is the function signature 46-01's pkg/inject/asar package
// registers via RegisterASARRepatcher. Wave-1 ordering note: 46-01 lands
// the implementation; this hook decouples the import so 46-02 can compile
// independently and 46-01's init() wires the real repatcher at startup.
//
// asarPath is the source app.asar; script is the preload bytes; scriptName
// is a human-readable label for the audit log. Returns the sibling
// .injected.asar output path on success.
type ASARRepatcher func(ctx context.Context, asarPath string, script []byte, scriptName string) (outputPath string, err error)

// CDPInjector is the function signature pkg/inject/electron registers via
// RegisterCDPInjector. Decoupled from this file to keep the package free of
// websocket transport dependencies in tests that don't exercise CDP.
type CDPInjector func(ctx context.Context, port int, script []byte, opts CDPInjectOpts) (CDPInjectResult, error)

// CDPInjectOpts controls a single CDP attach call.
type CDPInjectOpts struct {
	Persistent bool
	World      string
}

// CDPInjectResult is the per-attach outcome surfaced back to Inject.
type CDPInjectResult struct {
	TargetURL string
}

// TauriDetector is an optional hook that reports whether a target is a
// Tauri bundle. When nil, Inject falls back to a conservative file-pattern
// peek. Plan 46-02 ships only the fallback; 46-03 may register a richer
// detector via the framework registry.
type TauriDetector func(target string) bool

var (
	asarRepatcher ASARRepatcher
	cdpInjector   CDPInjector
	tauriDetector TauriDetector
)

// RegisterASARRepatcher is called from pkg/inject/asar/init() (Plan 46-01).
func RegisterASARRepatcher(fn ASARRepatcher) { asarRepatcher = fn }

// RegisterCDPInjector is called from pkg/inject/electron/init() (Plan 46-02).
func RegisterCDPInjector(fn CDPInjector) { cdpInjector = fn }

// RegisterTauriDetector lets a future plan supply a richer detector.
func RegisterTauriDetector(fn TauriDetector) { tauriDetector = fn }

// Inject is the top-level active-injection dispatcher.
//
// It refuses to run unless opts.Confirmed == true (defense-in-depth: the
// CLI/MCP layer also gates, but the library refuses unconditionally).
//
// Dispatch:
//   - target detected as Tauri        → ErrTauriUnsupported
//   - opts.Method == MethodCDP        → cdpInjector hook (pkg/inject/electron)
//   - opts.Method == MethodASAR       → asarRepatcher hook (Plan 46-01)
//   - any other / empty Method        → ErrInjectMethodUnknown
//
// On success, Append is called with the resolved AuditRecord before the
// result is returned. A failed Append is *not* swallowed — it surfaces as
// the error from Inject so a caller cannot silently lose forensic state.
func Inject(ctx context.Context, target string, opts InjectOpts) (InjectResult, error) {
	if !opts.Confirmed {
		return InjectResult{}, ErrConsentRequired
	}

	if isTauriTarget(target) {
		return InjectResult{}, ErrTauriUnsupported
	}

	hash := scriptSHA256(opts.Script)
	startedAt := time.Now().UTC()

	res := InjectResult{
		Method:     opts.Method,
		ScriptHash: hash,
		TargetPath: target,
		StartedAt:  startedAt,
		Persistent: opts.Persistent,
	}

	switch opts.Method {
	case MethodCDP:
		if cdpInjector == nil {
			return InjectResult{}, ErrInjectMethodUnknown
		}
		_, err := cdpInjector(ctx, opts.CDPPort, opts.Script, CDPInjectOpts{
			Persistent: opts.Persistent,
			World:      opts.World,
		})
		if err != nil {
			return InjectResult{}, err
		}
	case MethodASAR:
		if asarRepatcher == nil {
			return InjectResult{}, ErrInjectMethodUnknown
		}
		out, err := asarRepatcher(ctx, opts.ASARPath, opts.Script, opts.ScriptName)
		if err != nil {
			return InjectResult{}, err
		}
		res.OutputPath = out
	default:
		return InjectResult{}, ErrInjectMethodUnknown
	}

	res.FinishedAt = time.Now().UTC()

	if err := Append(AuditRecord{
		Timestamp:    res.FinishedAt,
		TargetPath:   target,
		Method:       string(opts.Method),
		ScriptName:   opts.ScriptName,
		ScriptSHA256: hash,
		Persistent:   opts.Persistent,
		OutputPath:   res.OutputPath,
	}); err != nil {
		return InjectResult{}, err
	}

	return res, nil
}

// scriptSHA256 returns the hex-encoded SHA-256 of the script bytes.
func scriptSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// isTauriTarget returns true if the registered TauriDetector says yes, or
// (when no detector is registered) if a conservative path-pattern peek
// matches a Tauri bundle marker. Plan 46-02 only ships the conservative
// fallback so the dispatcher can refuse Tauri targets even before 46-03
// wires a richer detector.
func isTauriTarget(target string) bool {
	if tauriDetector != nil {
		return tauriDetector(target)
	}
	return false
}
