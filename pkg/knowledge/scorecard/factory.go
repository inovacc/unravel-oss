/*
Copyright (c) 2026 Security Research
*/

// Package scorecard — frame-source factory wiring (P63).
//
// The frameSource interface (dispatch.go:32) is intentionally unexported to
// keep the test seam from leaking into the public API. Production code that
// needs to override the default noopFrameSource (e.g. cmd/knowledge.go when
// --cdp-port is set) calls InstallProductionCDPFactory(host) here, which
// internally swaps defaultFrameSourceFactory for one returning cdpFrameSource.
//
// Test code that needs a custom frameSource (e.g. fake-CDP server in
// cdp_source_test.go) uses SetFrameSourceFactory(factory) directly with a
// closure returning a private frameSource implementation defined inside the
// scorecard package (closures over package-private types stay package-private).
//
// Doc contract: SetFrameSourceFactory is a TEST-ONLY override. Production
// code must use InstallProductionCDPFactory which keeps the orchestration
// (host derivation, etc.) inside this package.
package scorecard

import "fmt"

// ProductionFrameSourceConfig is the per-call config the production factory
// receives. Today it carries the CDP host string (e.g. "127.0.0.1:9222") and
// (P64-05) the per-target KBOutputDir for frames.ndjson sidecar emission.
type ProductionFrameSourceConfig struct {
	// Host is the CDP HTTP host:port. Empty means "derive from
	// DissectTarget.CDPPort".
	Host string
	// KBDir is the per-target KBOutputDir used for frames.ndjson
	// sidecar emission (P64-05). Empty disables sidecar emission.
	KBDir string
}

// SetFrameSourceFactory overrides the default frame-source factory used by
// Rubric.Iterate. The supplied factory is invoked once per Iterate call with
// a per-call config derived from the DissectTarget.
//
// TEST-ONLY contract — the closure body must construct a frameSource that
// stays within this package (frameSource is unexported). Production code must
// use InstallProductionCDPFactory instead, which closes over the production
// cdpFrameSource constructor.
//
// Passing nil is a no-op (preserves the existing factory).
func SetFrameSourceFactory(factory func(cfg ProductionFrameSourceConfig) frameSource) {
	if factory == nil {
		return
	}
	defaultFrameSourceFactory = func(t *DissectTarget) frameSource {
		host := ""
		kbDir := ""
		if t != nil {
			if t.CDPPort != 0 {
				host = fmt.Sprintf("127.0.0.1:%d", t.CDPPort)
			}
			kbDir = t.KBOutputDir
		}
		return factory(ProductionFrameSourceConfig{Host: host, KBDir: kbDir})
	}
}

// InstallProductionCDPFactory wires the production cdpFrameSource into
// defaultFrameSourceFactory so any subsequent Rubric.Iterate call captures
// real CDP frames against host (typically "127.0.0.1:<port>").
//
// If host is empty, the factory derives the host per-call from
// DissectTarget.CDPPort. Calling with both empty host AND CDPPort=0 results
// in cdpFrameSource.Capture returning a "host empty and port=0" error — a
// graceful degraded mode equivalent to noopFrameSource.
//
// This is the production counterpart to SetFrameSourceFactory. Calling it
// from cmd/knowledge.go (where --cdp-port is read) is the documented closure
// of the P57 deferred-wiring gap.
func InstallProductionCDPFactory(host string) {
	SetFrameSourceFactory(func(cfg ProductionFrameSourceConfig) frameSource {
		h := host
		if h == "" {
			h = cfg.Host
		}
		return newCDPFrameSourceForTarget(h, cfg.KBDir)
	})
}

// ResetFrameSourceFactoryToNoop restores the original P57 default
// (noopFrameSource). Test-only — used by cdp_source_test.go to undo factory
// installs between tests so suite ordering is deterministic.
func ResetFrameSourceFactoryToNoop() {
	defaultFrameSourceFactory = func(target *DissectTarget) frameSource {
		return noopFrameSource{}
	}
}
