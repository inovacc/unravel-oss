/*
Copyright (c) 2026 Security Research
*/

package webview2

import "fmt"

// allowedOrigin is the single, portable source of truth for the CDP
// --remote-allow-origins allowlist. It scopes the DevTools surface to the
// exact loopback origin so a DNS-rebinding / any-origin web page cannot
// drive the debug port (T-83-04-03). It MUST be used by every code path
// that builds WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS — the MethodDirect
// process-env path (ensure.go) AND the MethodAUMID HKCU path
// (host_windows.go) — so the two cannot silently diverge (review IN-01).
// The wildcard form (--remote-allow-origins=*) is never written.
func allowedOrigin(port int) string {
	return fmt.Sprintf("http://127.0.0.1:%d", port)
}

// browserArgs is the full WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS value:
// the loopback-bound remote debugging port plus the scoped origin
// allowlist. Single source of truth for both launch methods.
func browserArgs(port int) string {
	return fmt.Sprintf("--remote-debugging-port=%d --remote-allow-origins=%s", port, allowedOrigin(port))
}
