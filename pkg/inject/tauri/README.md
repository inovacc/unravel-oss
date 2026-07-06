# pkg/inject/tauri — Tauri active-injection stub

**Phase 46 known gap:** Tauri active injection is deferred.

`InjectActive` returns `inject.ErrTauriUnsupported` unconditionally.

## Why deferred

- Tauri does not expose a remote-debug endpoint comparable to Electron's
  Chrome DevTools Protocol. There is nothing analogous to CDP attach.
- The bundled WebView (WebView2 on Windows, WKWebView on macOS, WebKitGTK
  on Linux) is not packaged as an asar-style archive, so the 46-01 repatch
  pattern does not apply.
- Tauri's IPC ACL surface is config-driven and signed; the design for a
  consent-gated, audit-logged equivalent has not been spec'd.

## Path forward

Tracked in the Phase 46 backlog. A future plan will scope:
1. Whether Tauri supports a vetted dev-mode hook.
2. WebView-host-specific injection (WebView2 UDF, WKWebView Web Inspector).
3. Whether to ship a static "config-rewrite" mode analogous to ASAR.

Until then, callers that hit a Tauri target receive
`inject.ErrTauriUnsupported` and can route the user to passive `Scan`
output instead.
