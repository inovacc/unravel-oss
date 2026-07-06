/*
Copyright (c) 2026 Security Research
*/

// Package aihost defines unravel's cross-host plugin packaging contract.
//
// Each concrete AI host (Claude Code, OpenAI Codex CLI, Gemini CLI) lives in a
// subpackage and satisfies the Host interface (Name + InstallTarget +
// TreeWriter). Optional capabilities — Installer, Status, Doctor — are picked
// up via type assertion so hosts ship lazily: the Claude host has the full
// surface; Codex and Gemini ship minimally and grow.
//
// Assets (commands, agents, skills) are Go raw-string literals registered via
// RegisterAsset in pkg/aihost/assets/<domain>/*.go and barreled through
// pkg/aihost/assets/all. There is NO embed.FS and NO anthropic-sdk-go import in
// this package (the D-09 MCP-only-AI invariant — see MAINTAINERS.md).
//
// The CLI dispatcher in cmd/plugin_install.go picks a host from --host, or fans
// out across aihost.All() when --host=all. lensr's pkg/aihost was ported FROM
// this package (2026-05-24); this alignment brings its later maturity back.
package aihost
