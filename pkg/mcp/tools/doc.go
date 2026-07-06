/*
Copyright (c) 2026 Security Research
*/

// Package mcptools provides MCP (Model Context Protocol) tool handlers for the
// unravel security analysis toolkit.
//
// It registers 24 tools with an MCP server, each calling the corresponding
// pkg/ function directly (no shell-out). Tools are organized by group:
// analyze, asar, cache, cert, extension, garble, ipc, jsdeob, leveldb, and license.
//
// Entry points:
//   - NewServer: create an MCP server with all tools registered
//
// The server communicates over stdio using newline-delimited JSON.
// Run it with: go run ./cmd/mcp
package mcptools
