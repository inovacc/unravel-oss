/*
Copyright (c) 2026 Security Research
*/

// Package ipc discovers and fuzzes IPC commands in Electron and Tauri applications.
//
// It performs static analysis on binaries to extract IPC command names, then
// generates and sends fuzz payloads to test for input validation issues.
//
// Entry points:
//   - DiscoverCommands: extract IPC commands from a binary via static analysis
//   - FuzzCommands: fuzz IPC endpoints with generated payloads
//   - GeneratePayload: create a fuzz payload for a given iteration
package ipc
