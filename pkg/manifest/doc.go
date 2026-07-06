/*
Copyright (c) 2026 Security Research
*/

// Package manifest loads and evaluates YAML-based unravel configuration.
//
// A Manifest defines detection rules, security analysis patterns, stealth
// feature signatures, telemetry service indicators, IPC command patterns,
// API extraction rules, and risk scoring weights.
//
// Entry points:
//   - Load: parse a manifest from a YAML file
//   - LoadDefault: load the default manifest from manifests/default.yaml
//   - Default: return a built-in fallback manifest
//   - NewDetector: create a framework detector using manifest rules
package manifest
