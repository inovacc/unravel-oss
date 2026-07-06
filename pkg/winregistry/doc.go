/*
Copyright (c) 2026 Security Research

Package winregistry walks Windows registry hives and emits structured
JSON/NDJSON dumps plus a .reg replay file. Pure-Go on Windows via
golang.org/x/sys/windows/registry; the non-Windows build returns a
"not supported on $GOOS" error so the surface stays uniform across hosts.

Phase 20.3.
*/
package winregistry
