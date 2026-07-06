// Package timeutil provides shared timestamp helpers in the canonical formats
// used by unravel's JSON outputs, capture pipelines, and database writes.
package timeutil

import "time"

// NowUTC returns the current time as an RFC3339 UTC string. Common for human-
// readable timestamps in dissect reports, capture metadata, and forensic
// output.
func NowUTC() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// NowUTCNano returns the current time as an RFC3339Nano UTC string. Use when
// sub-second precision matters (capture event ordering, run dirs).
func NowUTCNano() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

// NowUnixMilli returns the current time as Unix epoch milliseconds. Matches
// the BIGINT ms-epoch convention used by knowledge_sources, kb_aliases, and
// app_facts tables in the kb catalog.
func NowUnixMilli() int64 {
	return time.Now().UnixMilli()
}

// FormatUTC formats t as RFC3339 in UTC. Convenience for non-Now() values.
func FormatUTC(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// FormatUnixMilli formats a Unix-ms timestamp as RFC3339 UTC. Inverse of
// NowUnixMilli for display.
func FormatUnixMilli(ms int64) string {
	return time.UnixMilli(ms).UTC().Format(time.RFC3339)
}
