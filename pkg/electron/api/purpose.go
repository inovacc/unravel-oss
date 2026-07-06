/*
Copyright (c) 2026 Security Research
*/
package api

import "strings"

// Purpose buckets a URL into a coarse semantic category.
type Purpose string

const (
	PurposeAuth      Purpose = "auth"
	PurposeTelemetry Purpose = "telemetry"
	PurposeCDN       Purpose = "cdn"
	PurposeAPI       Purpose = "api"
	PurposeUpdate    Purpose = "update"
	PurposeWebsocket Purpose = "websocket"
	PurposeDocs      Purpose = "docs"
	PurposeUnknown   Purpose = "unknown"
)

// classifyPurpose maps (scheme, host, path) to a Purpose bucket. The "docs"
// bucket catches comment-style URL refs that survived denylist (e.g. random
// blog hosts) so they count as classified even though not real endpoints.
func classifyPurpose(scheme, host, path string) Purpose {
	h := strings.ToLower(host)
	p := strings.ToLower(path)
	switch {
	case scheme == "wss" || strings.HasPrefix(p, "/ws") || strings.Contains(h, "websocket") ||
		strings.HasPrefix(h, "gateway.") || strings.HasPrefix(h, "ws."):
		return PurposeWebsocket
	case strings.Contains(h, "auth") || strings.Contains(h, "login") ||
		strings.Contains(h, "oauth") || strings.Contains(h, "sso") ||
		strings.HasPrefix(p, "/oauth") || strings.HasPrefix(p, "/auth") ||
		strings.HasPrefix(p, "/login"):
		return PurposeAuth
	case strings.Contains(h, "telemetry") || strings.Contains(h, "analytics") ||
		strings.Contains(h, "metrics") || strings.Contains(h, "sentry") ||
		strings.Contains(h, "datadog") || strings.Contains(h, "segment.io") ||
		strings.Contains(h, "mixpanel") || strings.Contains(h, "amplitude") ||
		strings.Contains(h, "bugsnag") || strings.Contains(h, "rollbar"):
		return PurposeTelemetry
	case strings.Contains(h, "cdn") || strings.Contains(h, "akamai") ||
		strings.Contains(h, "fastly") || strings.Contains(h, "cloudfront") ||
		strings.Contains(h, "cloudflare") || strings.HasPrefix(h, "static.") ||
		strings.HasPrefix(h, "assets."):
		return PurposeCDN
	case strings.Contains(h, "update") || strings.Contains(p, "release") ||
		strings.Contains(p, "/version") || strings.Contains(h, "releases."):
		return PurposeUpdate
	case strings.HasPrefix(p, "/api") || strings.HasPrefix(p, "/v1") ||
		strings.HasPrefix(p, "/v2") || strings.HasPrefix(p, "/v3") ||
		strings.Contains(h, "api."):
		return PurposeAPI
	case strings.HasPrefix(h, "docs.") || strings.HasPrefix(h, "doc.") ||
		strings.HasPrefix(h, "developer.") || strings.HasPrefix(h, "developers.") ||
		strings.HasPrefix(h, "help.") || strings.HasPrefix(h, "support.") ||
		strings.HasPrefix(h, "blog.") || strings.HasPrefix(h, "wiki.") ||
		strings.HasPrefix(h, "learn.") || strings.HasPrefix(h, "kb."):
		return PurposeDocs
	}
	return PurposeUnknown
}
