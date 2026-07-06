// Package topic deterministically derives a coarse content topic for an
// enriched module from its existing enrichment signals. Pure: no DB, no AI,
// no embeddings, no ML. Same inputs → same topic.
package topic

import (
	"sort"
	"strings"
)

// keywordTopics maps a lowercase token to a topic. Checked (sorted, first
// match wins for determinism) against the combined tags+summary+deps text
// before falling back to the normalized role.
var keywordTopics = map[string]string{
	"sendmessage": "messaging", "message": "messaging", "chat": "messaging",
	"send": "messaging", "receive": "messaging", "msg": "messaging",
	"encrypt": "crypto", "decrypt": "crypto", "crypto": "crypto",
	"cipher": "crypto", "key": "crypto", "signal": "crypto",
	"media": "media", "video": "media", "audio": "media",
	"image": "media", "thumbnail": "media", "stream": "media",
	"presence": "presence", "typing": "presence", "online": "presence",
	"telemetry": "telemetry", "metric": "telemetry", "analytics": "telemetry",
	"log": "telemetry", "logger": "telemetry", "tracking": "telemetry",
	"storage": "storage", "cache": "storage", "indexeddb": "storage",
	"db": "storage", "persist": "storage", "blob": "storage",
	"auth": "auth", "login": "auth", "token": "auth",
	"session": "auth", "credential": "auth", "oauth": "auth",
	"react": "ui", "render": "ui", "component": "ui",
	"view": "ui", "dom": "ui", "window": "ui",
	"voip": "call", "ring": "call",
}

// roleTopics normalizes a known enrichment role to a topic.
var roleTopics = map[string]string{
	"send": "messaging", "receive": "messaging", "auth": "auth",
	"pair": "auth", "storage": "storage", "sync": "storage",
	"protocol": "messaging", "crypto": "crypto", "media": "media",
	"presence": "presence", "call": "call", "ui": "ui",
	"telemetry": "telemetry", "util": "other", "other": "other",
}

// Derive returns a stable coarse topic. Priority: a keyword hit in
// tags+summary+deps (deterministic: keys sorted, first match) → normalized
// role → "other".
func Derive(role, tags, summary, depsJSON string) string {
	hay := strings.ToLower(tags + " " + summary + " " + depsJSON)
	keys := make([]string, 0, len(keywordTopics))
	for k := range keywordTopics {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.Contains(hay, k) {
			return keywordTopics[k]
		}
	}
	if t, ok := roleTopics[strings.ToLower(strings.TrimSpace(role))]; ok && t != "other" {
		return t
	}
	return "other"
}
