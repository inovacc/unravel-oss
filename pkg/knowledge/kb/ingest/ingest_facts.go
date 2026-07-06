/*
Copyright (c) 2026 Security Research

knowledge.json → app_facts extractor for the v2.5 ingest writer.

ExtractFacts walks a parsed knowledge.json (loaded by the caller) and
emits one FactRow per detected fact across the canonical category set:
framework, dep, capability, url, cert, risk, auth.

All type assertions use the safe `, ok` form so malformed
knowledge.json never panics (T-30-03-08).

License: BSD-3-Clause.
*/

package ingest

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// FactRow is a single row destined for app_facts.
type FactRow struct {
	App      string `json:"app"`
	Category string `json:"category"`
	Key      string `json:"key"`
	Value    string `json:"value"`
}

// ExtractFacts walks knowledgeJSON and produces FactRow entries for
// app_facts. Categories emitted (lowercase, matching D-30-DIFF-IDENTIFIER):
//
//   - "framework"  one row when knowledge.json.framework non-empty
//   - "dep"        one row per dependency
//   - "capability" one row per UWP/Android capability
//   - "url"        one row per detected endpoint
//   - "cert"       one row per signing certificate
//   - "risk"       one row when CanonicalizeRisk yields a score
//   - "auth"       one row per detected auth provider/scheme
//
// Output is deterministically ordered for diff stability.
func ExtractFacts(knowledgeJSON map[string]any, app string) []FactRow {
	if knowledgeJSON == nil || app == "" {
		return nil
	}
	var out []FactRow

	// framework
	if fw, ok := knowledgeJSON["framework"].(string); ok && fw != "" {
		out = append(out, FactRow{App: app, Category: "framework", Key: "name", Value: fw})
	}

	// dep — knowledge.json.dependencies as []any of objects
	out = append(out, extractDeps(knowledgeJSON, app)...)

	// capability — uwp_analyze.capabilities or android.permissions
	out = append(out, extractCapabilities(knowledgeJSON, app)...)

	// url — endpoints / urls / network.endpoints
	out = append(out, extractURLs(knowledgeJSON, app)...)

	// cert — signing certificates
	out = append(out, extractCerts(knowledgeJSON, app)...)

	// risk — populated only when CanonicalizeRisk emitted a score
	if score, level := CanonicalizeRisk(knowledgeJSON); score != nil {
		out = append(out, FactRow{
			App:      app,
			Category: "risk",
			Key:      "risk-score",
			Value:    fmt.Sprintf("%d:%s", *score, level),
		})
	}

	// auth — auth.providers / auth.schemes / security.auth
	out = append(out, extractAuth(knowledgeJSON, app)...)

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func extractDeps(m map[string]any, app string) []FactRow {
	deps, ok := m["dependencies"].([]any)
	if !ok {
		return nil
	}
	var rows []FactRow
	for _, d := range deps {
		switch v := d.(type) {
		case string:
			if v != "" {
				rows = append(rows, FactRow{App: app, Category: "dep", Key: v, Value: v})
			}
		case map[string]any:
			name, _ := v["name"].(string)
			if name == "" {
				continue
			}
			val := name
			if ver, ok := v["version"].(string); ok && ver != "" {
				val = name + "@" + ver
			} else if b, err := json.Marshal(v); err == nil {
				val = string(b)
			}
			rows = append(rows, FactRow{App: app, Category: "dep", Key: name, Value: val})
		}
	}
	return rows
}

func extractCapabilities(m map[string]any, app string) []FactRow {
	var rows []FactRow

	// UWP — uwp_analyze.capabilities = []map{"namespace","name","severity"}
	if uwp, ok := m["uwp_analyze"].(map[string]any); ok {
		if caps, ok := uwp["capabilities"].([]any); ok {
			for _, c := range caps {
				if cm, ok := c.(map[string]any); ok {
					ns, _ := cm["namespace"].(string)
					name, _ := cm["name"].(string)
					if name == "" {
						continue
					}
					key := name
					if ns != "" {
						key = ns + ":" + name
					}
					b, _ := json.Marshal(cm)
					rows = append(rows, FactRow{App: app, Category: "capability", Key: key, Value: string(b)})
				} else if s, ok := c.(string); ok && s != "" {
					rows = append(rows, FactRow{App: app, Category: "capability", Key: s, Value: s})
				}
			}
		}
	}

	// Android — android_manifest.permissions = []string
	if am, ok := m["android_manifest"].(map[string]any); ok {
		if perms, ok := am["permissions"].([]any); ok {
			for _, p := range perms {
				if s, ok := p.(string); ok && s != "" {
					rows = append(rows, FactRow{App: app, Category: "capability", Key: s, Value: s})
				}
			}
		}
	}
	return rows
}

func extractURLs(m map[string]any, app string) []FactRow {
	var urls []string

	// Direct top-level urls / endpoints arrays
	for _, k := range []string{"urls", "endpoints"} {
		if arr, ok := m[k].([]any); ok {
			for _, u := range arr {
				if s, ok := u.(string); ok && s != "" {
					urls = append(urls, s)
				}
			}
		}
	}

	// Nested network.endpoints
	if net, ok := m["network"].(map[string]any); ok {
		if arr, ok := net["endpoints"].([]any); ok {
			for _, u := range arr {
				if s, ok := u.(string); ok && s != "" {
					urls = append(urls, s)
				}
			}
		}
	}

	var rows []FactRow
	for _, u := range urls {
		host := u
		if i := strings.Index(u, "://"); i > 0 {
			rest := u[i+3:]
			if j := strings.IndexAny(rest, "/?#"); j > 0 {
				host = rest[:j]
			} else {
				host = rest
			}
		}
		rows = append(rows, FactRow{App: app, Category: "url", Key: host, Value: u})
	}
	return rows
}

func extractCerts(m map[string]any, app string) []FactRow {
	certs, ok := m["certificates"].([]any)
	if !ok {
		return nil
	}
	var rows []FactRow
	for _, c := range certs {
		cm, ok := c.(map[string]any)
		if !ok {
			continue
		}
		fp, _ := cm["fingerprint"].(string)
		subj, _ := cm["subject"].(string)
		if fp == "" && subj == "" {
			continue
		}
		key := fp
		if key == "" {
			key = subj
		}
		if len(key) > 16 {
			key = key[:16]
		}
		b, _ := json.Marshal(cm)
		rows = append(rows, FactRow{App: app, Category: "cert", Key: key, Value: string(b)})
	}
	return rows
}

func extractAuth(m map[string]any, app string) []FactRow {
	var rows []FactRow

	// auth.providers — []string or []map
	if auth, ok := m["auth"].(map[string]any); ok {
		for _, k := range []string{"providers", "schemes"} {
			if arr, ok := auth[k].([]any); ok {
				for _, p := range arr {
					switch v := p.(type) {
					case string:
						if v != "" {
							rows = append(rows, FactRow{App: app, Category: "auth", Key: v, Value: v})
						}
					case map[string]any:
						name, _ := v["name"].(string)
						if name == "" {
							continue
						}
						b, _ := json.Marshal(v)
						rows = append(rows, FactRow{App: app, Category: "auth", Key: name, Value: string(b)})
					}
				}
			}
		}
	}

	// security.auth
	if sec, ok := m["security"].(map[string]any); ok {
		if v, ok := sec["auth"].(string); ok && v != "" {
			rows = append(rows, FactRow{App: app, Category: "auth", Key: "scheme", Value: v})
		}
	}
	return rows
}
