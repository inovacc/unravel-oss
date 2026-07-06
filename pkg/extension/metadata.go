/*
Copyright © 2026 Security Research
*/
package extension

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// maxExtensionReadSize caps reads of individual extension files (incl.
// manifest.json). Real manifests are KB-scale; 5 MiB is a generous ceiling.
// Var (not const) so tests can inject a small cap to exercise the guard.
var maxExtensionReadSize int64 = 5 * 1024 * 1024

var (
	msgTokenRe     = regexp.MustCompile(`^__MSG_([^_].*?)__$`)
	nativeHostRe   = regexp.MustCompile(`(?i)(?:runtime\.)?connectNative\(\s*["']([^"']+)["']\s*\)`)
	websocketRe    = regexp.MustCompile("(?i)wss?://[^\\s\"'`\\\\]+")
	httpEndpointRe = regexp.MustCompile("(?i)https?://[^\\s\"'`\\\\]+")
)

func normalizeOptionalPermissions(cm ChromeManifest) []string {
	seen := map[string]bool{}

	var out []string

	for _, p := range cm.OptPermissions {
		s := strings.TrimSpace(fmt.Sprintf("%v", p))
		if s == "" || seen[s] {
			continue
		}

		seen[s] = true
		out = append(out, s)
	}

	sort.Strings(out)

	return out
}

func extractBackgroundScripts(cm ChromeManifest) []string {
	if cm.Background == nil {
		return nil
	}

	scripts, ok := cm.Background["scripts"]
	if !ok {
		return nil
	}

	return toUniqueSortedStrings(scripts)
}

func extractBackgroundServiceWorker(cm ChromeManifest) string {
	if cm.Background == nil {
		return ""
	}

	worker, ok := cm.Background["service_worker"]
	if !ok {
		return ""
	}

	return strings.TrimSpace(fmt.Sprintf("%v", worker))
}

func normalizeWebAccessibleResources(raw any) []string {
	if raw == nil {
		return nil
	}

	seen := map[string]bool{}

	var out []string

	add := func(values ...string) {
		for _, v := range values {
			v = strings.TrimSpace(v)
			if v == "" || seen[v] {
				continue
			}

			seen[v] = true
			out = append(out, v)
		}
	}

	switch v := raw.(type) {
	case string:
		add(v)
	case []any:
		for _, item := range v {
			switch t := item.(type) {
			case string:
				add(t)
			case map[string]any:
				add(toUniqueSortedStrings(t["resources"])...)
			}
		}
	case map[string]any:
		add(toUniqueSortedStrings(v["resources"])...)
	}

	sort.Strings(out)

	return out
}

func normalizeExternallyConnectable(raw any) []string {
	if raw == nil {
		return nil
	}

	seen := map[string]bool{}

	var out []string

	add := func(prefix string, values []string) {
		for _, v := range values {
			item := strings.TrimSpace(prefix + v)
			if item == "" || seen[item] {
				continue
			}

			seen[item] = true
			out = append(out, item)
		}
	}

	obj, ok := raw.(map[string]any)
	if !ok {
		return nil
	}

	add("id:", toUniqueSortedStrings(obj["ids"]))
	add("match:", toUniqueSortedStrings(obj["matches"]))

	if atci, ok := obj["accepts_tls_channel_id"].(bool); ok {
		add("", []string{fmt.Sprintf("accepts_tls_channel_id:%t", atci)})
	}

	sort.Strings(out)

	return out
}

func toUniqueSortedStrings(raw any) []string {
	seen := map[string]bool{}

	var out []string

	switch v := raw.(type) {
	case string:
		s := strings.TrimSpace(v)
		if s != "" {
			seen[s] = true
			out = append(out, s)
		}
	case []string:
		for _, s := range v {
			s = strings.TrimSpace(s)
			if s == "" || seen[s] {
				continue
			}

			seen[s] = true
			out = append(out, s)
		}
	case []any:
		for _, item := range v {
			s := strings.TrimSpace(fmt.Sprintf("%v", item))
			if s == "" || seen[s] {
				continue
			}

			seen[s] = true
			out = append(out, s)
		}
	}

	sort.Strings(out)

	return out
}

func resolveLocaleMessage(raw, versionDir, defaultLocale string) string {
	token := strings.TrimSpace(raw)

	m := msgTokenRe.FindStringSubmatch(token)
	if len(m) != 2 {
		return raw
	}

	key := m[1]
	if msg := lookupMessage(versionDir, key, defaultLocale); msg != "" {
		return msg
	}

	return raw
}

func lookupMessage(versionDir, key, defaultLocale string) string {
	try := []string{}
	if defaultLocale != "" {
		try = append(try, defaultLocale)
	}

	try = append(try, "en")

	seen := map[string]bool{}
	for _, locale := range try {
		if seen[locale] {
			continue
		}

		seen[locale] = true
		if msg := readMessage(versionDir, locale, key); msg != "" {
			return msg
		}
	}

	localesDir := filepath.Join(versionDir, "_locales")

	entries, err := os.ReadDir(localesDir)
	if err != nil {
		return ""
	}

	for _, entry := range entries {
		if !entry.IsDir() || seen[entry.Name()] {
			continue
		}

		if msg := readMessage(versionDir, entry.Name(), key); msg != "" {
			return msg
		}
	}

	return ""
}

func readMessage(versionDir, locale, key string) string {
	path := filepath.Join(versionDir, "_locales", locale, "messages.json")

	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}

	var parsed map[string]struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return ""
	}

	if msg, ok := parsed[key]; ok && msg.Message != "" {
		return msg.Message
	}

	if msg, ok := parsed[strings.ToLower(key)]; ok && msg.Message != "" {
		return msg.Message
	}

	return ""
}

func findManifestDir(root string) (string, error) {
	best := ""
	bestDepth := int(^uint(0) >> 1)

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() && d.Name() == "_metadata" {
			return filepath.SkipDir
		}

		if d.IsDir() || !strings.EqualFold(d.Name(), "manifest.json") {
			return nil
		}

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}

		depth := strings.Count(rel, string(os.PathSeparator))
		if depth < bestDepth {
			bestDepth = depth
			best = filepath.Dir(path)
		}

		return nil
	})

	if best == "" {
		return "", fmt.Errorf("manifest.json not found under %s", root)
	}

	return best, nil
}

// enrichExtensionData adds lightweight forensic metadata on top of risk findings.
func enrichExtensionData(info *ExtensionInfo) {
	scriptSet := map[string]bool{}
	nativeHostSet := map[string]bool{}
	wsEndpointSet := map[string]bool{}
	urlEndpointSet := map[string]bool{}

	interestingExts := map[string]bool{
		".js": true, ".mjs": true, ".json": true, ".html": true, ".css": true,
	}

	_ = filepath.Walk(info.Path, func(path string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return nil
		}

		relPath, relErr := filepath.Rel(info.Path, path)
		if relErr != nil {
			relPath = fi.Name()
		}

		ext := strings.ToLower(filepath.Ext(path))
		info.FileStats.TotalFiles++
		info.FileStats.TotalBytes += fi.Size()

		switch ext {
		case ".js", ".mjs":
			info.FileStats.JavaScriptFiles++
			scriptSet[relPath] = true
		case ".json":
			info.FileStats.JSONFiles++
		case ".html":
			info.FileStats.HTMLFiles++
		case ".css":
			info.FileStats.CSSFiles++
		}

		if fi.Size() > maxExtensionReadSize || !interestingExts[ext] {
			return nil
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}

		content := string(data)

		for _, match := range nativeHostRe.FindAllStringSubmatch(content, -1) {
			if len(match) < 2 {
				continue
			}

			host := strings.TrimSpace(match[1])
			if host != "" {
				nativeHostSet[host] = true
			}
		}

		for _, match := range websocketRe.FindAllString(content, -1) {
			match = strings.TrimSpace(match)
			if match != "" {
				wsEndpointSet[match] = true
			}
		}

		for _, match := range httpEndpointRe.FindAllString(content, -1) {
			match = strings.TrimSpace(match)
			if match != "" {
				urlEndpointSet[match] = true
			}
		}

		return nil
	})

	info.ScriptFiles = sortedKeys(scriptSet)
	info.NativeMessagingHosts = sortedKeys(nativeHostSet)
	info.WebSocketEndpoints = sortedKeys(wsEndpointSet)
	info.URLEndpoints = sortedKeys(urlEndpointSet)
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}

	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}

	sort.Strings(out)

	return out
}
