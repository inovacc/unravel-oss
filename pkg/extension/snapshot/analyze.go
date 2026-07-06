/*
Copyright © 2026 Security Research
*/
package snapshot

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/inovacc/scout/pkg/scout"
)

const analyzeTargetURL = "https://www.amazon.com/dp/B0DFDJQH8Q"

// AnalyzeExtension launches a browser with the extension, visits a common site,
// captures HAR with correct recorder ordering, and maps source URLs to live traffic.
func AnalyzeExtension(ext Extension, targetDir string, sourceURLs *ExtractedURLs) error {
	extDir := filepath.Join(targetDir, ext.ID, "ext")
	manifestPath := filepath.Join(extDir, "manifest.json")
	if _, err := os.Stat(manifestPath); err != nil {
		return fmt.Errorf("extension not extracted: %s", ext.ID)
	}

	extTargetDir := filepath.Join(targetDir, ext.ID)
	dbDir := filepath.Join(extTargetDir, "db")
	harDir := filepath.Join(extTargetDir, "har")
	profileDir := filepath.Join(extTargetDir, "profile")
	for _, d := range []string{dbDir, harDir, profileDir} {
		_ = os.MkdirAll(d, 0o755)
	}

	db, err := OpenDB(filepath.Join(dbDir, ext.ID+".db"))
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer func() { _ = db.Close() }()

	b, err := scout.New(
		scout.WithHeadless(false),
		scout.WithUserDataDir(profileDir),
		scout.WithNoSandbox(),
		scout.WithWindowSize(1280, 900),
		scout.WithTimeout(30*time.Second),
		scout.WithExtension(extDir),
		scout.WithLaunchFlag("no-first-run"),
		scout.WithLaunchFlag("no-default-browser-check"),
		scout.WithLaunchFlag("disable-popup-blocking"),
	)
	if err != nil {
		return fmt.Errorf("launch browser: %w", err)
	}
	defer func() { _ = b.Close() }()

	time.Sleep(3 * time.Second)

	// Critical fix: open blank page first, attach recorder, THEN navigate
	page, err := b.NewPage("about:blank")
	if err != nil {
		return fmt.Errorf("open page: %w", err)
	}
	defer func() { _ = page.Close() }()

	recorder := scout.NewNetworkRecorder(page)
	waitIdle := page.WaitRequestIdle(3*time.Second, nil, nil)

	if err := page.Navigate(analyzeTargetURL); err != nil {
		return fmt.Errorf("navigate: %w", err)
	}

	if err := page.WaitLoad(); err != nil {
		slog.Warn("WaitLoad", "error", err)
	}

	waitIdle()
	time.Sleep(3 * time.Second)

	recorder.Stop()

	harData, _, err := recorder.ExportHAR()
	if err != nil {
		return fmt.Errorf("export HAR: %w", err)
	}

	harFile := filepath.Join(harDir, "analyze.har")
	if wErr := os.WriteFile(harFile, harData, 0o644); wErr != nil {
		slog.Warn("failed to write HAR file", "path", harFile, "error", wErr)
	} else {
		slog.Info("saved HAR", "path", harFile, "bytes", len(harData))
	}

	harEntries, err := parseHAREntries(harData)
	if err != nil {
		return fmt.Errorf("parse HAR: %w", err)
	}

	pageTitle, _ := page.Title()
	snapID, err := db.CreateSnapshot("analyze", analyzeTargetURL, pageTitle, 0)
	if err != nil {
		return fmt.Errorf("create snapshot: %w", err)
	}

	var netEntries []NetworkEntry
	for _, e := range harEntries {
		netEntries = append(netEntries, NetworkEntry{
			Method:       e.Method,
			URL:          e.URL,
			Status:       e.Status,
			ContentType:  e.ContentType,
			ResponseSize: e.ResponseSize,
		})
	}
	if len(netEntries) > 0 {
		_ = db.SaveNetworkEntries(snapID, netEntries)
	}

	mappings := mapURLs(ext.ID, snapID, sourceURLs, harEntries)
	if len(mappings) > 0 {
		if err := db.SaveURLMappings(mappings); err != nil {
			slog.Error("save URL mappings", "error", err)
		}
	}

	slog.Info("analyzed",
		"ext", ext.Name,
		"har_entries", len(harEntries),
		"source_urls", len(sourceURLs.URLs),
		"mappings", len(mappings),
	)

	return nil
}

type harEntry struct {
	Method       string
	URL          string
	Status       int
	ContentType  string
	ResponseSize int64
}

func parseHAREntries(data []byte) ([]harEntry, error) {
	var har struct {
		Log struct {
			Entries []struct {
				Request struct {
					Method string `json:"method"`
					URL    string `json:"url"`
				} `json:"request"`
				Response struct {
					Status  int `json:"status"`
					Content struct {
						Size     int64  `json:"size"`
						MimeType string `json:"mimeType"`
					} `json:"content"`
				} `json:"response"`
			} `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(data, &har); err != nil {
		return nil, err
	}

	var entries []harEntry
	for _, e := range har.Log.Entries {
		entries = append(entries, harEntry{
			Method:       e.Request.Method,
			URL:          e.Request.URL,
			Status:       e.Response.Status,
			ContentType:  e.Response.Content.MimeType,
			ResponseSize: e.Response.Content.Size,
		})
	}
	return entries, nil
}

func mapURLs(extID string, snapID int64, sourceURLs *ExtractedURLs, harEntries []harEntry) []URLMapping {
	var mappings []URLMapping

	type harByHost struct {
		entry  harEntry
		parsed *url.URL
	}
	harIndex := make(map[string][]harByHost)
	for _, he := range harEntries {
		parsed, err := url.Parse(he.URL)
		if err != nil {
			continue
		}
		host := strings.ToLower(parsed.Host)
		harIndex[host] = append(harIndex[host], harByHost{entry: he, parsed: parsed})
	}

	for _, su := range sourceURLs.URLs {
		srcParsed, err := url.Parse(su.URL)
		if err != nil {
			continue
		}
		srcHost := strings.ToLower(srcParsed.Host)
		srcHost = strings.TrimPrefix(srcHost, "*.")

		hostEntries, ok := harIndex[srcHost]
		if !ok {
			for h, entries := range harIndex {
				if strings.HasSuffix(h, "."+srcHost) || h == srcHost {
					hostEntries = append(hostEntries, entries...)
				}
			}
			if len(hostEntries) == 0 {
				continue
			}
		}

		for _, he := range hostEntries {
			matchType := matchURLs(srcParsed, he.parsed)
			if matchType == "" {
				continue
			}

			mappings = append(mappings, URLMapping{
				ExtensionID:     extID,
				SnapshotID:      snapID,
				SourceURL:       su.URL,
				HARURL:          he.entry.URL,
				MatchType:       matchType,
				HARMethod:       he.entry.Method,
				HARStatus:       he.entry.Status,
				HARContentType:  he.entry.ContentType,
				HARResponseSize: he.entry.ResponseSize,
			})
		}
	}

	return mappings
}

func matchURLs(src, har *url.URL) string {
	if src.Host == har.Host && src.Path == har.Path && src.RawQuery == har.RawQuery {
		return "exact"
	}

	srcPath := strings.TrimRight(src.Path, "/")
	harPath := strings.TrimRight(har.Path, "/")
	if srcPath != "" && srcPath != "/" && strings.HasPrefix(harPath, srcPath) {
		return "host_path"
	}

	if srcPath == "" || srcPath == "/" {
		return "host_only"
	}

	return ""
}
