/*
Copyright © 2026 Security Research
*/
package snapshot

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/inovacc/scout/pkg/scout"
)

// Extension represents a browser extension loaded from CSV.
type Extension struct {
	Name string
	ID   string
	URL  string
}

// StoreTarget represents an e-commerce store to visit during crawling.
type StoreTarget struct {
	ID         string
	Name       string
	ProductURL string
}

// DefaultStores lists the e-commerce sites visited during extension snapshot capture.
var DefaultStores = []StoreTarget{
	{"amazon-us", "Amazon US", "https://www.amazon.com/dp/B0DFDJQH8Q"},
	{"amazon-br", "Amazon Brasil", "https://www.amazon.com.br/dp/B0DFDJQH8Q"},
	{"walmart", "Walmart", "https://www.walmart.com/ip/Apple-AirPods-Pro-2/1752657021"},
	{"target", "Target", "https://www.target.com/p/apple-airpods-pro-2nd-generation/-/A-85978612"},
	{"bestbuy", "Best Buy", "https://www.bestbuy.com/site/apple-airpods-pro-2/6447382.p"},
	{"mercadolivre", "Mercado Livre", "https://www.mercadolivre.com.br/fone-de-ouvido-in-ear-gamer-sem-fio-samsung-galaxy-buds-fe/p/MLB27262627"},
	{"magalu", "Magazine Luiza", "https://www.magazineluiza.com.br/smartphone-samsung-galaxy-s24-ultra-256gb-titanium-gray-5g-12gb-ram-tela-68-cam-quadrupla-selfie-12mp-dual-chip/p/238052500/te/gaxu/"},
	{"kabum", "KaBuM!", "https://www.kabum.com.br/produto/480476/mouse-gamer-logitech-g-pro-x-superlight-2-lightspeed"},
	{"aliexpress", "AliExpress", "https://www.aliexpress.com/item/1005007380562498.html"},
	{"ebay", "eBay", "https://www.ebay.com/itm/125678901234"},
}

var extensionSelectors = []string{
	`[class*="honey"]`, `[id*="honey"]`, `#honeyContainer`,
	`[class*="wikibuy"]`, `[id*="wikibuy"]`, `[class*="capitalone"]`,
	`[class*="coupert"]`, `[id*="coupert"]`,
	`[class*="rakuten"]`, `[id*="rakuten"]`, `[class*="ebates"]`,
	`[class*="keepa"]`, `[id*="keepaBox"]`, `.keepaInline`,
	`[class*="camelizer"]`, `[id*="camelizer"]`,
	`[class*="cently"]`, `[id*="cently"]`,
	`[class*="meliuz"]`, `[id*="meliuz"]`,
	`[class*="cuponeria"]`, `[id*="cuponeria"]`,
	`[class*="reduza"]`, `[id*="reduza"]`,
	`[class*="klarna"]`, `[id*="klarna"]`, `[class*="piggy"]`,
	`[class*="dealdrop"]`, `[id*="dealdrop"]`,
	`[class*="karmanow"]`, `[id*="karma"]`,
	`[class*="ibotta"]`, `[id*="ibotta"]`,
	`[class*="cnet"]`, `[id*="cnet-shopping"]`,
	`[class*="savely"]`, `[id*="savely"]`,
	`[class*="shopback"]`, `[id*="shopback"]`,
	`[class*="simplycodes"]`, `[id*="simplycodes"]`,
	`[class*="retailmenot"]`, `[id*="retailmenot"]`,
	`[class*="couponbirds"]`, `[id*="couponbirds"]`,
	`[class*="befrugal"]`, `[id*="befrugal"]`,
	`[class*="kiwii"]`, `[id*="kiwii"]`,
	`[class*="discount-popup"]`, `[class*="coupon-overlay"]`,
	`iframe[src*="honey"]`, `iframe[src*="coupert"]`, `iframe[src*="rakuten"]`,
	`iframe[src*="klarna"]`, `iframe[src*="ibotta"]`,
}

// LoadCSV reads extensions from a CSV file (columns: Extension Name, Chrome Web Store Link).
func LoadCSV(path string) ([]Extension, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open CSV: %w", err)
	}
	defer func() { _ = f.Close() }()

	reader := csv.NewReader(f)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse CSV: %w", err)
	}

	var exts []Extension
	for _, row := range records[1:] {
		if len(row) < 2 {
			continue
		}
		parts := strings.Split(strings.TrimRight(row[1], "/"), "/")
		id := parts[len(parts)-1]
		exts = append(exts, Extension{
			Name: row[0],
			ID:   id,
			URL:  row[1],
		})
	}
	return exts, nil
}

// DownloadExtensions downloads and extracts all extensions into targetDir/{id}/ext/.
func DownloadExtensions(exts []Extension, targetDir string) error {
	for i, ext := range exts {
		extDir := filepath.Join(targetDir, ext.ID, "ext")
		manifest := filepath.Join(extDir, "manifest.json")

		if _, err := os.Stat(manifest); err == nil {
			slog.Info("already extracted, skipping", "index", i+1, "total", len(exts), "name", ext.Name)
			continue
		}

		slog.Info("downloading extension", "index", i+1, "total", len(exts), "name", ext.Name, "id", ext.ID)

		crxData, err := DownloadCRX(ext.ID)
		if err != nil {
			slog.Error("download failed", "name", ext.Name, "error", err)
			continue
		}
		slog.Info("downloaded", "name", ext.Name, "bytes", len(crxData))

		_ = os.MkdirAll(extDir, 0o755)
		if err := ExtractCRX(crxData, extDir); err != nil {
			slog.Error("extract failed", "name", ext.Name, "error", err)
			continue
		}
		slog.Info("extracted", "name", ext.Name, "dir", extDir)

		time.Sleep(500 * time.Millisecond)
	}
	return nil
}

// CrawlExtension launches a browser with a single extension and visits all stores,
// capturing snapshots to a per-extension SQLite database.
func CrawlExtension(ext Extension, targetDir string, stores []StoreTarget) error {
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

	// Save manifest info
	manifestData, err := readManifestBounded(manifestPath)
	if err == nil {
		var m map[string]any
		if err := json.Unmarshal(manifestData, &m); err == nil {
			name, _ := m["name"].(string)
			version, _ := m["version"].(string)
			var perms []string
			if p, ok := m["permissions"].([]any); ok {
				for _, v := range p {
					if s, ok := v.(string); ok {
						perms = append(perms, s)
					}
				}
			}
			_ = db.SaveManifest(ext.ID, name, version, manifestData, perms)
		}
	}

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

	for _, store := range stores {
		slog.Info("visiting store", "ext", ext.Name, "store", store.Name, "url", store.ProductURL)
		if err := crawlStore(b, db, ext, store, harDir); err != nil {
			slog.Error("crawl store failed", "ext", ext.Name, "store", store.Name, "error", err)
		}
	}

	return nil
}

func crawlStore(b *scout.Browser, db *DB, ext Extension, store StoreTarget, harDir string) error {
	start := time.Now()

	page, err := b.NewPage(store.ProductURL)
	if err != nil {
		return fmt.Errorf("open page: %w", err)
	}
	defer func() { _ = page.Close() }()

	recorder := scout.NewNetworkRecorder(page)

	if err := page.WaitLoad(); err != nil {
		slog.Warn("WaitLoad", "error", err)
	}

	// Give extension time to inject UI
	time.Sleep(25 * time.Second)

	loadTimeMs := time.Since(start).Milliseconds()
	pageTitle, _ := page.Title()

	snapID, err := db.CreateSnapshot(store.ID, store.ProductURL, pageTitle, loadTimeMs)
	if err != nil {
		return fmt.Errorf("create snapshot: %w", err)
	}

	// DOM elements
	var domElements []DOMElement
	for _, sel := range extensionSelectors {
		has, err := page.Has(sel)
		if err != nil || !has {
			continue
		}
		el, err := page.Element(sel)
		if err != nil {
			continue
		}
		html, _ := el.HTML()
		if len(html) > 2000 {
			html = html[:2000]
		}
		domElements = append(domElements, DOMElement{Selector: sel, HTML: html})
	}
	if len(domElements) > 0 {
		_ = db.SaveDOMElements(snapID, domElements)
	}

	// Storage
	var storageEntries []StorageEntry

	lsResult, err := page.Eval(`() => {
		const d = {};
		for (let i = 0; i < localStorage.length; i++) {
			const k = localStorage.key(i);
			d[k] = localStorage.getItem(k);
		}
		return JSON.stringify(d);
	}`)
	if err == nil {
		var ls map[string]string
		if err := json.Unmarshal(fmt.Appendf(nil, "%v", lsResult.Value), &ls); err == nil {
			for k, v := range ls {
				storageEntries = append(storageEntries, StorageEntry{StorageType: "localStorage", Key: k, Value: v})
			}
		}
	}

	ssResult, err := page.Eval(`() => {
		const d = {};
		for (let i = 0; i < sessionStorage.length; i++) {
			const k = sessionStorage.key(i);
			d[k] = sessionStorage.getItem(k);
		}
		return JSON.stringify(d);
	}`)
	if err == nil {
		var ss map[string]string
		if err := json.Unmarshal(fmt.Appendf(nil, "%v", ssResult.Value), &ss); err == nil {
			for k, v := range ss {
				storageEntries = append(storageEntries, StorageEntry{StorageType: "sessionStorage", Key: k, Value: v})
			}
		}
	}

	cookieResult, err := page.Eval(`() => document.cookie`)
	if err == nil {
		cookieStr := fmt.Sprintf("%v", cookieResult.Value)
		for pair := range strings.SplitSeq(cookieStr, ";") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			parts := strings.SplitN(pair, "=", 2)
			key := parts[0]
			val := ""
			if len(parts) > 1 {
				val = parts[1]
			}
			storageEntries = append(storageEntries, StorageEntry{StorageType: "cookie", Key: key, Value: val})
		}
	}

	if len(storageEntries) > 0 {
		_ = db.SaveStorageData(snapID, storageEntries)
	}

	// Network from HAR
	recorder.Stop()
	harData, _, err := recorder.ExportHAR()
	if err == nil {
		harFile := filepath.Join(harDir, store.ID+".har")
		if wErr := os.WriteFile(harFile, harData, 0o644); wErr != nil {
			slog.Warn("failed to write HAR file", "path", harFile, "error", wErr)
		} else {
			slog.Info("saved HAR", "path", harFile, "bytes", len(harData))
		}

		var har struct {
			Log struct {
				Entries []struct {
					Request struct {
						Method  string `json:"method"`
						URL     string `json:"url"`
						Headers []struct {
							Name  string `json:"name"`
							Value string `json:"value"`
						} `json:"headers"`
					} `json:"request"`
					Response struct {
						Status  int `json:"status"`
						Content struct {
							Size     int64  `json:"size"`
							MimeType string `json:"mimeType"`
						} `json:"content"`
					} `json:"response"`
					Time float64 `json:"time"`
				} `json:"entries"`
			} `json:"log"`
		}
		if err := json.Unmarshal(harData, &har); err == nil {
			var netEntries []NetworkEntry
			for _, e := range har.Log.Entries {
				headersJSON, _ := json.Marshal(e.Request.Headers)
				netEntries = append(netEntries, NetworkEntry{
					Method: e.Request.Method, URL: e.Request.URL, Status: e.Response.Status,
					ContentType: e.Response.Content.MimeType, RequestHeaders: string(headersJSON),
					ResponseSize: e.Response.Content.Size, TimingMs: e.Time,
				})
			}
			if len(netEntries) > 0 {
				_ = db.SaveNetworkEntries(snapID, netEntries)
			}
		}
	}

	// Screenshot
	png, err := page.Screenshot()
	if err == nil {
		_ = db.SaveScreenshot(snapID, png)
	}

	slog.Info("captured", "ext", ext.Name, "store", store.Name, "dom", len(domElements), "storage", len(storageEntries), "ms", loadTimeMs)
	return nil
}
