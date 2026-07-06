/*
Copyright © 2026 Security Research
*/
package snapshot

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// DB wraps a per-extension SQLite database for snapshot data.
type DB struct {
	db *sql.DB
}

// DOMElement represents an extension-injected DOM element detected on a page.
type DOMElement struct {
	Selector       string `json:"selector"`
	HTML           string `json:"html,omitempty"`
	TagName        string `json:"tagName,omitempty"`
	ClassList      string `json:"classList,omitempty"`
	ComputedStyles string `json:"computedStyles,omitempty"`
}

// StorageEntry represents a localStorage/sessionStorage/cookie entry.
type StorageEntry struct {
	StorageType string `json:"storageType"`
	Key         string `json:"key"`
	Value       string `json:"value"`
}

// NetworkEntry represents a single network request captured from HAR.
type NetworkEntry struct {
	Method         string  `json:"method,omitempty"`
	URL            string  `json:"url"`
	Status         int     `json:"status,omitempty"`
	ContentType    string  `json:"contentType,omitempty"`
	RequestHeaders string  `json:"requestHeaders,omitempty"`
	ResponseSize   int64   `json:"responseSize,omitempty"`
	TimingMs       float64 `json:"timingMs,omitempty"`
}

// SourceURL represents a URL found in extension source code.
type SourceURL struct {
	ExtensionID string `json:"extensionId"`
	URL         string `json:"url"`
	Host        string `json:"host"`
	Category    string `json:"category"`
	SourceFile  string `json:"sourceFile,omitempty"`
	SourceType  string `json:"sourceType"`
}

// URLMapping maps a source URL to a live HAR network entry.
type URLMapping struct {
	ExtensionID     string `json:"extensionId"`
	SnapshotID      int64  `json:"snapshotId"`
	SourceURL       string `json:"sourceUrl"`
	HARURL          string `json:"harUrl"`
	MatchType       string `json:"matchType"`
	HARMethod       string `json:"harMethod,omitempty"`
	HARStatus       int    `json:"harStatus,omitempty"`
	HARContentType  string `json:"harContentType,omitempty"`
	HARResponseSize int64  `json:"harResponseSize,omitempty"`
}

const dbSchema = `
CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    store_id TEXT NOT NULL,
    store_url TEXT NOT NULL,
    captured_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    load_time_ms INTEGER,
    page_title TEXT
);
CREATE TABLE IF NOT EXISTS dom_elements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER REFERENCES snapshots(id),
    selector TEXT NOT NULL,
    html TEXT,
    tag_name TEXT,
    class_list TEXT,
    computed_styles TEXT
);
CREATE TABLE IF NOT EXISTS storage_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER REFERENCES snapshots(id),
    storage_type TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT
);
CREATE TABLE IF NOT EXISTS network_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER REFERENCES snapshots(id),
    method TEXT,
    url TEXT NOT NULL,
    status INTEGER,
    content_type TEXT,
    request_headers TEXT,
    response_size INTEGER,
    timing_ms REAL
);
CREATE TABLE IF NOT EXISTS screenshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER REFERENCES snapshots(id),
    png_data BLOB
);
CREATE TABLE IF NOT EXISTS manifest_info (
    extension_id TEXT PRIMARY KEY,
    name TEXT,
    version TEXT,
    manifest_json TEXT,
    permissions TEXT
);
CREATE TABLE IF NOT EXISTS source_urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    extension_id TEXT NOT NULL,
    url TEXT NOT NULL,
    host TEXT NOT NULL,
    category TEXT NOT NULL,
    source_file TEXT,
    source_type TEXT NOT NULL,
    UNIQUE(extension_id, url, source_type)
);
CREATE TABLE IF NOT EXISTS url_mappings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    extension_id TEXT NOT NULL,
    snapshot_id INTEGER REFERENCES snapshots(id),
    source_url TEXT NOT NULL,
    har_url TEXT NOT NULL,
    match_type TEXT NOT NULL,
    har_method TEXT,
    har_status INTEGER,
    har_content_type TEXT,
    har_response_size INTEGER
);
`

// OpenDB opens or creates a per-extension SQLite database.
func OpenDB(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}
	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if _, err := sqlDB.Exec(dbSchema); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("run migrations: %w", err)
	}
	return &DB{db: sqlDB}, nil
}

func (d *DB) Close() error { return d.db.Close() }

func (d *DB) SaveManifest(extID, name, version string, manifestJSON []byte, permissions []string) error {
	permsJSON, _ := json.Marshal(permissions)
	_, err := d.db.Exec(`
		INSERT INTO manifest_info (extension_id, name, version, manifest_json, permissions)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(extension_id) DO UPDATE SET
			name=excluded.name, version=excluded.version,
			manifest_json=excluded.manifest_json, permissions=excluded.permissions`,
		extID, name, version, string(manifestJSON), string(permsJSON))
	return err
}

func (d *DB) CreateSnapshot(storeID, storeURL, pageTitle string, loadTimeMs int64) (int64, error) {
	res, err := d.db.Exec(`INSERT INTO snapshots (store_id, store_url, page_title, load_time_ms) VALUES (?, ?, ?, ?)`,
		storeID, storeURL, pageTitle, loadTimeMs)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (d *DB) SaveDOMElements(snapshotID int64, elements []DOMElement) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.Prepare(`INSERT INTO dom_elements (snapshot_id, selector, html, tag_name, class_list, computed_styles) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()
	for _, el := range elements {
		if _, err := stmt.Exec(snapshotID, el.Selector, el.HTML, el.TagName, el.ClassList, el.ComputedStyles); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (d *DB) SaveStorageData(snapshotID int64, entries []StorageEntry) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.Prepare(`INSERT INTO storage_data (snapshot_id, storage_type, key, value) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()
	for _, e := range entries {
		if _, err := stmt.Exec(snapshotID, e.StorageType, e.Key, e.Value); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (d *DB) SaveNetworkEntries(snapshotID int64, entries []NetworkEntry) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.Prepare(`INSERT INTO network_entries (snapshot_id, method, url, status, content_type, request_headers, response_size, timing_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()
	for _, e := range entries {
		if _, err := stmt.Exec(snapshotID, e.Method, e.URL, e.Status, e.ContentType, e.RequestHeaders, e.ResponseSize, e.TimingMs); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (d *DB) SaveScreenshot(snapshotID int64, png []byte) error {
	_, err := d.db.Exec(`INSERT INTO screenshots (snapshot_id, png_data) VALUES (?, ?)`, snapshotID, png)
	return err
}

func (d *DB) SaveSourceURLs(urls []SourceURL) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO source_urls (extension_id, url, host, category, source_file, source_type) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()
	for _, u := range urls {
		if _, err := stmt.Exec(u.ExtensionID, u.URL, u.Host, u.Category, u.SourceFile, u.SourceType); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (d *DB) GetSourceURLs(extensionID string) ([]SourceURL, error) {
	rows, err := d.db.Query(`SELECT extension_id, url, host, category, source_file, source_type FROM source_urls WHERE extension_id = ?`, extensionID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var urls []SourceURL
	for rows.Next() {
		var u SourceURL
		var sourceFile sql.NullString
		if err := rows.Scan(&u.ExtensionID, &u.URL, &u.Host, &u.Category, &sourceFile, &u.SourceType); err != nil {
			return nil, err
		}
		u.SourceFile = sourceFile.String
		urls = append(urls, u)
	}
	return urls, rows.Err()
}

func (d *DB) SaveURLMappings(mappings []URLMapping) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.Prepare(`INSERT INTO url_mappings (extension_id, snapshot_id, source_url, har_url, match_type, har_method, har_status, har_content_type, har_response_size) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()
	for _, m := range mappings {
		if _, err := stmt.Exec(m.ExtensionID, m.SnapshotID, m.SourceURL, m.HARURL, m.MatchType, m.HARMethod, m.HARStatus, m.HARContentType, m.HARResponseSize); err != nil {
			return err
		}
	}
	return tx.Commit()
}
