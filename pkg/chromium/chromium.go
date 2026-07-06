// Package chromium extracts data from Chromium-based application profiles.
package chromium

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// quoteSQLiteIdent escapes embedded `"` so a value can be safely interpolated
// inside a `"..."` SQLite quoted identifier. SQLite represents a literal `"`
// inside a quoted identifier by doubling it (`""`). Callers still wrap the
// result in `"..."` themselves; this helper only neutralizes the closing
// quote so attacker-controlled DB files (the threat model for an analysis
// tool) cannot break out of the identifier and inject SQL.
func quoteSQLiteIdent(name string) string {
	return strings.ReplaceAll(name, `"`, `""`)
}

// ExtractorConfig holds the configuration for extraction.
type ExtractorConfig struct {
	SourcePath string
	OutputPath string
	AppName    string
}

// ExtractionResult holds the complete extraction result.
type ExtractionResult struct {
	AppName      string            `json:"app_name"`
	SourcePath   string            `json:"source_path"`
	ExtractedAt  string            `json:"extracted_at"`
	Files        []ExtractedFile   `json:"files"`
	Databases    []DatabaseInfo    `json:"databases"`
	LocalStorage map[string]string `json:"local_storage,omitempty"`
	Cookies      []CookieInfo      `json:"cookies,omitempty"`
	TotalSize    int64             `json:"total_size_bytes"`
	FileCount    int               `json:"file_count"`
}

// ExtractedFile represents a single extracted file.
type ExtractedFile struct {
	OriginalPath string `json:"original_path"`
	OutputPath   string `json:"output_path"`
	Size         int64  `json:"size"`
	SHA256       string `json:"sha256"`
	Type         string `json:"type"`
}

// DatabaseInfo holds information about a discovered SQLite database.
type DatabaseInfo struct {
	Name    string   `json:"name"`
	Path    string   `json:"path"`
	Tables  []string `json:"tables"`
	Records int      `json:"total_records"`
}

// CookieInfo represents a single cookie entry.
type CookieInfo struct {
	Domain      string `json:"domain"`
	Name        string `json:"name"`
	Path        string `json:"path"`
	ExpiresUTC  int64  `json:"expires_utc"`
	IsSecure    bool   `json:"is_secure"`
	IsHTTPOnly  bool   `json:"is_httponly"`
	CreationUTC int64  `json:"creation_utc"`
}

// Extract performs a full extraction of a Chromium profile.
func Extract(config ExtractorConfig) (*ExtractionResult, error) {
	result := &ExtractionResult{
		AppName:      config.AppName,
		SourcePath:   config.SourcePath,
		ExtractedAt:  time.Now().UTC().Format(time.RFC3339),
		Files:        []ExtractedFile{},
		Databases:    []DatabaseInfo{},
		LocalStorage: make(map[string]string),
		Cookies:      []CookieInfo{},
	}

	if err := os.MkdirAll(config.OutputPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	ExtractBlobStorage(config, result)
	extractCache(config, result)
	extractCodeCache(config, result)
	extractLocalStorage(config, result)
	extractIndexedDB(config, result)
	ExtractDatabases(config, result)
	extractSessionStorage(config, result)
	extractNetworkData(config, result)
	extractConfigFiles(config, result)

	return result, nil
}

// ExtractBlobStorage extracts blob storage data.
func ExtractBlobStorage(config ExtractorConfig, result *ExtractionResult) {
	blobPath := filepath.Join(config.SourcePath, "blob_storage")
	outputDir := filepath.Join(config.OutputPath, "blob_storage")
	_ = os.MkdirAll(outputDir, 0755)

	_ = filepath.Walk(blobPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		relPath, _ := filepath.Rel(blobPath, path)
		destPath := filepath.Join(outputDir, relPath)
		_ = os.MkdirAll(filepath.Dir(destPath), 0755)
		_ = copyFileWithHash(path, destPath, result, "blob")

		return nil
	})
}

func extractCache(config ExtractorConfig, result *ExtractionResult) {
	cachePath := filepath.Join(config.SourcePath, "Cache")
	outputDir := filepath.Join(config.OutputPath, "cache")
	_ = os.MkdirAll(outputDir, 0755)

	_ = filepath.Walk(cachePath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		relPath, _ := filepath.Rel(cachePath, path)
		destPath := filepath.Join(outputDir, relPath)
		_ = os.MkdirAll(filepath.Dir(destPath), 0755)
		_ = copyFileWithHash(path, destPath, result, "cache")

		return nil
	})
}

func extractCodeCache(config ExtractorConfig, result *ExtractionResult) {
	codeCachePath := filepath.Join(config.SourcePath, "Code Cache")
	outputDir := filepath.Join(config.OutputPath, "code_cache")
	_ = os.MkdirAll(outputDir, 0755)

	_ = filepath.Walk(codeCachePath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		relPath, _ := filepath.Rel(codeCachePath, path)
		destPath := filepath.Join(outputDir, relPath)
		_ = os.MkdirAll(filepath.Dir(destPath), 0755)
		_ = copyFileWithHash(path, destPath, result, "code_cache")

		return nil
	})
}

func extractLocalStorage(config ExtractorConfig, result *ExtractionResult) {
	lsPath := filepath.Join(config.SourcePath, "Local Storage", "leveldb")
	outputDir := filepath.Join(config.OutputPath, "local_storage")
	_ = os.MkdirAll(outputDir, 0755)

	_ = filepath.Walk(lsPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		relPath, _ := filepath.Rel(lsPath, path)
		destPath := filepath.Join(outputDir, relPath)
		_ = os.MkdirAll(filepath.Dir(destPath), 0755)
		_ = copyFileWithHash(path, destPath, result, "local_storage")

		if strings.HasSuffix(path, ".log") || strings.HasSuffix(path, ".ldb") {
			extractStringsFromFile(path, result)
		}

		return nil
	})
}

func extractIndexedDB(config ExtractorConfig, result *ExtractionResult) {
	idbPath := filepath.Join(config.SourcePath, "IndexedDB")
	outputDir := filepath.Join(config.OutputPath, "indexeddb")
	_ = os.MkdirAll(outputDir, 0755)

	_ = filepath.Walk(idbPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		relPath, _ := filepath.Rel(idbPath, path)
		destPath := filepath.Join(outputDir, relPath)
		_ = os.MkdirAll(filepath.Dir(destPath), 0755)
		_ = copyFileWithHash(path, destPath, result, "indexeddb")

		return nil
	})
}

// ExtractDatabases finds and extracts all SQLite databases.
func ExtractDatabases(config ExtractorConfig, result *ExtractionResult) {
	outputDir := filepath.Join(config.OutputPath, "databases")
	_ = os.MkdirAll(outputDir, 0755)

	var dbFiles []string

	_ = filepath.Walk(config.SourcePath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		if strings.HasSuffix(path, ".db") ||
			strings.HasSuffix(path, ".sqlite") ||
			strings.HasSuffix(path, ".sqlite3") ||
			info.Name() == "Cookies" ||
			info.Name() == "History" ||
			info.Name() == "Web Data" ||
			info.Name() == "DIPS" {
			dbFiles = append(dbFiles, path)
		}

		return nil
	})

	for _, dbPath := range dbFiles {
		destPath := filepath.Join(outputDir, filepath.Base(dbPath))
		_ = copyFileWithHash(dbPath, destPath, result, "database")

		walPath := dbPath + "-wal"
		if _, err := os.Stat(walPath); err == nil {
			_ = copyFileWithHash(walPath, destPath+"-wal", result, "database_wal")
		}

		dbInfo := extractDatabaseInfo(dbPath)
		if dbInfo != nil {
			result.Databases = append(result.Databases, *dbInfo)

			dumpDatabaseToJSON(dbPath, filepath.Join(outputDir, filepath.Base(dbPath)+".json"))
		}
	}
}

func extractSessionStorage(config ExtractorConfig, result *ExtractionResult) {
	ssPath := filepath.Join(config.SourcePath, "Session Storage")
	outputDir := filepath.Join(config.OutputPath, "session_storage")
	_ = os.MkdirAll(outputDir, 0755)

	_ = filepath.Walk(ssPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		relPath, _ := filepath.Rel(ssPath, path)
		destPath := filepath.Join(outputDir, relPath)
		_ = os.MkdirAll(filepath.Dir(destPath), 0755)
		_ = copyFileWithHash(path, destPath, result, "session_storage")

		return nil
	})
}

func extractNetworkData(config ExtractorConfig, result *ExtractionResult) {
	netPath := filepath.Join(config.SourcePath, "Network")
	outputDir := filepath.Join(config.OutputPath, "network")
	_ = os.MkdirAll(outputDir, 0755)

	_ = filepath.Walk(netPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		relPath, _ := filepath.Rel(netPath, path)
		destPath := filepath.Join(outputDir, relPath)
		_ = os.MkdirAll(filepath.Dir(destPath), 0755)
		_ = copyFileWithHash(path, destPath, result, "network")

		return nil
	})

	cookiesPath := filepath.Join(netPath, "Cookies")
	if _, err := os.Stat(cookiesPath); err == nil {
		ExtractCookies(cookiesPath, result)
	}
}

func extractConfigFiles(config ExtractorConfig, result *ExtractionResult) {
	outputDir := filepath.Join(config.OutputPath, "config")
	_ = os.MkdirAll(outputDir, 0755)

	configFiles := []string{
		"Local State", "Preferences", "settings.json", "config.json", ".updaterId",
	}

	for _, configFile := range configFiles {
		srcPath := filepath.Join(config.SourcePath, configFile)
		if info, err := os.Stat(srcPath); err == nil && !info.IsDir() {
			destPath := filepath.Join(outputDir, configFile)
			_ = copyFileWithHash(srcPath, destPath, result, "config")
		}
	}

	sentryPath := filepath.Join(config.SourcePath, "sentry")
	if info, err := os.Stat(sentryPath); err == nil && info.IsDir() {
		sentryOutput := filepath.Join(outputDir, "sentry")
		_ = os.MkdirAll(sentryOutput, 0755)
		_ = filepath.Walk(sentryPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}

			relPath, _ := filepath.Rel(sentryPath, path)
			destPath := filepath.Join(sentryOutput, relPath)
			_ = os.MkdirAll(filepath.Dir(destPath), 0755)
			_ = copyFileWithHash(path, destPath, result, "sentry")

			return nil
		})
	}
}

func extractDatabaseInfo(dbPath string) *DatabaseInfo {
	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		return nil
	}

	defer func() { _ = db.Close() }()

	info := &DatabaseInfo{
		Name:   filepath.Base(dbPath),
		Path:   dbPath,
		Tables: []string{},
	}

	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table'")
	if err != nil {
		return info
	}

	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var tableName string
		if rows.Scan(&tableName) == nil {
			info.Tables = append(info.Tables, tableName)

			var count int

			countRow := db.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM "%s"`, quoteSQLiteIdent(tableName)))
			if countRow.Scan(&count) == nil {
				info.Records += count
			}
		}
	}

	return info
}

func dumpDatabaseToJSON(dbPath, outputPath string) {
	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		return
	}

	defer func() { _ = db.Close() }()

	result := make(map[string][]map[string]any)

	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table'")
	if err != nil {
		return
	}

	var tables []string

	for rows.Next() {
		var name string

		_ = rows.Scan(&name)
		tables = append(tables, name)
	}

	_ = rows.Close()

	for _, table := range tables {
		tableRows, err := db.Query(fmt.Sprintf(`SELECT * FROM "%s" LIMIT 1000`, quoteSQLiteIdent(table)))
		if err != nil {
			continue
		}

		columns, _ := tableRows.Columns()
		values := make([]any, len(columns))

		valuePtrs := make([]any, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		var records []map[string]any

		for tableRows.Next() {
			_ = tableRows.Scan(valuePtrs...)
			record := make(map[string]any)

			for i, col := range columns {
				val := values[i]
				if b, ok := val.([]byte); ok {
					record[col] = string(b)
				} else {
					record[col] = val
				}
			}

			records = append(records, record)
		}

		_ = tableRows.Close()
		result[table] = records
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	_ = os.WriteFile(outputPath, data, 0644)
}

// ExtractCookies extracts cookie entries from a Cookies database.
func ExtractCookies(cookiesPath string, result *ExtractionResult) {
	db, err := sql.Open("sqlite", cookiesPath+"?mode=ro")
	if err != nil {
		return
	}

	defer func() { _ = db.Close() }()

	rows, err := db.Query(`
		SELECT host_key, name, path, expires_utc, is_secure, is_httponly, creation_utc
		FROM cookies LIMIT 100
	`)
	if err != nil {
		return
	}

	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			cookie               CookieInfo
			isSecure, isHTTPOnly int
		)

		_ = rows.Scan(&cookie.Domain, &cookie.Name, &cookie.Path, &cookie.ExpiresUTC,
			&isSecure, &isHTTPOnly, &cookie.CreationUTC)
		cookie.IsSecure = isSecure == 1
		cookie.IsHTTPOnly = isHTTPOnly == 1
		result.Cookies = append(result.Cookies, cookie)
	}
}

func extractStringsFromFile(path string, result *ExtractionResult) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	var currentString []byte

	for _, b := range data {
		if b >= 32 && b < 127 {
			currentString = append(currentString, b)
		} else {
			if len(currentString) > 10 {
				str := string(currentString)
				if strings.Contains(str, "http") ||
					strings.Contains(str, "api") ||
					strings.Contains(str, "key") ||
					strings.Contains(str, "token") {
					if result.LocalStorage == nil {
						result.LocalStorage = make(map[string]string)
					}

					key := fmt.Sprintf("string_%d", len(result.LocalStorage))
					result.LocalStorage[key] = str
				}
			}

			currentString = nil
		}
	}
}

func copyFileWithHash(src, dst string, result *ExtractionResult, fileType string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}

	defer func() { _ = srcFile.Close() }()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}

	defer func() { _ = dstFile.Close() }()

	hash := sha256.New()
	writer := io.MultiWriter(dstFile, hash)

	size, err := io.Copy(writer, srcFile)
	if err != nil {
		return err
	}

	result.Files = append(result.Files, ExtractedFile{
		OriginalPath: src,
		OutputPath:   dst,
		Size:         size,
		SHA256:       hex.EncodeToString(hash.Sum(nil)),
		Type:         fileType,
	})

	result.TotalSize += size
	result.FileCount++

	return nil
}
