package snapshot

import (
	"path/filepath"
	"testing"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestOpenDB(t *testing.T) {
	db := openTestDB(t)
	if db == nil {
		t.Fatal("db is nil")
	}
}

func TestOpenDB_CreatesParentDir(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "nested", "dir", "test.db")
	db, err := OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB nested: %v", err)
	}
	_ = db.Close()
}

func TestSaveManifest(t *testing.T) {
	db := openTestDB(t)
	err := db.SaveManifest("ext1", "Test Ext", "1.0.0", []byte(`{"name":"Test Ext"}`), []string{"tabs", "storage"})
	if err != nil {
		t.Fatalf("SaveManifest: %v", err)
	}
	// Upsert should work
	err = db.SaveManifest("ext1", "Test Ext v2", "2.0.0", []byte(`{"name":"Test Ext v2"}`), []string{"tabs"})
	if err != nil {
		t.Fatalf("SaveManifest upsert: %v", err)
	}
}

func TestCreateSnapshot(t *testing.T) {
	db := openTestDB(t)
	id, err := db.CreateSnapshot("amazon-us", "https://amazon.com/dp/123", "Product Page", 1500)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if id <= 0 {
		t.Errorf("expected positive id, got %d", id)
	}
	// Create another
	id2, err := db.CreateSnapshot("walmart", "https://walmart.com/ip/456", "Walmart", 2000)
	if err != nil {
		t.Fatal(err)
	}
	if id2 <= id {
		t.Errorf("expected id2 > id, got %d <= %d", id2, id)
	}
}

func TestSaveDOMElements(t *testing.T) {
	db := openTestDB(t)
	snapID, _ := db.CreateSnapshot("test", "https://test.com", "Test", 100)

	elements := []DOMElement{
		{Selector: "#honey", HTML: "<div id='honey'>coupon</div>", TagName: "div", ClassList: "honey"},
		{Selector: ".keepa", HTML: "<span class='keepa'>chart</span>", TagName: "span"},
	}
	if err := db.SaveDOMElements(snapID, elements); err != nil {
		t.Fatalf("SaveDOMElements: %v", err)
	}
}

func TestSaveDOMElements_Empty(t *testing.T) {
	db := openTestDB(t)
	snapID, _ := db.CreateSnapshot("test", "https://test.com", "Test", 100)
	if err := db.SaveDOMElements(snapID, nil); err != nil {
		t.Fatalf("SaveDOMElements empty: %v", err)
	}
}

func TestSaveStorageData(t *testing.T) {
	db := openTestDB(t)
	snapID, _ := db.CreateSnapshot("test", "https://test.com", "Test", 100)

	entries := []StorageEntry{
		{StorageType: "localStorage", Key: "honey_user", Value: "abc123"},
		{StorageType: "cookie", Key: "session", Value: "xyz"},
	}
	if err := db.SaveStorageData(snapID, entries); err != nil {
		t.Fatalf("SaveStorageData: %v", err)
	}
}

func TestSaveNetworkEntries(t *testing.T) {
	db := openTestDB(t)
	snapID, _ := db.CreateSnapshot("test", "https://test.com", "Test", 100)

	entries := []NetworkEntry{
		{Method: "GET", URL: "https://api.honey.io/v1/coupons", Status: 200, ContentType: "application/json", ResponseSize: 1024},
		{Method: "POST", URL: "https://tracking.example.com/pixel", Status: 204},
	}
	if err := db.SaveNetworkEntries(snapID, entries); err != nil {
		t.Fatalf("SaveNetworkEntries: %v", err)
	}
}

func TestSaveScreenshot(t *testing.T) {
	db := openTestDB(t)
	snapID, _ := db.CreateSnapshot("test", "https://test.com", "Test", 100)

	png := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A} // PNG header
	if err := db.SaveScreenshot(snapID, png); err != nil {
		t.Fatalf("SaveScreenshot: %v", err)
	}
}

func TestSaveAndGetSourceURLs(t *testing.T) {
	db := openTestDB(t)

	urls := []SourceURL{
		{ExtensionID: "ext1", URL: "https://api.honey.io/v1/coupons", Host: "api.honey.io", Category: "api", SourceFile: "background.js", SourceType: "regex"},
		{ExtensionID: "ext1", URL: "https://tracking.example.com/pixel", Host: "tracking.example.com", Category: "tracking", SourceFile: "content.js", SourceType: "regex"},
		{ExtensionID: "ext2", URL: "https://other.com/api", Host: "other.com", Category: "api", SourceType: "regex"},
	}
	if err := db.SaveSourceURLs(urls); err != nil {
		t.Fatalf("SaveSourceURLs: %v", err)
	}

	got, err := db.GetSourceURLs("ext1")
	if err != nil {
		t.Fatalf("GetSourceURLs: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 URLs for ext1, got %d", len(got))
	}
	if got[0].URL != "https://api.honey.io/v1/coupons" {
		t.Errorf("unexpected URL: %s", got[0].URL)
	}
}

func TestSaveSourceURLs_Dedup(t *testing.T) {
	db := openTestDB(t)

	url := SourceURL{ExtensionID: "ext1", URL: "https://api.test.com", Host: "api.test.com", Category: "api", SourceType: "regex"}
	if err := db.SaveSourceURLs([]SourceURL{url}); err != nil {
		t.Fatal(err)
	}
	// Insert same again — should be ignored (INSERT OR IGNORE)
	if err := db.SaveSourceURLs([]SourceURL{url}); err != nil {
		t.Fatal(err)
	}
	got, _ := db.GetSourceURLs("ext1")
	if len(got) != 1 {
		t.Errorf("expected dedup to 1, got %d", len(got))
	}
}

func TestGetSourceURLs_Empty(t *testing.T) {
	db := openTestDB(t)
	got, err := db.GetSourceURLs("nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
}

func TestSaveURLMappings(t *testing.T) {
	db := openTestDB(t)
	snapID, _ := db.CreateSnapshot("test", "https://test.com", "Test", 100)

	mappings := []URLMapping{
		{ExtensionID: "ext1", SnapshotID: snapID, SourceURL: "https://api.honey.io/v1", HARURL: "https://api.honey.io/v1/coupons?store=amazon", MatchType: "host_path", HARMethod: "GET", HARStatus: 200, HARContentType: "application/json", HARResponseSize: 2048},
	}
	if err := db.SaveURLMappings(mappings); err != nil {
		t.Fatalf("SaveURLMappings: %v", err)
	}
}
