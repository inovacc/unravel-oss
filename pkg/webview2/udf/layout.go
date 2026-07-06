/*
Copyright (c) 2026 Security Research
*/

// Package udf contains WebView2 User Data Folder discovery and profile
// enumeration helpers. Layout constants reflect the Chromium on-disk schema
// (D-02, D-03, FRM-02) and use forward slashes; callers MUST join with
// filepath.Join for cross-platform paths.
package udf

// Chromium / WebView2 directory-layout names. Constants are relative path
// fragments; callers MUST use filepath.Join to compose platform paths.
const (
	// EBWebViewDir is the top-level user-data subfolder WebView2 writes into.
	EBWebViewDir = "EBWebView"
	// DefaultProfileDir is the default Chromium profile directory.
	DefaultProfileDir = "Default"
	// GuestProfileDir is the Guest profile directory (incognito-like).
	GuestProfileDir = "Guest Profile"
	// SystemProfileDir is the System profile directory.
	SystemProfileDir = "System Profile"

	// CacheSubdir is the HTTP cache location under a profile (Simple Cache).
	CacheSubdir = "Cache/Cache_Data"
	// NetworkSubdir holds Network/Cookies and related net-stack state.
	NetworkSubdir = "Network"
	// CookiesFile is the SQLite Cookies database under Network/.
	CookiesFile = "Cookies"
	// LocalStorageSubdir is the localStorage LevelDB directory.
	LocalStorageSubdir = "Local Storage/leveldb"
	// IndexedDBSubdir is the IndexedDB root (contains <origin>.leveldb dirs).
	IndexedDBSubdir = "IndexedDB"
	// SessionStorageSubdir is the Session Storage LevelDB directory.
	SessionStorageSubdir = "Session Storage"
	// CodeCacheJSSubdir is the V8 compilation-cache directory; Chromium
	// stores the original JS *source* alongside the cached bytecode here.
	CodeCacheJSSubdir = "Code Cache/js"
	// ServiceWorkerScriptCacheSubdir is the service-worker script cache;
	// also retains recoverable JS source (not only V8 bytecode).
	ServiceWorkerScriptCacheSubdir = "Service Worker/ScriptCache"
	// PreferencesFile is the plaintext Preferences JSON file.
	PreferencesFile = "Preferences"
	// SecurePreferencesFile is the DPAPI-wrapped Preferences JSON file.
	SecurePreferencesFile = "Secure Preferences"
	// LocalStateFile is the EBWebView-root-level profile-list state JSON.
	LocalStateFile = "Local State"

	// ProfileNumberedPrefix is the prefix for enumerated profiles.
	ProfileNumberedPrefix = "Profile "
)
