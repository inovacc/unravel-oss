// Package store provides a persistent cache for analysis results.
//
// Data is stored under %LOCALAPPDATA%/Unravel/cache/{uuidv7}/ with a
// top-level cache.json index at %LOCALAPPDATA%/Unravel/cache.json.
package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CacheDir returns the base cache directory: %LOCALAPPDATA%/Unravel/cache
func CacheDir() string {
	local := os.Getenv("LOCALAPPDATA")
	if local == "" {
		if home, err := os.UserHomeDir(); err == nil {
			local = filepath.Join(home, ".local", "share")
		} else {
			local = os.TempDir()
		}
	}

	return filepath.Join(local, "Unravel", "cache")
}

// IndexPath returns the cache index file: %LOCALAPPDATA%/Unravel/cache.json
func IndexPath() string {
	local := os.Getenv("LOCALAPPDATA")
	if local == "" {
		if home, err := os.UserHomeDir(); err == nil {
			local = filepath.Join(home, ".local", "share")
		} else {
			local = os.TempDir()
		}
	}

	return filepath.Join(local, "Unravel", "cache.json")
}

// Entry represents a single cached analysis result in the index.
type Entry struct {
	ID         string            `json:"id"`
	SourcePath string            `json:"source_path"`
	SourceHash string            `json:"source_hash,omitempty"`
	SourceSize int64             `json:"source_size"`
	Size       int64             `json:"size"`
	Type       string            `json:"type"`
	CreatedAt  time.Time         `json:"created_at"`
	Tags       []string          `json:"tags,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	CacheDir   string            `json:"cache_dir"`
}

// IndexVersionSharded marks a cache.json whose entries live under the
// 256-bucket sharded layout (cache/{shard}/{id}/).
const IndexVersionSharded = 2

// Index is the top-level cache.json structure.
type Index struct {
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	Entries   []Entry   `json:"entries"`
}

// Store manages the persistent analysis cache.
type Store struct {
	mu        sync.Mutex
	baseDir   string
	indexPath string
}

// New creates a Store with default paths.
func New() *Store {
	return &Store{
		baseDir:   CacheDir(),
		indexPath: IndexPath(),
	}
}

// NewWithDir creates a Store with a custom base directory.
func NewWithDir(baseDir string) *Store {
	return &Store{
		baseDir:   baseDir,
		indexPath: filepath.Join(filepath.Dir(baseDir), "cache.json"),
	}
}

// Put stores data for a source file and returns the cache entry.
// The data map values are written as files inside the cache entry directory.
func (s *Store) Put(sourcePath, entryType string, tags []string, data map[string][]byte) (*Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := newUUIDv7()

	entryDir := filepath.Join(s.baseDir, shardFor(id), id)
	if err := os.MkdirAll(entryDir, 0o755); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}

	// Write data files; sum their sizes for the size-cap policy (Phase 2).
	var size int64
	for name, content := range data {
		path, err := containedJoin(entryDir, name)
		if err != nil {
			return nil, fmt.Errorf("write %s: %w", name, err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, fmt.Errorf("create subdir for %s: %w", name, err)
		}

		if err := os.WriteFile(path, content, 0o644); err != nil {
			return nil, fmt.Errorf("write %s: %w", name, err)
		}

		size += int64(len(content))
	}

	// Compute source hash
	var sourceHash string
	var sourceSize int64

	if info, err := os.Stat(sourcePath); err == nil {
		sourceSize = info.Size()

		if f, err := os.Open(sourcePath); err == nil {
			h := sha256.New()
			buf := make([]byte, 32*1024)

			for {
				n, readErr := f.Read(buf)
				if n > 0 {
					h.Write(buf[:n])
				}

				if readErr != nil {
					break
				}
			}

			_ = f.Close()
			sourceHash = hex.EncodeToString(h.Sum(nil))
		}
	}

	entry := &Entry{
		ID:         id,
		SourcePath: sourcePath,
		SourceHash: sourceHash,
		SourceSize: sourceSize,
		Size:       size,
		Type:       entryType,
		CreatedAt:  time.Now().UTC(),
		Tags:       tags,
		Metadata:   make(map[string]string),
		CacheDir:   entryDir,
	}

	// Update index. Abort (do not clobber) if the existing index is unreadable.
	index, err := s.readIndex()
	if err != nil {
		return nil, fmt.Errorf("read index: %w", err)
	}
	index.Version = IndexVersionSharded
	index.Entries = append(index.Entries, *entry)
	index.UpdatedAt = time.Now().UTC()

	if err := s.writeIndex(index); err != nil {
		return nil, fmt.Errorf("update index: %w", err)
	}

	return entry, nil
}

// Get returns the cache entry directory for a given ID, or empty if not found.
func (s *Store) Get(id string) (*Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	index, err := s.readIndex()
	if err != nil {
		return nil, err
	}

	for i := range index.Entries {
		if index.Entries[i].ID == id {
			return &index.Entries[i], nil
		}
	}

	return nil, fmt.Errorf("entry not found: %s", id)
}

// Find searches for cached entries matching a source path or hash.
func (s *Store) Find(sourcePath string) []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()

	index, err := s.readIndex()
	if err != nil {
		// Transient/corrupt index → report no matches so the caller re-analyzes
		// rather than acting on a phantom empty cache.
		return nil
	}

	var matches []Entry

	// Compute hash if file exists
	var targetHash string

	if f, err := os.Open(sourcePath); err == nil {
		h := sha256.New()
		buf := make([]byte, 32*1024)

		for {
			n, readErr := f.Read(buf)
			if n > 0 {
				h.Write(buf[:n])
			}

			if readErr != nil {
				break
			}
		}

		_ = f.Close()
		targetHash = hex.EncodeToString(h.Sum(nil))
	}

	absPath, _ := filepath.Abs(sourcePath)

	for _, e := range index.Entries {
		entryAbs, _ := filepath.Abs(e.SourcePath)

		// DSC-06 (13-06): require path equality. A pure content-hash match is
		// not safe because two distinct inputs (e.g. WhatsApp install dir vs.
		// Discord ASAR) can sometimes share content fingerprints, and even when
		// they don't, downstream callers (pkg/dissect) rely on Find as a
		// composite-key lookup. Match a hash only when the abs path also
		// matches; otherwise fall back to abs-path equality alone.
		if entryAbs != absPath {
			continue
		}

		// Same abs path: prefer hash equality when both sides have a hash, else
		// accept the abs-path match.
		if targetHash != "" && e.SourceHash != "" && e.SourceHash != targetHash {
			continue
		}

		matches = append(matches, e)
	}

	return matches
}

// CacheKey returns a stable composite cache key combining the absolute input
// path and the content hash. This is the canonical "what input was analyzed"
// fingerprint and prevents collisions across distinct inputs that happen to
// share content (DSC-06 / 13-06).
func CacheKey(inputPath string, contentHash string) string {
	abs, _ := filepath.Abs(inputPath)
	h := sha256.New()
	h.Write([]byte(abs))
	h.Write([]byte{0})
	h.Write([]byte(contentHash))
	return hex.EncodeToString(h.Sum(nil))
}

// shardFor maps an entry ID to one of 256 hex buckets. It hashes the ID with
// sha256 rather than using the uuidv7 prefix: uuidv7 leads with a 48-bit ms
// timestamp, so its prefix is near-constant over the project's lifetime and
// would collapse almost every entry into a single bucket. Hashing yields a
// uniform spread and is derivable from the ID alone (orphan GC needs that).
func shardFor(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:1])
}

// List returns all cache entries.
func (s *Store) List() ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	index, err := s.readIndex()
	if err != nil {
		return nil, err
	}

	return index.Entries, nil
}

// Delete removes a cache entry by ID.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	index, err := s.readIndex()
	if err != nil {
		return err
	}

	found := false
	filtered := make([]Entry, 0, len(index.Entries))

	for _, e := range index.Entries {
		if e.ID == id {
			found = true
			_ = os.RemoveAll(e.CacheDir)

			continue
		}

		filtered = append(filtered, e)
	}

	if !found {
		return fmt.Errorf("entry not found: %s", id)
	}

	index.Entries = filtered
	index.UpdatedAt = time.Now().UTC()

	return s.writeIndex(index)
}

// Prune removes entries older than maxAge.
func (s *Store) Prune(maxAge time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	index, err := s.readIndex()
	if err != nil {
		return 0, err
	}

	cutoff := time.Now().UTC().Add(-maxAge)
	pruned := 0
	filtered := make([]Entry, 0, len(index.Entries))

	for _, e := range index.Entries {
		if e.CreatedAt.Before(cutoff) {
			_ = os.RemoveAll(e.CacheDir)
			pruned++

			continue
		}

		filtered = append(filtered, e)
	}

	index.Entries = filtered
	index.UpdatedAt = time.Now().UTC()

	if err := s.writeIndex(index); err != nil {
		return pruned, err
	}

	return pruned, nil
}

// ReadFile reads a file from a cache entry directory.
func (s *Store) ReadFile(id, filename string) ([]byte, error) {
	entry, err := s.Get(id)
	if err != nil {
		return nil, err
	}

	path, err := containedJoin(entry.CacheDir, filename)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filename, err)
	}
	return os.ReadFile(path)
}

// reservedDeviceNames are Windows device names that, used as a path component
// (even with an extension, e.g. "nul.txt"), resolve to a device rather than a
// file. Rejected on every OS so a portable store entry cannot target one when
// the hash-keyed store is materialised on Windows.
var reservedDeviceNames = map[string]struct{}{
	"CON": {}, "PRN": {}, "AUX": {}, "NUL": {},
	"COM1": {}, "COM2": {}, "COM3": {}, "COM4": {}, "COM5": {},
	"COM6": {}, "COM7": {}, "COM8": {}, "COM9": {},
	"LPT1": {}, "LPT2": {}, "LPT3": {}, "LPT4": {}, "LPT5": {},
	"LPT6": {}, "LPT7": {}, "LPT8": {}, "LPT9": {},
}

// rejectPortabilityUnsafeName rejects entry-name components that are legal on
// the running OS but dangerous when the hash-keyed, portable store is later
// materialised on Windows: ':' (NTFS alternate-data-stream / drive-letter),
// '\\' (a Windows path separator that filepath.Clean does not normalise on
// POSIX), and reserved device names. It runs on EVERY OS so a Linux-authored
// bundle cannot clobber a sibling entry's primary stream when imported on
// Windows (hardening finding #9 / NTFS-ADS follow-up).
func rejectPortabilityUnsafeName(name string) error {
	if strings.ContainsAny(name, `:\`) {
		return fmt.Errorf("entry name %q contains a path-unsafe character (':' or '\\')", name)
	}
	for _, comp := range strings.Split(name, "/") {
		if comp == "" {
			continue
		}
		base := comp
		if dot := strings.IndexByte(base, '.'); dot >= 0 {
			base = base[:dot]
		}
		if _, bad := reservedDeviceNames[strings.ToUpper(base)]; bad {
			return fmt.Errorf("entry name %q uses a reserved device name (%q)", name, comp)
		}
	}
	return nil
}

// containedJoin joins a caller-supplied entry name onto root and verifies the
// result stays within root, rejecting "..", absolute, and escaping names
// (latent path traversal — hardening finding #9). Nested names like
// "sub/file.json" are permitted (Put deliberately supports nested keys via
// MkdirAll), only escapes are rejected. Mirrors the filepath.Rel containment
// guard used in pkg/asar, pkg/deb, and pkg/dotnet/decompile.
func containedJoin(root, name string) (string, error) {
	if name == "" {
		return "", errors.New("empty entry name")
	}
	if filepath.IsAbs(name) {
		return "", fmt.Errorf("absolute entry name not allowed: %q", name)
	}
	if err := rejectPortabilityUnsafeName(name); err != nil {
		return "", err
	}
	joined := filepath.Join(root, name)
	rel, err := filepath.Rel(root, joined)
	if err != nil {
		return "", fmt.Errorf("entry name %q escapes store root: %w", name, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("entry name %q escapes store root", name)
	}
	return joined, nil
}

// readIndex loads the cache index from disk.
func (s *Store) readIndex() (*Index, error) {
	data, err := os.ReadFile(s.indexPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// First run: no index yet is a legitimately empty cache.
			return &Index{Version: IndexVersionSharded}, nil
		}
		// A genuine read failure (lock / permission / sharing violation) must
		// NOT be masked as an empty index — that would let gcOrphans treat
		// every entry as an orphan and wipe the cache.
		return nil, fmt.Errorf("read cache index %s: %w", s.indexPath, err)
	}

	var index Index
	if err := json.Unmarshal(data, &index); err != nil {
		// Corrupt index: surface it rather than returning a misleading empty
		// index (same mass-delete hazard as above).
		return nil, fmt.Errorf("parse cache index %s (corrupt?): %w", s.indexPath, err)
	}

	return &index, nil
}

// writeIndex writes the cache index to disk atomically (temp file + rename).
// os.Rename is atomic on the same volume (NTFS via MoveFileEx, POSIX rename),
// so a crash or concurrent writer mid-write can never leave a truncated
// cache.json — the failure mode that previously orphaned cache directories.
func (s *Store) writeIndex(index *Index) error {
	if err := os.MkdirAll(filepath.Dir(s.indexPath), 0o755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return err
	}

	tmp := s.indexPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}

	if err := os.Rename(tmp, s.indexPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	return nil
}

// newUUIDv7 generates a UUIDv7 (time-ordered, ms precision).
func newUUIDv7() string {
	now := time.Now().UnixMilli()

	var uuid [16]byte

	// 48-bit timestamp (ms since epoch)
	uuid[0] = byte(now >> 40)
	uuid[1] = byte(now >> 32)
	uuid[2] = byte(now >> 24)
	uuid[3] = byte(now >> 16)
	uuid[4] = byte(now >> 8)
	uuid[5] = byte(now)

	// Version 7 (4 bits)
	uuid[6] = 0x70 | (uuid[6] & 0x0f)

	// Random bits for uniqueness. crypto/rand is cross-platform (BCryptGenRandom
	// on Windows, getrandom/urandom on POSIX) — the old os.Open("/dev/urandom")
	// failed on Windows and silently fell back to the clock, which collides in
	// tight loops and breaks UUID-keyed cache identity.
	rnd := make([]byte, 10)
	if _, err := rand.Read(rnd); err != nil {
		// crypto/rand should never fail on a supported OS; degrade to a
		// clock-seeded fill rather than crash a long-running analysis.
		ns := time.Now().UnixNano()
		for i := range rnd {
			rnd[i] = byte(ns >> (i * 8))
		}
	}

	copy(uuid[6:], rnd[:10])

	// Set version (7) and variant (RFC 4122)
	uuid[6] = (uuid[6] & 0x0f) | 0x70
	uuid[8] = (uuid[8] & 0x3f) | 0x80

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}
