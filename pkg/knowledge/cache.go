/*
Copyright (c) 2026 Security Research
*/
package knowledge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/inovacc/unravel-oss/pkg/store"
)

// payloadSizeCap bounds beautify cache payloads. Anything above this is
// treated as a degenerate input (T-07-06 layered defense): the orchestrator
// already bails out before invoking MCP for inputs >10 MiB; the cache
// layer rejects writes >50 MiB so a misbehaving track can never bloat the
// on-disk cache.
const payloadSizeCap = 50 << 20 // 50 MiB

// payloadFile is the file name for the cached beautified payload inside
// the per-entry cache directory.
const payloadFile = "payload.bin"

// errPayloadTooLarge signals that a beautify result exceeds payloadSizeCap.
var errPayloadTooLarge = errors.New("knowledge: beautify payload exceeds cache size cap")

// computeSourceHash returns the canonical SHA-256 (hex) of content. The
// cache key is the (hash, type) tuple; see Pitfall 4 in 07-RESEARCH.md
// for why omitting Type would be unsafe.
func computeSourceHash(content []byte) string {
	h := sha256.Sum256(content)
	return hex.EncodeToString(h[:])
}

// beautifyCacheLookup searches s for an entry matching the (hash, typ)
// tuple and returns the cached payload bytes. A miss is reported as
// (nil, false, nil) — never as an error — so callers can branch on hit/miss
// without unwrapping.
//
// Type vocabulary (D-13):
//
//	"beautify-java"   pkg/java/beautify outputs
//	"beautify-js"     pkg/jsdeob beautify outputs (bundle is JS-internal, D-17)
//	"beautify-bundle" pkg/jsdeob/bundle.Reconstruct intermediate (optional)
//	"beautify-csharp" pkg/dotnet/decompile outputs
func beautifyCacheLookup(s *store.Store, hash, typ string) ([]byte, bool, error) {
	if s == nil {
		return nil, false, errors.New("knowledge: nil store")
	}
	if hash == "" || typ == "" {
		return nil, false, errors.New("knowledge: empty hash or type")
	}
	entries, err := s.List()
	if err != nil {
		return nil, false, fmt.Errorf("list cache: %w", err)
	}
	for _, e := range entries {
		if e.SourceHash == hash && e.Type == typ {
			data, err := os.ReadFile(filepath.Join(e.CacheDir, payloadFile))
			if err != nil {
				// Treat unreadable cached file as a miss — caller will
				// regenerate. We do not surface the error so a corrupt
				// cache entry never blocks beautify.
				return nil, false, nil
			}
			return data, true, nil
		}
	}
	return nil, false, nil
}

// beautifyCachePut writes payload to the cache under the (hash, typ) key.
// The store's Put implementation hashes the on-disk source path; we
// override the resulting Entry's SourceHash field by re-storing the
// payload alongside an explicit Entry record so the lookup tuple is
// honored.
func beautifyCachePut(s *store.Store, hash, typ, sourcePath string, payload []byte) error {
	if s == nil {
		return errors.New("knowledge: nil store")
	}
	if hash == "" || typ == "" {
		return errors.New("knowledge: empty hash or type")
	}
	if len(payload) > payloadSizeCap {
		return fmt.Errorf("%w: %d > %d", errPayloadTooLarge, len(payload), payloadSizeCap)
	}

	entry, err := s.Put(sourcePath, typ, nil, map[string][]byte{payloadFile: payload})
	if err != nil {
		return fmt.Errorf("store put: %w", err)
	}
	// store.Put hashes the on-disk source path which may not exist (eg. a
	// virtual path inside an APK). Force the canonical content hash so
	// lookups by (hash, type) succeed.
	if entry.SourceHash != hash {
		if err := overrideEntryHash(s, entry.ID, hash); err != nil {
			return fmt.Errorf("override entry hash: %w", err)
		}
	}

	// Rewrite the cached payload via the atomic helper. store.Put already
	// wrote the file with an O_CREATE/WRITE; the rewrite is intentional so
	// we obtain the temp+rename guarantee writeFileAtomic provides
	// (T-07-01 layered defense + atomicity for partial-read avoidance).
	target := filepath.Join(entry.CacheDir, payloadFile)
	if err := writeFileAtomic(target, payload, 0o644); err != nil {
		return fmt.Errorf("atomic payload write: %w", err)
	}
	return nil
}

// overrideEntryHash patches the in-index SourceHash for an entry. The
// store package does not expose a direct setter; we rebuild the index by
// fetching all entries and forcing this one's hash to the canonical
// content hash.
func overrideEntryHash(s *store.Store, id, hash string) error {
	// store.Get returns a pointer-to-slice-element which is read-only from
	// the public API; instead we read all entries, mutate locally, and
	// rely on the next Put to surface the updated hash. For test purposes
	// the lookup tuple is satisfied because beautifyCacheLookup iterates
	// the live List() output. We persist the hash by re-serializing the
	// index via a thin wrapper here.
	entries, err := s.List()
	if err != nil {
		return err
	}
	for i := range entries {
		if entries[i].ID == id {
			entries[i].SourceHash = hash
			return rewriteIndex(s, entries)
		}
	}
	return fmt.Errorf("entry %s not found", id)
}

// rewriteIndex re-serializes the cache index for s with the given entry list.
// The store package keeps indexPath unexported; reflection is used to read
// it. This is the single point where we cross the package boundary; future
// work may replace it with a Store.UpdateEntries(...) method upstream.
func rewriteIndex(s *store.Store, entries []store.Entry) error {
	v := reflect.ValueOf(s).Elem().FieldByName("indexPath")
	if !v.IsValid() {
		return errors.New("store.Store has no indexPath field")
	}
	indexPath := v.String()
	if indexPath == "" {
		return errors.New("empty indexPath")
	}
	idx := store.Index{
		Version:   1,
		UpdatedAt: time.Now().UTC(),
		Entries:   entries,
	}
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal index: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(indexPath), 0o755); err != nil {
		return fmt.Errorf("mkdir index parent: %w", err)
	}
	return os.WriteFile(indexPath, data, 0o644)
}
