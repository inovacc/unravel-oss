/*
Copyright (c) 2026 Security Research
*/
package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// uuidv7Pattern matches the canonical lowercase 8-4-4-4-12 hex form whose
// 13th hex nibble (version) is 7. newUUIDv7 always emits this shape.
var uuidv7Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// isUUIDv7 reports whether name is a canonical lowercase uuidv7 string.
func isUUIDv7(name string) bool {
	return uuidv7Pattern.MatchString(name)
}

// uuidv7Time extracts the embedded 48-bit big-endian millisecond creation
// timestamp from a uuidv7 string. ok is false if name is not a uuidv7.
func uuidv7Time(name string) (t time.Time, ok bool) {
	if !isUUIDv7(name) {
		return time.Time{}, false
	}

	// Bytes 0-5 (48 bits) = ms since epoch. In the string that is the first 8
	// hex chars plus the 4 hex chars after the first '-' (index 9..12).
	hexTS := name[0:8] + name[9:13]

	var ms int64
	for _, c := range hexTS {
		ms <<= 4
		switch {
		case c >= '0' && c <= '9':
			ms |= int64(c - '0')
		case c >= 'a' && c <= 'f':
			ms |= int64(c-'a') + 10
		}
	}

	return time.UnixMilli(ms).UTC(), true
}

// dirSize sums the byte sizes of all regular files under dir (best-effort).
func dirSize(dir string) int64 {
	var total int64
	_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, e := d.Info(); e == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}

// DefaultOrphanGrace is the minimum age (from the uuidv7-embedded creation
// time) before an unindexed cache dir is eligible for GC. It protects dirs a
// peer process may have just created but not yet committed to the index (the
// CLI and daemon are separate processes with separate in-memory locks).
const DefaultOrphanGrace = time.Hour

// gcOrphans removes entry directories that are NOT referenced by the index,
// but only when the dir name is a uuidv7 older than grace. It handles the
// sharded layout (cache/{xx}/{id}/) and the legacy flat layout (cache/{id}/),
// and never touches the index, bucket dirs, or non-uuid-named paths. When
// dryRun is true nothing is deleted and the count reflects what would be.
func (s *Store) gcOrphans(grace time.Duration, dryRun bool) (removed int, bytesFreed int64, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gcOrphansLocked(grace, dryRun)
}

// gcOrphansLocked is the body of gcOrphans; callers must hold s.mu.
func (s *Store) gcOrphansLocked(grace time.Duration, dryRun bool) (removed int, bytesFreed int64, err error) {
	index, err := s.readIndex()
	if err != nil {
		// Never GC against an index we could not authoritatively load — an
		// empty indexed-set would classify every dir as an orphan and wipe it.
		return 0, 0, err
	}
	indexed := make(map[string]struct{}, len(index.Entries))
	for _, e := range index.Entries {
		indexed[e.ID] = struct{}{}
	}

	cutoff := time.Now().UTC().Add(-grace)

	consider := func(dir, name string) {
		if _, ok := indexed[name]; ok {
			return // tracked — keep
		}
		ts, ok := uuidv7Time(name)
		if !ok {
			return // not a uuidv7 entry dir — never touch
		}
		if ts.After(cutoff) {
			return // within grace — keep
		}
		sz := dirSize(dir)
		if !dryRun {
			if rmErr := os.RemoveAll(dir); rmErr != nil {
				return // best-effort
			}
		}
		removed++
		bytesFreed += sz
	}

	top, rerr := os.ReadDir(s.baseDir)
	if rerr != nil {
		if errors.Is(rerr, os.ErrNotExist) {
			return removed, bytesFreed, nil // no cache dir yet — nothing to GC
		}
		// A failed enumeration must surface, not report a misleading "0 orphans".
		return removed, bytesFreed, fmt.Errorf("read cache base %s: %w", s.baseDir, rerr)
	}
	for _, e := range top {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		full := filepath.Join(s.baseDir, name)

		if isUUIDv7(name) { // legacy flat entry dir
			consider(full, name)
			continue
		}
		if len(name) == 2 { // shard bucket → inspect its children
			sub, _ := os.ReadDir(full)
			for _, c := range sub {
				if c.IsDir() {
					consider(filepath.Join(full, c.Name()), c.Name())
				}
			}
		}
	}

	return removed, bytesFreed, nil
}
