/*
Copyright (c) 2026 Security Research
*/
package store

import (
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// ReconcileReport summarizes a Reconcile run.
type ReconcileReport struct {
	Migrated       int   // flat entries moved into the sharded layout
	SizeBackfilled int   // entries whose Size was 0 and got stat-summed
	OrphansGC      int   // unindexed strays removed
	BytesReclaimed int64 // bytes freed by orphan GC
}

// Reconcile migrates a legacy flat cache to the sharded layout and reclaims
// orphans, using the default orphan grace. Idempotent: a second run on an
// already-sharded store is a no-op. When dryRun is true, nothing is changed
// and the report reflects what would change.
func (s *Store) Reconcile(dryRun bool) (ReconcileReport, error) {
	return s.reconcileWithGrace(DefaultOrphanGrace, dryRun)
}

// reconcileWithGrace is the body of Reconcile with an explicit orphan grace
// (tests pass 0). It acquires s.mu and calls gcOrphansLocked.
func (s *Store) reconcileWithGrace(grace time.Duration, dryRun bool) (ReconcileReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var rep ReconcileReport
	index, err := s.readIndex()
	if err != nil {
		return rep, err
	}

	// Reclaim orphans FIRST so a read failure aborts before any migration —
	// nothing is left half-moved. Orphans (dirs not in the index) are disjoint
	// from indexed entries, so GC order does not change which dirs survive.
	n, freed, gcErr := s.gcOrphansLocked(grace, dryRun)
	if gcErr != nil {
		return rep, gcErr
	}
	rep.OrphansGC = n
	rep.BytesReclaimed = freed

	for i := range index.Entries {
		e := &index.Entries[i]
		want := filepath.Join(s.baseDir, shardFor(e.ID), e.ID)

		// Move mis-located (flat) indexed entries into the sharded layout.
		if e.CacheDir != want && e.CacheDir != "" {
			oldDir := e.CacheDir
			_, srcErr := os.Stat(oldDir)
			_, destErr := os.Stat(want)
			srcExists := srcErr == nil
			destExists := destErr == nil

			switch {
			case destExists:
				// A prior interrupted run already placed this entry at the
				// sharded path. Adopt it; drop any stale flat duplicate.
				if !dryRun {
					e.CacheDir = want
					if srcExists {
						_ = os.RemoveAll(oldDir)
					}
				}
				rep.Migrated++
			case srcExists:
				if dryRun {
					rep.Migrated++
					break
				}
				// Best-effort per the spec: a per-entry failure is logged and
				// skipped, never fatal — one bad entry must not abort the run.
				if mkErr := os.MkdirAll(filepath.Dir(want), 0o755); mkErr != nil {
					slog.Warn("reconcile: mkdir shard failed; skipping entry", "id", e.ID, "err", mkErr)
					break
				}
				if mvErr := os.Rename(oldDir, want); mvErr != nil {
					slog.Warn("reconcile: move failed; skipping entry", "id", e.ID, "err", mvErr)
					break
				}
				e.CacheDir = want
				rep.Migrated++
			default:
				// Neither src nor dest exists — the entry's data is gone; leave
				// the index record untouched.
			}
		}

		// Backfill Size for version-1 entries (Size == 0).
		if e.Size == 0 {
			if sz := dirSize(e.CacheDir); sz > 0 {
				if !dryRun {
					e.Size = sz
				}
				rep.SizeBackfilled++
			}
		}
	}

	if !dryRun {
		index.Version = IndexVersionSharded
		index.UpdatedAt = time.Now().UTC()
		if err := s.writeIndex(index); err != nil {
			return rep, err
		}
	}

	return rep, nil
}
