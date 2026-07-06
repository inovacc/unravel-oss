package goversions

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

// Sync fetches all sources and upserts them. `now` is epoch-ms (injected for tests).
func Sync(ctx context.Context, db *sql.DB, src Sources, now int64) (SyncReport, error) {
	var rep SyncReport
	rels, err := src.Downloads(ctx)
	if err != nil {
		return rep, fmt.Errorf("downloads: %w", err)
	}
	meta, err := src.ReleaseMeta(ctx)
	if err != nil {
		rep.Errors = append(rep.Errors, "release-meta: "+err.Error())
	}
	vulns, err := src.Vulns(ctx)
	if err != nil {
		rep.Errors = append(rep.Errors, "vulns: "+err.Error())
	}

	for _, r := range rels {
		m := meta[r.Version]
		var inserted bool
		err := db.QueryRowContext(ctx, `
			INSERT INTO go_releases (version, stable, release_date, security_summary, first_seen_at, last_seen_at)
			VALUES ($1,$2,$3,$4,$5,$5)
			ON CONFLICT (version) DO UPDATE SET
				stable=excluded.stable,
				release_date=COALESCE(excluded.release_date, go_releases.release_date),
				security_summary=COALESCE(NULLIF(excluded.security_summary,''), go_releases.security_summary),
				last_seen_at=excluded.last_seen_at
			RETURNING (xmax = 0)`, r.Version, r.Stable, nullDate(m.Date), nullStr(m.Security), now).Scan(&inserted)
		if err != nil {
			rep.Errors = append(rep.Errors, "release "+r.Version+": "+err.Error())
			continue
		}
		if inserted {
			rep.NewVersions = append(rep.NewVersions, r.Version)
		}
		rep.Releases++
		for _, f := range r.Files {
			if _, err := db.ExecContext(ctx, `
				INSERT INTO go_release_files (version, filename, os, arch, kind, sha256, size)
				VALUES ($1,$2,$3,$4,$5,$6,$7)
				ON CONFLICT (version, filename) DO UPDATE SET
					os=excluded.os, arch=excluded.arch, kind=excluded.kind, sha256=excluded.sha256, size=excluded.size`,
				r.Version, f.Filename, f.OS, f.Arch, f.Kind, f.SHA256, f.Size); err != nil {
				rep.Errors = append(rep.Errors, "file "+f.Filename+": "+err.Error())
			} else {
				rep.Files++
			}
		}
	}

	for _, v := range vulns {
		var inserted bool
		if err := db.QueryRowContext(ctx, `
			INSERT INTO go_vulns (id, summary)
			VALUES ($1,$2)
			ON CONFLICT (id) DO UPDATE SET summary=excluded.summary
			RETURNING (xmax = 0)`,
			v.ID, v.Summary).Scan(&inserted); err != nil {
			rep.Errors = append(rep.Errors, "vuln "+v.ID+": "+err.Error())
			continue
		}
		if inserted {
			rep.NewVulns = append(rep.NewVulns, v.ID)
		}
		rep.Vulns++
		// Replace affected ranges with delete-then-insert. go_vuln_affected has
		// no unique constraint (a vuln may have several ranges), so a plain
		// insert after clearing the prior set keeps re-syncs idempotent.
		if _, derr := db.ExecContext(ctx, `DELETE FROM go_vuln_affected WHERE vuln_id=$1`, v.ID); derr != nil {
			rep.Errors = append(rep.Errors, "vuln-affected del "+v.ID+": "+derr.Error())
			continue
		}
		for _, ar := range v.Affected {
			intro := ar.Introduced
			if intro == "" {
				intro = "0"
			}
			if _, err := db.ExecContext(ctx, `
				INSERT INTO go_vuln_affected (vuln_id, component, introduced, fixed)
				VALUES ($1,$2,$3,$4)`,
				v.ID, ar.Component, intro, nullStr(ar.Fixed)); err != nil {
				rep.Errors = append(rep.Errors, "vuln-affected "+v.ID+": "+err.Error())
			}
		}
	}

	upsertSyncState(ctx, db, "dl", now, rep.Releases)
	upsertSyncState(ctx, db, "vuln", now, rep.Vulns)
	return rep, nil
}

func upsertSyncState(ctx context.Context, db *sql.DB, source string, now int64, count int) {
	_, _ = db.ExecContext(ctx, `
		INSERT INTO go_sync_state (source, last_sync_at, item_count) VALUES ($1,$2,$3)
		ON CONFLICT (source) DO UPDATE SET last_sync_at=excluded.last_sync_at, item_count=excluded.item_count`,
		source, now, count)
}

func nullDate(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// VerifyArtifact returns the release+filename owning a given sha256, if any.
func VerifyArtifact(db *sql.DB, sha256 string) (version, filename string, ok bool, err error) {
	row := db.QueryRow(`SELECT version, filename FROM go_release_files WHERE sha256=$1 LIMIT 1`, sha256)
	switch err = row.Scan(&version, &filename); err {
	case nil:
		return version, filename, true, nil
	case sql.ErrNoRows:
		return "", "", false, nil
	default:
		return "", "", false, err
	}
}

// ReleaseInfo returns a release row + its files.
func ReleaseInfo(db *sql.DB, version string) (Release, ReleaseMeta, []File, error) {
	var rel Release
	var meta ReleaseMeta
	rel.Version = version
	var date sql.NullString
	var sec sql.NullString
	err := db.QueryRow(`SELECT stable, release_date::text, security_summary FROM go_releases WHERE version=$1`, version).
		Scan(&rel.Stable, &date, &sec)
	if err != nil {
		return rel, meta, nil, err
	}
	meta.Date, meta.Security = date.String, sec.String
	rows, err := db.Query(`SELECT filename, os, arch, kind, sha256, size FROM go_release_files WHERE version=$1 ORDER BY filename`, version)
	if err != nil {
		return rel, meta, nil, err
	}
	defer func() { _ = rows.Close() }()
	var files []File
	for rows.Next() {
		var f File
		f.Version = version
		if err := rows.Scan(&f.Filename, &f.OS, &f.Arch, &f.Kind, &f.SHA256, &f.Size); err != nil {
			return rel, meta, files, err
		}
		files = append(files, f)
	}
	return rel, meta, files, rows.Err()
}

// ListReleases returns versions (optionally stable-only) newest-first.
func ListReleases(db *sql.DB, stableOnly bool, limit int) ([]Release, error) {
	q := `SELECT version, stable FROM go_releases`
	if stableOnly {
		q += ` WHERE stable = true`
	}
	q += ` ORDER BY first_seen_at DESC`
	if limit > 0 {
		q += fmt.Sprintf(` LIMIT %d`, limit)
	}
	rows, err := db.Query(q)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Release
	for rows.Next() {
		var r Release
		if err := rows.Scan(&r.Version, &r.Stable); err != nil {
			return out, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// loadVulns reads all vulns + ranges for posture computation.
func loadVulns(db *sql.DB) ([]Vuln, error) {
	rows, err := db.Query(`
		SELECT v.id, v.summary, a.component, a.introduced, a.fixed
		FROM go_vulns v JOIN go_vuln_affected a ON a.vuln_id = v.id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	byID := map[string]*Vuln{}
	var order []string
	for rows.Next() {
		var id, summary, comp, intro string
		var fixed sql.NullString
		if err := rows.Scan(&id, &summary, &comp, &intro, &fixed); err != nil {
			return nil, err
		}
		v, ok := byID[id]
		if !ok {
			v = &Vuln{ID: id, Summary: summary}
			byID[id] = v
			order = append(order, id)
		}
		v.Affected = append(v.Affected, AffectedRange{Component: comp, Introduced: intro, Fixed: fixed.String})
	}
	out := make([]Vuln, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out, rows.Err()
}

// CVEPostureFor computes the CVE posture of a stored version.
func CVEPostureFor(db *sql.DB, version string) (CVEPosture, error) {
	vulns, err := loadVulns(db)
	if err != nil {
		return CVEPosture{}, err
	}
	return Posture(version, vulns), nil
}

// Freshness returns the oldest sync timestamp (epoch ms); 0 if never synced.
func Freshness(db *sql.DB) (int64, error) {
	var ts sql.NullInt64
	err := db.QueryRow(`SELECT MIN(last_sync_at) FROM go_sync_state`).Scan(&ts)
	if err != nil {
		return 0, err
	}
	if !ts.Valid {
		return 0, nil
	}
	return ts.Int64, nil
}
