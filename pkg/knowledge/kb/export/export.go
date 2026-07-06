/*
Copyright (c) 2026 Security Research

Export reads KB rows for a given kb_id and writes a deterministic bundle
directory tree (D-43-BUNDLE-DIR-TREE-PLUS-TARGZ). Pack wraps that tree as
<kbID>.kbb.tar.gz for transport. Pure Go — no shell-out to external `tar`.

D-09 inviolate: NO anthropic / claude imports.
*/
package export

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"time"
)

// Querier is the minimal *sql.DB-shaped read surface Export depends on.
// Production passes *sql.DB; tests substitute a fake Loader instead.
type Querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// Loader is the testable seam between Export's bundle-writing logic and the
// underlying database. Production code uses dbLoader{db}; tests substitute
// an in-memory implementation.
//
// Mitigates T-43-04 — non-deterministic marshaling — by making the data
// path deterministic-by-construction in tests.
type Loader interface {
	LoadApp(ctx context.Context, kbID string) (*KbApp, error)
	LoadSources(ctx context.Context, kbID string) ([]Source, error)
	LoadFacts(ctx context.Context, kbID string) ([]Fact, error)
	LoadDiffs(ctx context.Context, kbID string) ([]Diff, error)
}

// KbApp is the exported kb_apps row metadata.
type KbApp struct {
	KbID      string
	Platform  string
	PackageID string
}

// Source is one knowledge_sources row reduced to bundle-relevant columns.
type Source struct {
	Epoch        int64
	SourceSHA256 string
	JSON         json.RawMessage
}

// Fact is one app_facts row.
type Fact struct {
	Epoch    int64
	Category string
	Key      string
	Value    string
}

// Diff is one kb_diffs row.
type Diff struct {
	FromEpoch int64
	ToEpoch   int64
	Payload   json.RawMessage
}

// Export reads the kb_apps row + all knowledge_sources / app_facts / kb_diffs
// rows for the given kbID, writes the D-43-BUNDLE-SCHEMA-V1 directory tree
// under outDir/<kbID>.kbb/, and returns the manifest.
//
// Empty kbID or kbID-not-found returns a descriptive error WITHOUT writing
// any partial bundle.
func Export(ctx context.Context, db Querier, kbID, outDir string) (*BundleManifest, error) {
	if db == nil {
		return nil, errors.New("kb_export: nil db")
	}
	return ExportWithLoader(ctx, &dbLoader{db: db}, kbID, outDir)
}

// ExportWithLoader is the testable bundle-writer. Production callers should
// use Export instead.
func ExportWithLoader(ctx context.Context, ld Loader, kbID, outDir string) (*BundleManifest, error) {
	if kbID == "" {
		return nil, errors.New("kb_export: kb_id is empty")
	}
	if ld == nil {
		return nil, errors.New("kb_export: nil loader")
	}
	if outDir == "" {
		return nil, errors.New("kb_export: outDir is empty")
	}

	app, err := ld.LoadApp(ctx, kbID)
	if err != nil {
		return nil, err
	}
	sources, err := ld.LoadSources(ctx, kbID)
	if err != nil {
		return nil, fmt.Errorf("kb_export: load sources: %w", err)
	}
	facts, err := ld.LoadFacts(ctx, kbID)
	if err != nil {
		return nil, fmt.Errorf("kb_export: load facts: %w", err)
	}
	diffs, err := ld.LoadDiffs(ctx, kbID)
	if err != nil {
		return nil, fmt.Errorf("kb_export: load diffs: %w", err)
	}

	bundleRoot := filepath.Join(outDir, kbID+".kbb")
	if err := os.MkdirAll(bundleRoot, 0o755); err != nil {
		return nil, fmt.Errorf("kb_export: mkdir bundle: %w", err)
	}
	for _, sub := range []string{"knowledge_sources", "app_facts", "kb_diffs"} {
		if err := os.MkdirAll(filepath.Join(bundleRoot, sub), 0o755); err != nil {
			return nil, fmt.Errorf("kb_export: mkdir %s: %w", sub, err)
		}
	}

	// knowledge.json — latest-epoch KnowledgeResult (deterministic).
	knowledgeBytes, err := buildKnowledgeJSON(sources)
	if err != nil {
		return nil, fmt.Errorf("kb_export: build knowledge.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(bundleRoot, "knowledge.json"), knowledgeBytes, 0o644); err != nil {
		return nil, fmt.Errorf("kb_export: write knowledge.json: %w", err)
	}

	// knowledge_sources/<epoch>-<sha>.json (one per row).
	for _, s := range sources {
		name := fmt.Sprintf("%d-%s.json", s.Epoch, shortSHA(s.SourceSHA256))
		canonical, err := canonicalRawJSON(s.JSON)
		if err != nil {
			return nil, fmt.Errorf("kb_export: canonicalize source epoch=%d: %w", s.Epoch, err)
		}
		if err := os.WriteFile(filepath.Join(bundleRoot, "knowledge_sources", name), canonical, 0o644); err != nil {
			return nil, err
		}
	}

	// app_facts/<epoch>.jsonl (one .jsonl per epoch; one row per line).
	if err := writeFactJSONL(bundleRoot, facts); err != nil {
		return nil, err
	}

	// kb_diffs/<from>-<to>.json (one per consecutive-epoch diff).
	for _, d := range diffs {
		name := fmt.Sprintf("%d-%d.json", d.FromEpoch, d.ToEpoch)
		canonical, err := canonicalRawJSON(d.Payload)
		if err != nil {
			return nil, fmt.Errorf("kb_export: canonicalize diff %d->%d: %w", d.FromEpoch, d.ToEpoch, err)
		}
		if err := os.WriteFile(filepath.Join(bundleRoot, "kb_diffs", name), canonical, 0o644); err != nil {
			return nil, err
		}
	}

	// bundle.json — checksum is sha256 over canonicalized knowledge.json.
	sum := sha256.Sum256(knowledgeBytes)
	manifest := &BundleManifest{
		BundleSchemaVersion: BundleSchemaVersion,
		KbID:                app.KbID,
		PackageID:           app.PackageID,
		Platform:            app.Platform,
		ExportedAt:          time.Now().UTC(),
		ExportedBy:          exportedBy(),
		Counts: Counts{
			KnowledgeSources: len(sources),
			AppFacts:         len(facts),
			KbDiffs:          len(diffs),
		},
		Checksum: hex.EncodeToString(sum[:]),
	}
	manifestBytes, err := MarshalManifest(manifest)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(bundleRoot, "bundle.json"), manifestBytes, 0o644); err != nil {
		return nil, err
	}
	return manifest, nil
}

// Pack wraps <outDir>/<kbID>.kbb/ as <outDir>/<kbID>.kbb.tar.gz. Pure Go via
// archive/tar + compress/gzip. Entries are alphabetically sorted; mtime field
// is fixed to bundle.json's ExportedAt to keep tarball bytes deterministic.
func Pack(outDir, kbID string) (string, error) {
	if kbID == "" {
		return "", errors.New("kb_export: kb_id is empty")
	}
	bundleRoot := filepath.Join(outDir, kbID+".kbb")
	manifestPath := filepath.Join(bundleRoot, "bundle.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return "", fmt.Errorf("kb_export: read bundle manifest: %w", err)
	}
	manifest, err := UnmarshalManifest(manifestBytes)
	if err != nil {
		return "", fmt.Errorf("kb_export: parse bundle manifest: %w", err)
	}

	// Collect entries deterministically.
	var entries []string
	if err := filepath.WalkDir(bundleRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(bundleRoot, path)
		if err != nil {
			return err
		}
		entries = append(entries, filepath.ToSlash(rel))
		return nil
	}); err != nil {
		return "", fmt.Errorf("kb_export: walk bundle: %w", err)
	}
	sort.Strings(entries)

	tarballPath := filepath.Join(outDir, kbID+".kbb.tar.gz")
	f, err := os.Create(tarballPath)
	if err != nil {
		return "", fmt.Errorf("kb_export: create tarball: %w", err)
	}
	success := false
	defer func() {
		_ = f.Close()
		if !success {
			_ = os.Remove(tarballPath)
		}
	}()

	gw := gzip.NewWriter(f)
	gw.ModTime = manifest.ExportedAt
	tw := tar.NewWriter(gw)

	for _, rel := range entries {
		full := filepath.Join(bundleRoot, filepath.FromSlash(rel))
		data, err := os.ReadFile(full)
		if err != nil {
			return "", fmt.Errorf("kb_export: read %s: %w", rel, err)
		}
		// Tar slip defense — kbID may not be path-traversal-safe.
		entryName := kbID + ".kbb/" + rel
		if strings.Contains(entryName, "..") || strings.HasPrefix(entryName, "/") {
			return "", fmt.Errorf("kb_export: invalid tar entry %q", entryName)
		}
		hdr := &tar.Header{
			Name:    entryName,
			Mode:    0o644,
			Size:    int64(len(data)),
			ModTime: manifest.ExportedAt,
			Format:  tar.FormatPAX,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return "", fmt.Errorf("kb_export: write header %s: %w", rel, err)
		}
		if _, err := tw.Write(data); err != nil {
			return "", fmt.Errorf("kb_export: write data %s: %w", rel, err)
		}
	}
	if err := tw.Close(); err != nil {
		return "", fmt.Errorf("kb_export: close tar: %w", err)
	}
	if err := gw.Close(); err != nil {
		return "", fmt.Errorf("kb_export: close gzip: %w", err)
	}
	success = true
	return tarballPath, nil
}

// dbLoader implements Loader against a real *sql.DB.
type dbLoader struct{ db Querier }

func (l *dbLoader) LoadApp(ctx context.Context, kbID string) (*KbApp, error) {
	var row KbApp
	var platform, pkg sql.NullString
	err := l.db.QueryRowContext(ctx,
		`SELECT kb_id, COALESCE(platform, ''), COALESCE(package_id, '')
		   FROM kb_apps WHERE kb_id = $1`, kbID).
		Scan(&row.KbID, &platform, &pkg)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("kb_export: kb_id %q not found", kbID)
	}
	if err != nil {
		return nil, fmt.Errorf("kb_export: load kb_apps: %w", err)
	}
	row.Platform = platform.String
	row.PackageID = pkg.String
	return &row, nil
}

// LoadSources projects knowledge_sources rows for kbID into a synthetic
// JSON payload built from real scalar columns. The schema (migrations
// 000002 + 000004) has NO payload column; the bundle's per-source JSON is
// rebuilt from (source_kind, source_path, app_version, source_sha256,
// captured_at, modules_indexed, bodies_indexed, notes, framework,
// risk_score, risk_level, depth_score, binary_sha256) so that round-trip
// import via the bundle preserves provenance.
func (l *dbLoader) LoadSources(ctx context.Context, kbID string) ([]Source, error) {
	rows, err := l.db.QueryContext(ctx,
		`SELECT
		   epoch,
		   COALESCE(source_sha256, ''),
		   COALESCE(source_kind, ''),
		   COALESCE(source_path, ''),
		   COALESCE(app_version, ''),
		   COALESCE(captured_at, 0),
		   COALESCE(modules_indexed, 0),
		   COALESCE(bodies_indexed, 0),
		   COALESCE(notes, ''),
		   COALESCE(framework, ''),
		   COALESCE(risk_score, 0),
		   COALESCE(risk_level, ''),
		   COALESCE(depth_score, 0),
		   COALESCE(binary_sha256, '')
		   FROM knowledge_sources WHERE kb_id = $1 ORDER BY epoch ASC`, kbID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Source
	for rows.Next() {
		var (
			s              Source
			sha, kind, pth sql.NullString
			ver, notes     sql.NullString
			fw, riskLvl    sql.NullString
			binSHA         sql.NullString
			capturedAt     sql.NullInt64
			modules, bod   sql.NullInt64
			riskScore      sql.NullInt64
			depthScore     sql.NullInt64
		)
		if err := rows.Scan(&s.Epoch, &sha, &kind, &pth, &ver, &capturedAt,
			&modules, &bod, &notes, &fw, &riskScore, &riskLvl, &depthScore, &binSHA); err != nil {
			return nil, err
		}
		s.SourceSHA256 = sha.String
		// Synthesize payload from real columns. Keys are sorted by canonicalJSON
		// downstream — order here is irrelevant for byte-determinism.
		payload := map[string]any{
			"epoch":           s.Epoch,
			"source_kind":     kind.String,
			"source_path":     pth.String,
			"app_version":     ver.String,
			"source_sha256":   sha.String,
			"captured_at":     capturedAt.Int64,
			"modules_indexed": modules.Int64,
			"bodies_indexed":  bod.Int64,
			"notes":           notes.String,
			"framework":       fw.String,
			"risk_score":      riskScore.Int64,
			"risk_level":      riskLvl.String,
			"depth_score":     depthScore.Int64,
			"binary_sha256":   binSHA.String,
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("kb_export: synthesize source payload epoch=%d: %w", s.Epoch, err)
		}
		s.JSON = json.RawMessage(raw)
		out = append(out, s)
	}
	return out, rows.Err()
}

// LoadFacts reads app_facts rows for the given kbID. The app_facts table
// has NO kb_id and NO epoch columns — the schema-of-record key is
// app_facts.app, which holds either kb_apps.canonical_name (capture-time
// ingest path) or kb_id directly (D-43 import path). We match both so
// round-trip is symmetric. Epoch is not stored on app_facts; export
// assigns Epoch=0 to all facts and consumers treat them as KB-wide
// (not epoch-scoped). This matches the import contract which discards
// the bundle's per-epoch grouping when calling UpsertFact.
func (l *dbLoader) LoadFacts(ctx context.Context, kbID string) ([]Fact, error) {
	rows, err := l.db.QueryContext(ctx,
		`SELECT 0::bigint AS epoch, category, key, COALESCE(value, '')
		   FROM app_facts
		  WHERE app = $1
		     OR app = (SELECT canonical_name FROM kb_apps WHERE kb_id = $1)
		  ORDER BY category ASC, key ASC`, kbID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Fact
	for rows.Next() {
		var f Fact
		if err := rows.Scan(&f.Epoch, &f.Category, &f.Key, &f.Value); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// LoadDiffs reads kb_diffs rows for the given kbID by joining
// knowledge_sources twice (from_source_id → epoch, to_source_id → epoch)
// and projecting payload. kb_diffs has NO kb_id / from_epoch / to_epoch
// columns — those are derived via the join. Rows whose endpoints belong
// to a different kb_id are excluded by the WHERE clause.
//
// Multiple per-(from,to) rows are collapsed: the first row's payload wins
// (deterministic by stable sort on category/change_type/identifier). This
// mirrors import.go's storage convention (one synthetic row per bundle
// diff with category='import', change_type='added').
func (l *dbLoader) LoadDiffs(ctx context.Context, kbID string) ([]Diff, error) {
	rows, err := l.db.QueryContext(ctx,
		`SELECT ks_from.epoch AS from_epoch,
		        ks_to.epoch   AS to_epoch,
		        d.payload
		   FROM kb_diffs d
		   JOIN knowledge_sources ks_from ON ks_from.id = d.from_source_id
		   JOIN knowledge_sources ks_to   ON ks_to.id   = d.to_source_id
		  WHERE ks_from.kb_id = $1 AND ks_to.kb_id = $1
		  ORDER BY ks_from.epoch ASC, ks_to.epoch ASC,
		           d.category ASC, d.change_type ASC, d.identifier ASC`, kbID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Diff
	seen := map[[2]int64]bool{}
	for rows.Next() {
		var d Diff
		var payload []byte
		if err := rows.Scan(&d.FromEpoch, &d.ToEpoch, &payload); err != nil {
			return nil, err
		}
		key := [2]int64{d.FromEpoch, d.ToEpoch}
		if seen[key] {
			continue
		}
		seen[key] = true
		if len(payload) == 0 {
			payload = []byte("{}")
		}
		d.Payload = append(json.RawMessage(nil), payload...)
		out = append(out, d)
	}
	return out, rows.Err()
}

// buildKnowledgeJSON returns canonical bytes of the latest-epoch knowledge
// payload. When sources is empty, returns "{}\n"-style canonical empty.
func buildKnowledgeJSON(sources []Source) ([]byte, error) {
	if len(sources) == 0 {
		return canonicalJSON(map[string]any{})
	}
	latest := sources[len(sources)-1]
	return canonicalRawJSON(latest.JSON)
}

// canonicalRawJSON re-marshals an arbitrary json.RawMessage through the
// canonical writer to enforce sorted-key, two-space-indent output.
func canonicalRawJSON(raw json.RawMessage) ([]byte, error) {
	var v any
	if len(raw) == 0 {
		return canonicalJSON(map[string]any{})
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return canonicalJSON(v)
}

// writeFactJSONL groups facts by epoch and writes one .jsonl per epoch with
// canonical (sorted-key) JSON per line. Empty facts → no files.
func writeFactJSONL(bundleRoot string, facts []Fact) error {
	if len(facts) == 0 {
		return nil
	}
	type epochBucket struct {
		epoch int64
		rows  []Fact
	}
	byEpoch := map[int64]*epochBucket{}
	var orderedEpochs []int64
	for _, f := range facts {
		b, ok := byEpoch[f.Epoch]
		if !ok {
			b = &epochBucket{epoch: f.Epoch}
			byEpoch[f.Epoch] = b
			orderedEpochs = append(orderedEpochs, f.Epoch)
		}
		b.rows = append(b.rows, f)
	}
	slices.Sort(orderedEpochs)
	for _, ep := range orderedEpochs {
		b := byEpoch[ep]
		sort.Slice(b.rows, func(i, j int) bool {
			if b.rows[i].Category != b.rows[j].Category {
				return b.rows[i].Category < b.rows[j].Category
			}
			return b.rows[i].Key < b.rows[j].Key
		})
		var lines []byte
		for _, r := range b.rows {
			line, err := canonicalJSON(map[string]any{
				"epoch":    r.Epoch,
				"category": r.Category,
				"key":      r.Key,
				"value":    r.Value,
			})
			if err != nil {
				return err
			}
			// Compact each line to a single line for jsonl format.
			compact, err := compactJSON(line)
			if err != nil {
				return err
			}
			lines = append(lines, compact...)
			lines = append(lines, '\n')
		}
		path := filepath.Join(bundleRoot, "app_facts", fmt.Sprintf("%d.jsonl", ep))
		if err := os.WriteFile(path, lines, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// compactJSON re-encodes pretty JSON as a single-line compact form while
// preserving sorted-key ordering (the input is already canonical).
func compactJSON(pretty []byte) ([]byte, error) {
	var v any
	if err := json.Unmarshal(pretty, &v); err != nil {
		return nil, err
	}
	// Rebuild sorted compact via canonicalJSON then strip indentation.
	canon, err := canonicalJSON(v)
	if err != nil {
		return nil, err
	}
	// Strip leading whitespace from each line and join.
	out := make([]byte, 0, len(canon))
	inString := false
	escape := false
	for _, c := range canon {
		if escape {
			out = append(out, c)
			escape = false
			continue
		}
		if c == '\\' && inString {
			out = append(out, c)
			escape = true
			continue
		}
		if c == '"' {
			inString = !inString
			out = append(out, c)
			continue
		}
		if !inString {
			if c == '\n' || c == ' ' {
				continue
			}
		}
		out = append(out, c)
	}
	// Re-insert single spaces after `:` and `,` for readable jsonl.
	return spaceAfterPunct(out), nil
}

func spaceAfterPunct(in []byte) []byte {
	out := make([]byte, 0, len(in)+8)
	inString := false
	escape := false
	for _, c := range in {
		out = append(out, c)
		if escape {
			escape = false
			continue
		}
		if c == '\\' && inString {
			escape = true
			continue
		}
		if c == '"' {
			inString = !inString
			continue
		}
		if !inString && (c == ':' || c == ',') {
			out = append(out, ' ')
		}
	}
	return out
}

// shortSHA returns the first 12 hex chars of sha (or "0" * 12 when sha is
// empty).
func shortSHA(sha string) string {
	if len(sha) >= 12 {
		return sha[:12]
	}
	if sha == "" {
		return "000000000000"
	}
	return sha
}

// exportedBy returns a stable "github.com/inovacc/unravel-oss/<sha>" identifier from build info, or
// "github.com/inovacc/unravel-oss/dev" when no build info is available.
func exportedBy() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "github.com/inovacc/unravel-oss/dev"
	}
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" && s.Value != "" {
			rev := s.Value
			if len(rev) > 12 {
				rev = rev[:12]
			}
			return "github.com/inovacc/unravel-oss/" + rev
		}
	}
	return "github.com/inovacc/unravel-oss/dev"
}
