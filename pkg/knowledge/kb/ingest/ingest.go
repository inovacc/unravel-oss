/*
Copyright (c) 2026 Security Research

ingest.Run — entry point for the v2.5 KB ingest writer.

Performs the 9-step single-transaction folder→DB ingest per
D-30-INGEST-TX-SCOPE:

  Step 0  Compute binary sha256 (outside tx — needed for idempotency).
  Step 1  Pre-tx idempotency check: SELECT on (kb_id, binary_sha256).
  Step 1b Open *sql.Conn for ComputeDepth BEFORE BeginTx (since
          *sql.Tx has NO .Conn() method — depth uses the conn for its
          read-only probe queries while the tx covers writes).
  Step 2  BeginTx with READ COMMITTED isolation.
  Step 3  Upsert kb_apps (last_seen_at bumped on existing kb_id).
  Step 4  identity.AllocateEpoch (takes pg_advisory_xact_lock); int64.
  Step 5  Compute depth via the separate *sql.Conn; INSERT
          knowledge_sources with all SCOR-01 fields (TEXT[] columns
          bound natively via []string — pgx/v5; NO lib/pq import,
          NO pq.Array shim).
  Step 6  WalkKSFolder + INSERT module_bodies / modules /
          module_app_refs / files / file_app_refs.
  Step 7  ExtractFacts + INSERT app_facts.
  Step 8  diff.ComputeConsecutive(prevEpoch=epoch-1, thisEpoch=epoch)
          + INSERT kb_diffs. Skipped when epoch==1.
  Step 9  COMMIT (advisory lock auto-releases).

Phase 30 boundary: this code path NEVER writes to module_components.
The classifier owns those writes in Phase 31.

License: BSD-3-Clause.
*/

package ingest

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/pkg/dotnet/clr"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/depth"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/diff"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/identity"
)

// Options control ingest.Run behavior. Force is a P32 ergonomic that
// is ignored in P30 — the idempotency check is non-overrideable here.
//
// jsonschema tags describe inputs surfaced to MCP tool schema reflection
// (D-33-SCHEMA-REUSE). Descriptions mirror the corresponding CLI flag
// --help text in cmd/kb_capture.go.
type Options struct {
	Force        bool     `jsonschema:"bypass idempotency check; create new epoch even if binary_sha256 matches latest"`
	Tags         []string `jsonschema:"free-form labels attached to this capture (repeatable)"`
	Reason       string   `jsonschema:"human-readable reason for the capture (audit trail)"`
	By           string   `jsonschema:"actor identifier (user, ci-job, agent-name) attributed to this capture"`
	ResolveAlias bool     `jsonschema:"call identity.ResolveAlias before ingest so loser kb_ids are remapped to their canonical winner"`
	AllowedRoots []string `jsonschema:"filesystem roots permitted as ksDir prefixes; enforces path-traversal safety in WalkKSFolder"`

	// App overrides the canonical app key written into modules/files/
	// app_facts. Defaults to canonical-name slug derived from
	// knowledge.json.display_name when empty.
	App string `jsonschema:"override canonical app key written to modules/files/app_facts; defaults to slug of display_name"`

	// PackageID / Platform / Publisher / Framework / DisplayName /
	// CanonicalName seed the kb_apps upsert. Caller (the capture
	// pipeline) MUST populate Platform — the rest are best-effort.
	PackageID     string `jsonschema:"platform-specific package identifier (e.g. android applicationId); seeds kb_apps.package_id"`
	Platform      string `jsonschema:"app platform (android, electron, tauri, dotnet, ios, ...); REQUIRED, seeds kb_apps.platform"`
	Publisher     string `jsonschema:"signing publisher common name; seeds kb_apps.publisher_cn"`
	Framework     string `jsonschema:"detected framework (electron, tauri, flutter, react-native, ...); seeds kb_apps.framework"`
	DisplayName   string `jsonschema:"human-readable application display name; seeds kb_apps.display_name"`
	CanonicalName string `jsonschema:"normalized canonical app name; seeds kb_apps.canonical_name (auto-derived from DisplayName when empty)"`

	// BinarySHA256 optionally supplies the authoritative source-binary
	// hash for the idempotency check (D-30-IDEMPOTENCY). When set it
	// takes precedence over readBinarySHA256(ksDir). Required for inputs
	// whose staging dir has no top-level PE/ELF/Mach-O file (e.g. APK
	// archives) so identical re-captures still short-circuit with
	// Skipped=true. Empty falls back to ksDir discovery + walk-derived.
	BinarySHA256 string `jsonschema:"sha256 of the source-binary input file; takes precedence over staged-dir discovery for idempotency"`

	// CLRModules carries native pure-Go CLR decompiler output (one TypeModule
	// per managed TypeDef) threaded in-memory from the capture pipeline
	// (DissectResult.CLRModules → KnowledgeResult.CLRModules). When non-empty,
	// Run persists them as lang='cil' rows via IngestModules INSIDE the main
	// ingest transaction. Empty for non-.NET inputs. Not a jsonschema input —
	// it is an in-process struct field, never surfaced to MCP tool schemas.
	CLRModules []clr.TypeModule
}

// Result is the structured summary of an ingest run. Epoch is int64
// to match identity.AllocateEpoch.
type Result struct {
	KBID           string   `json:"kb_id"`
	KSID           string   `json:"ks_id"`
	Epoch          int64    `json:"epoch"`
	RiskScore      *int     `json:"risk_score,omitempty"`
	RiskLevel      string   `json:"risk_level"`
	Framework      string   `json:"framework,omitempty"`
	DepthScore     int      `json:"depth_score"`
	DepthCovered   []string `json:"depth_covered"`
	DepthMissing   []string `json:"depth_missing"`
	ModulesIndexed int64    `json:"modules_indexed"`
	BodiesIndexed  int64    `json:"bodies_indexed"`
	DiffsWritten   int      `json:"diffs_written"`
	Skipped        bool     `json:"skipped"`
	SkippedReason  string   `json:"skipped_reason,omitempty"`
	BinarySHA256   string   `json:"binary_sha256"`

	// App is the app key actually resolved and written to modules.app /
	// files.app / app_facts.app (see the `app` local a few lines into Run:
	// opts.App -> knowledge.json["app"] -> opts.CanonicalName ->
	// slug(opts.DisplayName) -> kbID). Callers that need to scope a
	// downstream pass (e.g. static backfill) to exactly the rows this run
	// touched MUST use this field rather than re-deriving the app key
	// themselves, since re-derivation can disagree with Run's precedence.
	// Empty on the pre-tx idempotency Skipped=true path (resolution never
	// runs there) — callers should treat empty as "no scoped app key
	// available" rather than substituting an unscoped/whole-KB fallback.
	App string `json:"app"`
}

// Run is the entry point for the v2.5 KB ingest writer. ksDir MUST
// already be the FS-form path under kb-store root produced by the
// capture pipeline (Plan 30-04). The 9-step ingest transaction is
// described in detail in the package doc above.
func Run(ctx context.Context, db *sql.DB, kbID, ksID, ksDir string, opts Options) (*Result, error) {
	if db == nil {
		return nil, errors.New("db is required")
	}
	if kbID == "" {
		return nil, errors.New("kb_id required")
	}
	if ksID == "" {
		return nil, errors.New("ks_id required")
	}
	if ksDir == "" {
		return nil, errors.New("ksDir required")
	}

	// Always-on KB-assembly stage logging (stderr only; snake_case keys).
	// The closure fires on every return path so a hung assembly is
	// instantly localizable. No behavior change — logging only.
	kbStart := time.Now()
	var ingestEpoch int64
	slog.Info("stage start", "stage", "kb_assembly", "target", kbID)
	defer func() {
		slog.Info("stage end",
			"stage", "kb_assembly",
			"target", kbID,
			"elapsed_ms", time.Since(kbStart).Milliseconds(),
			"epoch", ingestEpoch,
		)
	}()

	// Resolve alias if requested (replaces a loser kb_id with its winner).
	if opts.ResolveAlias {
		canonical, err := identity.ResolveAlias(ctx, db, kbID)
		if err != nil {
			return nil, fmt.Errorf("resolve alias: %w", err)
		}
		kbID = canonical
	}

	// Step 0: compute binary sha256 (needed for the pre-tx idempotency
	// check). Caller-supplied opts.BinarySHA256 takes precedence — it is
	// the authoritative source-binary hash for inputs whose staging dir
	// has no top-level PE/ELF/Mach-O (e.g. APK archives). Falls back to
	// best-effort ksDir discovery, then walk-derived later.
	binarySHA256 := opts.BinarySHA256
	if binarySHA256 == "" {
		var err error
		binarySHA256, err = readBinarySHA256(ksDir)
		if err != nil {
			return nil, fmt.Errorf("read binary sha256: %w", err)
		}
	}

	// Step 1: pre-tx idempotency check (D-30-IDEMPOTENCY).
	if binarySHA256 != "" && !opts.Force {
		skip, err := CheckIdempotency(ctx, db, kbID, binarySHA256)
		if err != nil {
			return nil, fmt.Errorf("check idempotency: %w", err)
		}
		if skip != nil {
			return &Result{
				KBID:          kbID,
				KSID:          skip.KSID,
				Epoch:         skip.Epoch,
				Skipped:       true,
				SkippedReason: skip.Reason,
				BinarySHA256:  binarySHA256,
				RiskLevel:     "unknown",
			}, nil
		}
	}

	// Load knowledge.json (best-effort — empty map when absent so
	// scoring still executes).
	knowledgeJSON := loadKnowledgeJSON(ksDir)

	// Resolve app key (used for modules / files / app_facts joins).
	app := opts.App
	if app == "" {
		if v, ok := knowledgeJSON["app"].(string); ok && v != "" {
			app = v
		} else if opts.CanonicalName != "" {
			app = opts.CanonicalName
		} else if opts.DisplayName != "" {
			app = identity.CanonicalName(opts.DisplayName)
		} else {
			app = kbID
		}
	}
	framework := opts.Framework
	if framework == "" {
		if v, ok := knowledgeJSON["framework"].(string); ok {
			framework = v
		}
	}

	// Step 1b: open a dedicated *sql.Conn for ComputeDepth BEFORE
	// BeginTx. *sql.Tx has NO .Conn() method, so depth.ComputeDepth
	// receives its own conn handle for read-only probe queries.
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire conn for depth: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// Step 2: open ingest transaction (READ COMMITTED isolation per
	// D-30-INGEST-TX-SCOPE). Advisory lock is taken inside
	// identity.AllocateEpoch in step 4.
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Step 3: upsert kb_apps (last_seen_at bumps on existing kb_id).
	now := time.Now().Unix()
	canonical := opts.CanonicalName
	if canonical == "" {
		canonical = identity.CanonicalName(opts.DisplayName)
		if canonical == "" {
			canonical = app
		}
	}
	display := opts.DisplayName
	if display == "" {
		display = canonical
	}
	platform := opts.Platform
	if platform == "" {
		platform = "other"
	}
	// On --force re-ingest, also refresh identity columns (display_name,
	// canonical_name, framework). Without --force, identity is stable per
	// kb_id and only last_seen_at bumps. This lets analysts correct stale
	// labels (e.g. early Electron captures that wrote display_name as the
	// framework literal) by re-running with --force.
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO kb_apps (
			kb_id, canonical_name, display_name, platform, publisher,
			framework, package_id, first_seen_at, last_seen_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
		ON CONFLICT (kb_id) DO UPDATE SET
			last_seen_at   = EXCLUDED.last_seen_at,
			display_name   = CASE WHEN $9 THEN EXCLUDED.display_name   ELSE kb_apps.display_name   END,
			canonical_name = CASE WHEN $9 THEN EXCLUDED.canonical_name ELSE kb_apps.canonical_name END,
			framework      = CASE WHEN $9 THEN EXCLUDED.framework      ELSE kb_apps.framework      END
	`, kbID, canonical, display, platform, nullable(opts.Publisher),
		nullable(framework), nullable(opts.PackageID), now, opts.Force); err != nil {
		return nil, fmt.Errorf("upsert kb_apps: %w", err)
	}

	// Step 4: allocate epoch — int64, advisory lock held for tx duration.
	epoch, err := identity.AllocateEpoch(ctx, tx, kbID)
	if err != nil {
		return nil, fmt.Errorf("allocate epoch: %w", err)
	}
	ingestEpoch = epoch

	// Step 5: compute depth via the SEPARATE *sql.Conn (NOT tx).
	depthScore, depthCovered, depthMissing, err := depth.ComputeDepth(ctx, ksDir, conn)
	if err != nil {
		return nil, fmt.Errorf("compute depth: %w", err)
	}
	if depthCovered == nil {
		depthCovered = []string{}
	}
	if depthMissing == nil {
		depthMissing = []string{}
	}

	riskScore, riskLevel := CanonicalizeRisk(knowledgeJSON)

	// Walk KS folder up-front so we have module/body counts for the
	// knowledge_sources INSERT (modules_indexed, bodies_indexed).
	walk, err := WalkKSFolder(ctx, ksDir, kbID, app, WalkOptions{
		AllowedRoots:    opts.AllowedRoots,
		RetainBodyBytes: true,
	})
	if err != nil {
		return nil, fmt.Errorf("walk ks folder: %w", err)
	}
	if walk.BinarySHA256 == "" {
		walk.BinarySHA256 = binarySHA256
	}
	if binarySHA256 == "" {
		binarySHA256 = walk.BinarySHA256
	}

	// INSERT knowledge_sources. depth_covered / depth_missing are
	// []string — pgx/v5 binds them natively to TEXT[]. NO lib/pq.
	// NO pq.Array shim. modules_indexed / bodies_indexed are BIGINT.
	const insertSourceSQL = `
		INSERT INTO knowledge_sources (
			app, epoch, source_path, source_kind, app_version,
			source_sha256, captured_at, modules_indexed, bodies_indexed,
			kb_id, ks_id, framework, risk_score, risk_level,
			depth_score, depth_covered, depth_missing, binary_sha256
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11, $12, $13, $14,
			$15, $16, $17, $18
		)
		RETURNING id
	`
	var sourceID int64
	if err := tx.QueryRowContext(ctx, insertSourceSQL,
		app, epoch, ksDir, "kb-store", nullable(opts.Reason),
		nullable(binarySHA256), time.Now().UnixMilli(),
		walk.ModuleCount, walk.BodyCount,
		kbID, ksID, nullable(framework), riskScore, riskLevel,
		depthScore, depthCovered, depthMissing, nullable(binarySHA256),
	).Scan(&sourceID); err != nil {
		return nil, fmt.Errorf("insert knowledge_sources: %w", err)
	}

	// Step 6: persist module_bodies / modules / module_app_refs /
	// files / file_app_refs. Phase 30 boundary: NEVER writes
	// module_components — Phase 31 classifier owns those rows.
	if err := writeBodies(ctx, tx, walk, sourceID); err != nil {
		return nil, err
	}

	// Step 6b (FIX #1): persist native CLR modules as lang='cil' rows INSIDE
	// the same transaction so they commit atomically with the epoch. No-op
	// for non-.NET inputs (CLRModules empty). The capture pipeline threads
	// these in-memory from DissectResult.CLRModules (no sidecar file).
	if len(opts.CLRModules) > 0 {
		if _, err := IngestModules(ctx, tx, app, sourceID, opts.CLRModules); err != nil {
			return nil, fmt.Errorf("ingest cil modules: %w", err)
		}
	}

	// Step 7: app_facts (typed key-value rows).
	//
	// app_facts has UNIQUE(app, category, key) — so the UPSERT below
	// overwrites prev-epoch values in place. To diff prev vs new in the
	// next step we MUST snapshot prev facts BEFORE the UPSERT (when
	// epoch>1); otherwise diff.loadFacts would return identical
	// post-UPSERT state for both endpoints and emit zero diffs.
	facts := ExtractFacts(knowledgeJSON, app)

	var prevFactsSnapshot map[string]string
	var prevSourceID int64
	if epoch > 1 {
		var err error
		prevSourceID, _, err = diff.ResolveSource(ctx, tx, kbID, epoch-1)
		if err != nil {
			return nil, fmt.Errorf("resolve prev source: %w", err)
		}
		prevFactsSnapshot, err = diff.LoadFactsForApp(ctx, tx, app)
		if err != nil {
			return nil, fmt.Errorf("snapshot prev facts: %w", err)
		}
	}

	if err := writeFacts(ctx, tx, facts); err != nil {
		return nil, err
	}

	// Step 8: consecutive-epoch diff via in-memory snapshots. Skipped
	// when epoch==1. Builds the next-facts map from the extracted facts
	// slice (post-UPSERT state) and diffs against the pre-UPSERT
	// snapshot. The legacy diff.ComputeConsecutive path is preserved for
	// out-of-band callers but the ingest writer can't use it because
	// Step 7 has already mutated app_facts.
	diffsWritten := 0
	if epoch > 1 {
		nextFacts := make(map[string]string, len(facts))
		for _, f := range facts {
			nextFacts[f.Category+"/"+f.Key] = f.Value
		}
		diffs, err := diff.ComputeFromSnapshots(prevFactsSnapshot, nextFacts, prevSourceID, sourceID)
		if err != nil {
			return nil, fmt.Errorf("compute consecutive diffs: %w", err)
		}
		if err := writeDiffs(ctx, tx, diffs); err != nil {
			return nil, err
		}
		diffsWritten = len(diffs)
	}

	// Step 9: COMMIT (advisory lock auto-releases).
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit ingest tx: %w", err)
	}
	committed = true

	return &Result{
		KBID:           kbID,
		KSID:           ksID,
		Epoch:          epoch,
		RiskScore:      riskScore,
		RiskLevel:      riskLevel,
		Framework:      framework,
		DepthScore:     depthScore,
		DepthCovered:   depthCovered,
		DepthMissing:   depthMissing,
		ModulesIndexed: walk.ModuleCount,
		BodiesIndexed:  walk.BodyCount,
		DiffsWritten:   diffsWritten,
		BinarySHA256:   binarySHA256,
		App:            app,
	}, nil
}

// readBinarySHA256 walks ksDir for a top-level PE/ELF/Mach-O / file
// named "binary" and returns its sha256. Empty string when no
// candidate is found (caller falls back to walk-derived value).
func readBinarySHA256(ksDir string) (string, error) {
	entries, err := os.ReadDir(ksDir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if e.IsDir() || e.Type()&os.ModeSymlink != 0 {
			continue
		}
		name := strings.ToLower(e.Name())
		ext := filepath.Ext(name)
		if name == "binary" || ext == ".exe" || ext == ".so" ||
			ext == ".dylib" || ext == ".dll" {
			return digestPath(filepath.Join(ksDir, e.Name()))
		}
	}
	return "", nil
}

func digestPath(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// loadKnowledgeJSON reads ksDir/knowledge.json with a 64MiB cap
// (T-30-03-03). Returns empty map on any error so ingest can proceed
// with default scoring.
func loadKnowledgeJSON(ksDir string) map[string]any {
	out := map[string]any{}
	f, err := os.Open(filepath.Join(ksDir, "knowledge.json"))
	if err != nil {
		return out
	}
	defer func() { _ = f.Close() }()
	const maxKnowledgeJSON = 64 * 1024 * 1024
	body, err := io.ReadAll(io.LimitReader(f, maxKnowledgeJSON))
	if err != nil {
		return out
	}
	_ = json.Unmarshal(body, &out)
	return out
}

func writeBodies(ctx context.Context, tx *sql.Tx, walk *WalkResult, sourceID int64) error {
	now := time.Now().UnixMilli()

	for _, b := range walk.ModuleBodies {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO module_bodies (body_sha256, body, body_size, stored_at)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (body_sha256) DO NOTHING
		`, b.BodySHA256, b.Body, b.SizeBytes, now); err != nil {
			return fmt.Errorf("insert module_bodies: %w", err)
		}
	}

	for _, m := range walk.Modules {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO modules (
				app, name, body_sha256, body_size, first_seen_at, last_seen_at,
				first_source_id, last_source_id
			) VALUES ($1, $2, $3, NULL, $4, $4, $5, $5)
			ON CONFLICT DO NOTHING
		`, m.App, m.Name, m.BodySHA256, now, sourceID); err != nil {
			return fmt.Errorf("insert modules: %w", err)
		}
	}

	for _, r := range walk.ModuleAppRefs {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO module_app_refs (body_sha256, app, source_id, observed_at)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (body_sha256, app, source_id) DO NOTHING
		`, r.BodySHA256, r.App, sourceID, now); err != nil {
			return fmt.Errorf("insert module_app_refs: %w", err)
		}
	}

	for _, f := range walk.Files {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO files (file_sha256, file_size, first_seen_at)
			VALUES ($1, $2, $3)
			ON CONFLICT (file_sha256) DO NOTHING
		`, f.FileSHA256, f.SizeBytes, now); err != nil {
			return fmt.Errorf("insert files: %w", err)
		}
	}

	for i, r := range walk.FileAppRefs {
		relPath := ""
		if i < len(walk.Files) {
			relPath = walk.Files[i].RelPath
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO file_app_refs (file_sha256, source_id, rel_path, observed_at)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (file_sha256, source_id, rel_path) DO NOTHING
		`, r.FileSHA256, sourceID, relPath, now); err != nil {
			return fmt.Errorf("insert file_app_refs: %w", err)
		}
	}
	return nil
}

func writeFacts(ctx context.Context, tx *sql.Tx, facts []FactRow) error {
	for _, f := range facts {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO app_facts (app, category, key, value, source_step)
			VALUES ($1, $2, $3, $4, 'kb-ingest')
			ON CONFLICT (app, category, key) DO UPDATE SET value = EXCLUDED.value
		`, f.App, f.Category, f.Key, f.Value); err != nil {
			return fmt.Errorf("insert app_facts: %w", err)
		}
	}
	return nil
}

func writeDiffs(ctx context.Context, tx *sql.Tx, diffs []diff.Diff) error {
	for _, d := range diffs {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO kb_diffs (
				from_source_id, to_source_id, category, change_type,
				identifier, payload, computed_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT DO NOTHING
		`, d.FromSourceID, d.ToSourceID, d.Category, d.ChangeType,
			d.Identifier, d.Payload, d.ComputedAt); err != nil {
			return fmt.Errorf("insert kb_diffs: %w", err)
		}
	}
	return nil
}

// nullable converts an empty string to a nil interface so the Postgres
// driver writes NULL rather than the empty string.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
