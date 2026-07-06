/*
Copyright (c) 2026 Security Research

kb_export.go — `unravel kb export <kb_id>` (Phase 32, Plan 32-05).
*/

package cmd

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
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lib/pq"
	"github.com/spf13/cobra"

	"github.com/inovacc/unravel-oss/cmd/kb_output"
	knowledge "github.com/inovacc/unravel-oss/pkg/knowledge"
	kbdb "github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"
	kbexport "github.com/inovacc/unravel-oss/pkg/knowledge/kb/export"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/exportbundle"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/fsutil"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/identity"
	kbstore "github.com/inovacc/unravel-oss/pkg/knowledge/kb/store"
)

var kbExportFlags struct {
	latestOnly bool
	jsonOut    bool
	dsn        string

	// Phase 43 — D-43-BUNDLE-SCHEMA-V1 bundle mode flags.
	bundle bool
	kbID   string
	outDir string
	noPack bool

	// v2.9 P54 (BNDL-02) — D-43 V2 Ed25519 signing flag.
	// Path to a 32-byte raw Ed25519 private seed (or "-" for stdin).
	// When set, the bundle is signed and a .kbb.sig sidecar is written.
	signKey string

	// kbc-v-export-fidelity — fidelity bundle mode flags.
	// --bodies enables the fidelity path. The output path (legacy tarball
	// path OR fidelity output directory) is supplied by the root persistent
	// --output/-o flag (§7 of COMMAND-TAXONOMY.md) — no local redeclaration.
	// --limit caps module count (0 = unlimited); --max-bytes caps cumulative
	// body bytes written (0 = unlimited).
	bodies   bool
	limit    int
	maxBytes int64
}

var kbExportCmd = &cobra.Command{
	Use:   "export [kb_id]",
	Short: "Export a KB application (legacy tarball or D-43 bundle)",
	Long: `Two modes:

LEGACY (default; Phase 32 schema):
  unravel kb export <kb_id> -o out.tar.gz [--latest-only] [--json]

  Produces a self-contained .tar.gz archive containing:
    1. On-disk kb-store version folders for the app.
    2. A 'kb-export.json' DB row dump (app, snapshots, modules, facts, diffs).
  Alias kb_ids are automatically resolved to their canonical form.

BUNDLE (Phase 43 — D-43-BUNDLE-SCHEMA-V1):
  unravel kb export --bundle --kb-id <id> --out-dir <dir> [--no-pack]

  Produces a portable bundle directory:
    <out-dir>/<kb_id>.kbb/
      bundle.json              -- manifest (schema_version=1, sha256 checksum)
      knowledge.json           -- latest-epoch canonical KnowledgeResult
      knowledge_sources/...    -- one .json per epoch
      app_facts/<epoch>.jsonl  -- one .jsonl per epoch
      kb_diffs/<from>-<to>.json
  Unless --no-pack is set, also writes <out-dir>/<kb_id>.kbb.tar.gz.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runKbExport,
}

func init() {
	kbExportCmd.Flags().BoolVar(&kbExportFlags.latestOnly, "latest-only", false, "(legacy) include only the newest epoch's data")
	kbExportCmd.Flags().BoolVar(&kbExportFlags.jsonOut, "json", false, "emit export metadata as JSON")

	// Phase 43 bundle-mode flags.
	kbExportCmd.Flags().BoolVar(&kbExportFlags.bundle, "bundle", false, "use D-43 bundle export (writes <out-dir>/<kb_id>.kbb/ + .tar.gz)")
	kbExportCmd.Flags().StringVar(&kbExportFlags.kbID, "kb-id", "", "(bundle mode) kb_id to export")
	kbExportCmd.Flags().StringVar(&kbExportFlags.outDir, "out-dir", "", "(bundle mode) output directory; defaults to cwd")
	kbExportCmd.Flags().BoolVar(&kbExportFlags.noPack, "no-pack", false, "(bundle mode) skip tarball wrap; produce directory tree only")

	// v2.9 P54 (BNDL-02): Ed25519 detached signature for D-43 V2.
	kbExportCmd.Flags().StringVar(&kbExportFlags.signKey, "sign-key", "", "(bundle mode) path to Ed25519 private seed (32 bytes raw); '-' reads stdin. Produces <kb_id>.kbb.sig sidecar.")

	// kbc-v-export-fidelity: fidelity bundle mode flags.
	kbExportCmd.Flags().BoolVar(&kbExportFlags.bodies, "bodies", false, "fidelity mode: write module bodies + enrichment manifest bundle")
	kbExportCmd.Flags().IntVar(&kbExportFlags.limit, "limit", 0, "fidelity: max modules (0 = unlimited)")
	kbExportCmd.Flags().Int64Var(&kbExportFlags.maxBytes, "max-bytes", 0, "fidelity: cumulative body-byte cap (0 = unlimited)")

	kbTransferCmd.AddCommand(kbExportCmd)
}

func runKbExport(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	if cmd != nil && cmd.Context() != nil {
		ctx = cmd.Context()
	}

	// Phase 43 — D-43 bundle mode dispatch.
	if kbExportFlags.bundle {
		return runKbExportBundle(ctx, cmd)
	}

	// kbc-v-export-fidelity — fidelity body/enrichment bundle dispatch.
	if kbExportFlags.bodies {
		return runKbExportFidelity(cmd)
	}

	if len(args) != 1 {
		return errors.New("legacy export requires <kb_id> positional arg; or use --bundle --kb-id")
	}
	kbID := args[0]
	if output == "" {
		return errors.New("legacy export requires --output / -o")
	}

	dsn, err := kb_output.ResolveDSN(kbExportFlags.dsn)
	if err != nil {
		return err
	}

	db, err := kbdb.Open(ctx, dsn)
	if err != nil {
		return fmt.Errorf("open kb db: %w", err)
	}
	defer func() { _ = db.Close() }()

	// Step 2-4 + 7 (DB reads): delegate to kbstore.Export. Alias
	// resolution, epoch enumeration, and per-row DB collection live in
	// pkg/knowledge/kb/store (Phase A2 extraction).
	export, err := kbstore.Export(ctx, db, kbID, kbstore.ExportOptions{
		LatestOnly: kbExportFlags.latestOnly,
	})
	if err != nil {
		return fmt.Errorf("collect export: %w", err)
	}
	canonical := export.Canonical
	if export.ExportedUnderAlias {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: %q is alias of canonical %q; exporting canonical\n", kbID, canonical)
	}
	if len(export.Snapshots) == 0 {
		return fmt.Errorf("no snapshots found for kb_id %s", canonical)
	}

	// Step 3: validate output path.
	outputPath := filepath.Clean(output)
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("create output parent dir: %w", err)
	}

	// Step 5: open output file and writers.
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}

	// Error handling for partial file removal.
	success := false
	defer func() {
		if !success {
			_ = f.Close()
			_ = os.Remove(outputPath)
		}
	}()

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	// f is closed via the success/failure defer above; tw and gw are closed
	// explicitly on the success path so write errors are surfaced. On failure
	// they are abandoned (the file is removed).

	storeRoot, err := fsutil.KBStoreRoot()
	if err != nil {
		return fmt.Errorf("resolve kb-store root: %w", err)
	}

	// Step 6: FS section.
	filesExported := 0
	for _, epoch := range export.Snapshots {
		ksFS, err := fsutil.EncodeKsID(epoch.KSID)
		if err != nil {
			return fmt.Errorf("encode ks_id %s: %w", epoch.KSID, err)
		}
		versionDir := filepath.Join(storeRoot, "apps", canonical, "versions", ksFS)
		versionDir = fsutil.WrapLongPath(versionDir)

		err = filepath.WalkDir(versionDir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}

			rel, err := filepath.Rel(versionDir, path)
			if err != nil {
				return err
			}

			// Defense for tar slip (T-32-05-01).
			tarName := "kb-store/apps/" + canonical + "/versions/" + ksFS + "/" + filepath.ToSlash(rel)
			if strings.Contains(tarName, "..") || strings.HasPrefix(tarName, "/") {
				return fmt.Errorf("invalid tar entry name: %s", tarName)
			}
			if !strings.HasPrefix(tarName, "kb-store/") && tarName != "kb-export.json" {
				return fmt.Errorf("tar name not allowlisted: %s", tarName)
			}

			info, err := d.Info()
			if err != nil {
				return err
			}

			header, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return err
			}
			header.Name = tarName

			if err := tw.WriteHeader(header); err != nil {
				return err
			}

			in, err := os.Open(path)
			if err != nil {
				return err
			}
			_, err = io.CopyBuffer(tw, in, make([]byte, 64*1024))
			closeErr := in.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
			filesExported++
			if filesExported%100 == 0 {
				fmt.Fprintf(os.Stderr, "exporting epoch=%d files=%d\n", epoch.Epoch, filesExported)
			}
			return nil
		})
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				fmt.Fprintf(os.Stderr, "warning: version dir %s not found on disk, skipping files for epoch %d\n", versionDir, epoch.Epoch)
				continue
			}
			return fmt.Errorf("walk version dir: %w", err)
		}
	}

	// Step 7: DB section.
	// kbstore.Export already collected every DB row (see kbstore call
	// above); we only need to serialize.
	exportJSON, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal export json: %w", err)
	}

	header := &tar.Header{
		Name: "kb-export.json",
		Size: int64(len(exportJSON)),
		Mode: 0o644,
	}
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	if _, err := tw.Write(exportJSON); err != nil {
		return err
	}

	// Close writers explicitly to check for errors.
	if err := tw.Close(); err != nil {
		return fmt.Errorf("close tar writer: %w", err)
	}
	if err := gw.Close(); err != nil {
		return fmt.Errorf("close gzip writer: %w", err)
	}

	fi, _ := f.Stat()
	size := int64(0)
	if fi != nil {
		size = fi.Size()
	}

	success = true

	// Step 9: Stdout.
	if kbExportFlags.jsonOut {
		return kb_output.WriteJSON(cmd.OutOrStdout(), 1, map[string]any{
			"kb_id":          canonical,
			"epochs":         len(export.Snapshots),
			"files":          filesExported,
			"archive":        outputPath,
			"size":           size,
			"latest_only":    kbExportFlags.latestOnly,
			"schema_version": 1,
		})
	}

	fmt.Fprintf(cmd.OutOrStdout(), "exported kb_id=%s epochs=%d files=%d archive=%q size=%d\n",
		canonical, len(export.Snapshots), filesExported, outputPath, size)

	return nil
}

// runKbExportBundle drives the Phase 43 D-43-BUNDLE-SCHEMA-V1 export.
// In-process: opens DB, runs export.Export → optional export.Pack, prints
// manifest JSON envelope (schema_version=1) on stdout.
func runKbExportBundle(ctx context.Context, cmd *cobra.Command) error {
	if kbExportFlags.kbID == "" {
		return errors.New("bundle mode requires --kb-id")
	}
	outDir := kbExportFlags.outDir
	if outDir == "" {
		var err error
		outDir, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("resolve cwd: %w", err)
		}
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create out-dir: %w", err)
	}

	dsn, err := kb_output.ResolveDSN(kbExportFlags.dsn)
	if err != nil {
		return err
	}
	db, err := kbdb.Open(ctx, dsn)
	if err != nil {
		return fmt.Errorf("open kb db: %w", err)
	}
	defer func() { _ = db.Close() }()

	manifest, err := kbexport.Export(ctx, db, kbExportFlags.kbID, outDir)
	if err != nil {
		return err
	}

	var tarballPath string
	if !kbExportFlags.noPack {
		tarballPath, err = kbexport.Pack(outDir, kbExportFlags.kbID)
		if err != nil {
			return err
		}
	}

	manifestBytes, err := kbexport.MarshalManifest(manifest)
	if err != nil {
		return err
	}

	// v2.9 P54 (BNDL-02): when --sign-key is set, sign the canonical manifest
	// with Ed25519 and write the detached signature to <kb_id>.kbb.sig
	// alongside the tarball. ADR-0007.
	if kbExportFlags.signKey != "" {
		key, err := kbexport.LoadEd25519Private(kbExportFlags.signKey)
		if err != nil {
			return fmt.Errorf("sign-key: %w", err)
		}
		sig := kbexport.SignManifest(manifestBytes, key)
		sigPath := filepath.Join(outDir, kbExportFlags.kbID+".kbb.sig")
		if err := kbexport.WriteSignatureFile(sigPath, sig); err != nil {
			return fmt.Errorf("write signature: %w", err)
		}
	}
	if kbExportFlags.jsonOut {
		return kb_output.WriteJSON(cmd.OutOrStdout(), 1, map[string]any{
			"kb_id":    manifest.KbID,
			"bundle":   filepath.Join(outDir, manifest.KbID+".kbb"),
			"tarball":  tarballPath,
			"manifest": json.RawMessage(manifestBytes),
			"counts":   manifest.Counts,
			"checksum": manifest.Checksum,
			"no_pack":  kbExportFlags.noPack,
		})
	}

	fmt.Fprintf(cmd.OutOrStdout(),
		"exported kb_id=%s bundle=%s tarball=%q sources=%d facts=%d diffs=%d checksum=%s\n",
		manifest.KbID,
		filepath.Join(outDir, manifest.KbID+".kbb"),
		tarballPath,
		manifest.Counts.KnowledgeSources,
		manifest.Counts.AppFacts,
		manifest.Counts.KbDiffs,
		manifest.Checksum,
	)
	return nil
}

// runKbExportFidelity implements `kb export --bodies --out DIR`.
// It writes a deterministic, bounded, content-addressed bundle:
//   - bodies/<sha[:2]>/<sha>.txt — one file per module body (full or excerpt)
//   - manifest.json — one ManifestRecord per module with enrichment fields
//
// Selection mirrors the legacy export: canonical kb_id → all knowledge_sources
// epochs → module_app_refs. Bodies and enrichment are LEFT JOINed so rows with
// no body or no enrichment are still included (status "absent"/"empty").
// Budget enforces --limit (count) and --max-bytes (cumulative body bytes).
// Writes are content-addressed: existing file with matching sha256 is skipped
// (idempotent/resumable); sha mismatch is a hard error (storage corruption).
func runKbExportFidelity(cmd *cobra.Command) error {
	if output == "" {
		return errors.New("--output / -o is required with --bodies")
	}
	out := output

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	dsn, err := kb_output.ResolveDSN(kbExportFlags.dsn)
	if err != nil {
		return err
	}
	db, err := kbdb.Open(ctx, dsn)
	if err != nil {
		return fmt.Errorf("open kb db: %w", err)
	}
	defer func() { _ = db.Close() }()

	// Resolve the kb_id from --kb-id flag (bundle mode convention) or args.
	// runKbExportFidelity is called from runKbExport which has already parsed
	// args, so we use the same kbID resolution the legacy path uses.
	kbID := kbExportFlags.kbID
	if kbID == "" {
		// Fidelity mode may be invoked as: kb export --bodies --out DIR <kb_id>
		// The positional arg is not available here; callers should set --kb-id.
		return errors.New("--kb-id is required with --bodies (or use --kb-id flag)")
	}

	canonical, err := identity.ResolveAlias(ctx, db, kbID)
	if err != nil {
		return fmt.Errorf("resolve alias: %w", err)
	}

	// Collect all knowledge_sources ids for this canonical kb_id.
	ksRows, err := db.QueryContext(ctx,
		`SELECT id FROM knowledge_sources WHERE kb_id = $1 AND ks_id IS NOT NULL`,
		canonical)
	if err != nil {
		return fmt.Errorf("query knowledge_sources: %w", err)
	}
	defer ksRows.Close()
	var sourceIDs []int64
	for ksRows.Next() {
		var id int64
		if err := ksRows.Scan(&id); err != nil {
			return fmt.Errorf("scan source id: %w", err)
		}
		sourceIDs = append(sourceIDs, id)
	}
	if err := ksRows.Err(); err != nil {
		return fmt.Errorf("iterate knowledge_sources: %w", err)
	}
	if len(sourceIDs) == 0 {
		return fmt.Errorf("no knowledge_sources found for kb_id %q", canonical)
	}

	// Module query: LEFT JOIN enrichment + bodies so non-enriched/bodyless rows
	// are still returned. $1 = pq.Array(sourceIDs) — mirrors the ANY($1) idiom
	// used by the legacy modules query at @415-420.
	const moduleQuery = `
SELECT m.id, m.app, m.name, COALESCE(m.synthetic_name,''), m.body_sha256,
       COALESCE(m.body_size,0), COALESCE(m.lang,''),
       COALESCE(m.summary,''), COALESCE(m.tags,''),
       COALESCE(me.role,''), COALESCE(me.long_summary,''),
       COALESCE(me.inputs_json,''), COALESCE(me.outputs_json,''),
       COALESCE(me.side_effects,''), COALESCE(me.deps_json,''),
       mb.body,
       COALESCE(m.body_excerpt,'')
FROM modules m
LEFT JOIN module_enrichment me ON me.module_id = m.id
LEFT JOIN module_bodies mb ON mb.body_sha256 = m.body_sha256
WHERE m.id IN (SELECT module_id FROM module_app_refs WHERE source_id = ANY($1))
ORDER BY m.id ASC`

	rows, err := db.QueryContext(ctx, moduleQuery, pq.Array(sourceIDs))
	if err != nil {
		return fmt.Errorf("query modules: %w", err)
	}
	defer rows.Close()

	bud := &exportbundle.Budget{Limit: kbExportFlags.limit, MaxBytes: kbExportFlags.maxBytes}
	var records []exportbundle.ManifestRecord
	var errCount int

	for rows.Next() {
		var (
			modID         int64
			app           string
			name          string
			syntheticName string
			bodySHA256    sql.NullString
			bodySize      int64
			lang          string
			summary       string
			tags          string
			role          string
			longSummary   string
			inputsJSON    string
			outputsJSON   string
			sideEffects   string
			depsJSON      string
			body          []byte // nil-safe: LEFT JOIN may yield SQL NULL
			bodyExcerpt   string
		)
		if err := rows.Scan(
			&modID, &app, &name, &syntheticName, &bodySHA256,
			&bodySize, &lang, &summary, &tags,
			&role, &longSummary, &inputsJSON, &outputsJSON,
			&sideEffects, &depsJSON,
			&body, &bodyExcerpt,
		); err != nil {
			slog.Error("kb fidelity export: scan row", "err", err)
			errCount++
			continue
		}

		sha := ""
		if bodySHA256.Valid {
			sha = bodySHA256.String
		}

		// Decide body content and status.
		var content []byte
		var status string
		if len(body) > 0 {
			status = "full"
			content = body
		} else if bodyExcerpt != "" {
			status = "excerpt"
			content = []byte(bodyExcerpt)
		} else {
			status = "absent"
			content = nil
		}

		// Budget enforcement: count this module's body bytes.
		bodyLen := int64(len(content))
		if !bud.Add(bodyLen) {
			// Budget exceeded; Truncated is latched. Stop processing.
			break
		}

		// Write body file if content is available.
		rel := ""
		if content != nil && sha != "" {
			rel = exportbundle.BodyPath(sha)
			abs := filepath.Join(out, rel)

			if _, statErr := os.Stat(abs); statErr == nil {
				// File exists — compare sha256 to detect corruption.
				existing, readErr := os.ReadFile(abs)
				if readErr != nil {
					slog.Error("kb fidelity export: read existing body", "path", abs, "err", readErr)
					errCount++
					continue
				}
				sum := sha256.Sum256(existing)
				existingSHA := hex.EncodeToString(sum[:])
				computedSHA := sha256.Sum256(content)
				computedSHAStr := hex.EncodeToString(computedSHA[:])
				if existingSHA == computedSHAStr {
					// Idempotent skip — content already written correctly.
				} else {
					// Hard error: storage corruption detected.
					return fmt.Errorf("export body sha mismatch at %s (have %s, want %s)", abs, existingSHA, computedSHAStr)
				}
			} else {
				// File does not exist — write atomically.
				if writeErr := knowledge.WriteFileAtomic(abs, content, 0o644); writeErr != nil {
					slog.Error("kb fidelity export: write body", "path", abs, "err", writeErr)
					errCount++
					continue
				}
			}
		}

		records = append(records, exportbundle.ManifestRecord{
			ModuleID:      modID,
			App:           app,
			Name:          name,
			SyntheticName: syntheticName,
			BodySHA256:    sha,
			BodySize:      bodySize,
			Lang:          lang,
			BodyPath:      rel,
			BodyStatus:    status,
			Summary:       summary,
			Tags:          tags,
			Role:          role,
			LongSummary:   longSummary,
			Inputs:        inputsJSON,
			Outputs:       outputsJSON,
			SideEffects:   sideEffects,
			Deps:          depsJSON,
		})
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate modules: %w", err)
	}

	// Build and write manifest.json.
	truncatedReason := ""
	if bud.Truncated {
		if kbExportFlags.limit > 0 && kbExportFlags.maxBytes > 0 {
			truncatedReason = fmt.Sprintf("limit=%d or max-bytes=%d reached", kbExportFlags.limit, kbExportFlags.maxBytes)
		} else if kbExportFlags.limit > 0 {
			truncatedReason = fmt.Sprintf("limit=%d reached", kbExportFlags.limit)
		} else {
			truncatedReason = fmt.Sprintf("max-bytes=%d reached", kbExportFlags.maxBytes)
		}
	}
	manifest := exportbundle.Manifest{
		SchemaVersion:   exportbundle.SchemaVersion,
		KbID:            canonical,
		GeneratedAtUnix: time.Now().Unix(),
		ModuleCount:     len(records),
		Truncated:       bud.Truncated,
		TruncatedReason: truncatedReason,
		Records:         records,
	}
	manifestPath := filepath.Join(out, "manifest.json")
	if err := knowledge.WriteJSONAtomic(manifestPath, &manifest); err != nil {
		return fmt.Errorf("write manifest.json: %w", err)
	}

	if bud.Truncated {
		slog.Warn("kb export fidelity truncated",
			"limit", kbExportFlags.limit,
			"max_bytes", kbExportFlags.maxBytes,
			"written", len(records))
	}

	fmt.Fprintf(cmd.OutOrStdout(),
		"fidelity export kb_id=%s out=%s modules=%d truncated=%v\n",
		canonical, out, len(records), bud.Truncated)

	if errCount > 0 {
		slog.Warn("kb export fidelity completed with row errors", "error_count", errCount)
	}
	return nil
}
