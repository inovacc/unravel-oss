/*
Copyright (c) 2026 Security Research

kb_classify.go — `unravel kb classify <kb_id>` (Phase 31, Plan 31-04).

Wires the rule-based component classifier to the CLI. Resolves a Postgres
DSN via --dsn flag or UNRAVEL_KB_DSN env var, opens a *sql.DB via
kbdb.Open (mirrors kb_merge.go), and invokes classify.Run for the given
(kbID, epoch). Emits a one-line text summary by default; --json emits the
full Report struct.

Flags (D-31-CLI-CLASSIFY):
  --epoch  <int64>   epoch to classify; 0 = latest
  --dsn    <string>  Postgres DSN; falls back to UNRAVEL_KB_DSN
  --by     <string>  operator identifier for audit trail
  --reason <string>  reason for re-classify (audit)
  --json             emit JSON Report instead of text summary

License: BSD-3-Clause.
*/

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/inovacc/unravel-oss/cmd/kb_output"
	internalmcp "github.com/inovacc/unravel-oss/internal/mcp"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/classify"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/corpus"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/eval"
	_ "github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/runtime" // populate rule registry
	kbdb "github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"
	pkgmcp "github.com/inovacc/unravel-oss/pkg/mcp"
)

var (
	classifyEpoch      int64
	classifyBy         string
	classifyReason     string
	classifyJSON       bool
	classifyEvalCorpus string
	classifyOut        string
	classifyReviewMode bool
	classifyMode       string
)

// defaultV1CorpusPath is the v1 corpus the --review-mode flag operates on.
var defaultV1CorpusPath = filepath.Join(
	"pkg", "knowledge", "kb", "component", "eval", "testdata", "corpus.json",
)

var classifyCmd = &cobra.Command{
	Use:   "classify <kb_id>",
	Short: "Run the rule-based component classifier over a kb snapshot",
	Long: `Classify every module in a (kb_id, epoch) snapshot into one of the
fixed taxonomy buckets (auth, crypto, ipc, security, stealth, telemetry,
storage, communication, ui, protocol, other).

The classifier is purely rule-based in Phase 31 (LLM mode lands in v2.6).
Re-running the command preserves rows whose classifier='manual' or 'llm'
— only 'rule' / 'heuristic' rows are overwritten (D-31-NO-COMPONENT-
DELETES-ON-RECLASSIFY).

Connection:
  DSN comes from %LOCALAPPDATA%/Unravel/config.yaml (run "unravel db setup").

Examples:
  unravel kb classify abc123def456
  unravel kb classify abc123 --epoch 3 --by analyst@example.com --reason "rule update"
  unravel kb classify abc123 --json`,
	Args: cobra.RangeArgs(0, 1),
	RunE: runKbClassify,
}

func init() {
	classifyCmd.Flags().Int64Var(&classifyEpoch, "epoch", 0, "epoch to classify (0 = latest)")
	classifyCmd.Flags().StringVar(&classifyBy, "by", "", "operator identifier for audit trail")
	classifyCmd.Flags().StringVar(&classifyReason, "reason", "", "reason for re-classify (audit)")
	classifyCmd.Flags().BoolVar(&classifyJSON, "json", false, "emit JSON report")
	classifyCmd.Flags().StringVar(&classifyEvalCorpus, "eval-corpus-build", "",
		"kb_id to extract draft corpus for (writes corpus.json.draft, never overwrites active corpus)")
	classifyCmd.Flags().StringVar(&classifyOut, "out", "",
		"output path for --eval-corpus-build (default: pkg/knowledge/kb/component/eval/testdata/corpus.json.draft)")
	classifyCmd.Flags().BoolVar(&classifyReviewMode, "review-mode", false,
		"P40: archive v1 corpus.json and migrate to schema_version 2 stub (Pass-B pending)")
	classifyCmd.Flags().StringVar(&classifyMode, "classifier", "auto",
		"classifier strategy: auto|rule|mcp (P45 LLMC-02). auto picks MCP→rule when host advertises sampling capability, otherwise rule.")
	// Phase 45 LLMC-02: --classifier supersedes the v3-dispatcher idea referenced in
	// .planning/phases/45-llm-classifier-v2-mcp-sampling-readiness/45-02-classify-v2-mcp-path-with-fallback-PLAN.md.
	kbEnrichCmd.AddCommand(classifyCmd)
}

// defaultDraftCorpusPath is the in-tree default --out for --eval-corpus-build.
var defaultDraftCorpusPath = filepath.Join(
	"pkg", "knowledge", "kb", "component", "eval", "testdata", "corpus.json.draft",
)

func runKbClassify(cmd *cobra.Command, args []string) error {
	// P40 --review-mode: short-circuit before kb_id/dsn checks.
	// Archives v1 corpus.json + migrates to v2 stub. No DB access required.
	if classifyReviewMode {
		return runReviewMode(cmd)
	}

	// Resolve kb_id: positional arg OR --eval-corpus-build value (D-34-CORPUS-GENERATOR).
	kbID := ""
	if len(args) == 1 {
		kbID = args[0]
	}
	if classifyEvalCorpus != "" {
		if kbID != "" && kbID != classifyEvalCorpus {
			return fmt.Errorf("conflicting kb_id: positional %q vs --eval-corpus-build %q", kbID, classifyEvalCorpus)
		}
		kbID = classifyEvalCorpus
	}
	if kbID == "" {
		return fmt.Errorf("missing kb_id: pass as positional arg or via --eval-corpus-build")
	}

	dsn, err := kb_output.ResolveDSN("")
	if err != nil {
		return err
	}

	ctx := context.Background()
	if cmd != nil && cmd.Context() != nil {
		ctx = cmd.Context()
	}

	db, err := kbdb.Open(ctx, dsn)
	if err != nil {
		return fmt.Errorf("open kb db: %w", err)
	}
	defer func() { _ = db.Close() }()

	// --eval-corpus-build branch: skip module_components writes entirely.
	// Per D-34-CORPUS-NO-AUTO-PROMOTE the .draft suffix is enforced inside
	// corpus.GenerateDraft.
	if classifyEvalCorpus != "" {
		outPath := classifyOut
		if outPath == "" {
			outPath = defaultDraftCorpusPath
		}
		rep, gerr := corpus.GenerateDraft(ctx, db, kbID, classifyEpoch, outPath)
		if gerr != nil {
			return fmt.Errorf("eval-corpus-build: %w", gerr)
		}
		w := cmd.OutOrStdout()
		if classifyJSON {
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			return enc.Encode(rep)
		}
		_, _ = fmt.Fprintf(w, "wrote draft corpus: %s (modules=%d)\n", rep.OutPath, rep.ModuleCount)
		return nil
	}

	clf, source, selErr := classify.Select(ctx, classify.SelectOptions{
		Mode:        classifyMode,
		HasSampling: pkgmcp.HasSamplingCapability,
		MCPClient:   internalmcp.ClassifyClient,
	})
	if selErr != nil {
		return fmt.Errorf("classify: %w", selErr)
	}
	slog.Info("classify: classifier selected", "classifier", clf.Name(), "source", source)

	rep, err := classify.RunWithOptions(ctx, db, kbID, classifyEpoch, classify.Options{Classifier: clf})
	if err != nil {
		return fmt.Errorf("classify: %w", err)
	}

	w := cmd.OutOrStdout()
	if classifyJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}
	_, _ = fmt.Fprintf(w, "kb_id=%s epoch=%d classified=%d skipped=%d\n",
		rep.KBID, rep.Epoch, rep.ModulesClassified, rep.Skipped)
	for bucket, count := range rep.BucketCounts {
		_, _ = fmt.Fprintf(w, "  %-14s %d\n", bucket, count)
	}
	if classifyBy != "" || classifyReason != "" {
		_, _ = fmt.Fprintf(w, "by=%s reason=%s\n", classifyBy, classifyReason)
	}
	return nil
}

// runReviewMode implements P40 --review-mode: archive v1 corpus.json then
// migrate to schema_version 2 stub via eval.MigrateCorpusV1ToV2. The archive
// path is corpus.v1.json.archive in the same directory.
//
// Path remap deviation (Plan 40-01): planner referenced fictional path
// pkg/knowledge/kb/classify/corpus.json — actual is
// pkg/knowledge/kb/component/eval/testdata/corpus.json.
func runReviewMode(cmd *cobra.Command) error {
	corpusPath := classifyOut
	if corpusPath == "" {
		corpusPath = defaultV1CorpusPath
	}
	dir := filepath.Dir(corpusPath)
	archivePath := filepath.Join(dir, "corpus.v1.json.archive")

	src, err := os.ReadFile(corpusPath)
	if err != nil {
		return fmt.Errorf("read v1 corpus: %w", err)
	}
	if err := os.WriteFile(archivePath, src, 0o644); err != nil {
		return fmt.Errorf("write archive: %w", err)
	}

	// Migration reads v1 (which still exists at corpusPath) and overwrites it with v2.
	if err := eval.MigrateCorpusV1ToV2(corpusPath, corpusPath); err != nil {
		return fmt.Errorf("migrate v1->v2: %w", err)
	}

	w := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(w, "review-mode: archived v1 to %s; migrated %s to schema_version 2 (Pass-B pending)\n",
		archivePath, corpusPath)
	return nil
}
