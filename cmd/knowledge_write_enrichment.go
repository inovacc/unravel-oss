/*
Copyright (c) 2026 Security Research
*/

// cmd/knowledge_write_enrichment.go owns `unravel knowledge write-enrichment`,
// a direct-Postgres write path for a single module enrichment. It calls the
// same kbenrich.WriteEnrichmentJSON seam the MCP unravel_kb_enrich_write_enrichment
// tool wraps, but dials the DB directly via kbOpenDB (config.yaml) — so it
// keeps working when the supervisor / MCP transport is wedged. This is the
// resilient write path for Task-subagent re-enrichment of already-summarised
// modules (which the plugin /unravel:enrich path cannot reach, since
// PendingModules filters summary IS NULL).
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kbenrich"
)

var (
	writeEnrichDB    string
	writeEnrichID    int
	writeEnrichApp   string
	writeEnrichSHA   string
	writeEnrichModel string
	writeEnrichFile  string
	writeEnrichJSON  string
)

var kbWriteEnrichmentCmd = &cobra.Command{
	Use:   "write-enrichment",
	Short: "Persist one enrichment result from JSON (direct-PG; MCP-free write path)",
	Long: `Write a single module enrichment straight to Postgres via the same
kbenrich.WriteEnrichmentJSON seam the MCP unravel_kb_enrich_write_enrichment tool uses.
Unlike the MCP path it dials the DB directly (config.yaml), so it keeps working
when the supervisor / MCP transport is wedged.

parsed_json keys: summary, long_summary, role, inputs[], outputs[],
side_effects[], deps[], tags[].

Examples:
  unravel knowledge write-enrichment --id 755115 --app cluely \
      --sha256 711435... --file enrich-755115.json
  unravel knowledge write-enrichment --id 1 --app cluely --sha256 ab.. --json '{"summary":"..."}'`,
	RunE: runKBWriteEnrichment,
}

func init() {
	kbWriteEnrichmentCmd.Flags().StringVar(&writeEnrichDB, "database", "", "DSN override (defaults to config.yaml)")
	kbWriteEnrichmentCmd.Flags().IntVar(&writeEnrichID, "id", 0, "module id (required)")
	kbWriteEnrichmentCmd.Flags().StringVar(&writeEnrichApp, "app", "", "app the module belongs to (required)")
	kbWriteEnrichmentCmd.Flags().StringVar(&writeEnrichSHA, "sha256", "", "module body sha256 (required)")
	kbWriteEnrichmentCmd.Flags().StringVar(&writeEnrichModel, "model", "claude-code-subagent-hardened", "model label written to module_enrichment.model")
	kbWriteEnrichmentCmd.Flags().StringVar(&writeEnrichFile, "file", "", "path to a JSON file with the parsed enrichment")
	kbWriteEnrichmentCmd.Flags().StringVar(&writeEnrichJSON, "json", "", "inline parsed enrichment JSON (alternative to --file)")
	kbEnrichCmd.AddCommand(kbWriteEnrichmentCmd)
}

// loadParsedJSON resolves the parsed enrichment JSON from either an inline
// string or a file path. Exactly one must be provided.
func loadParsedJSON(file, inline string) ([]byte, error) {
	if inline != "" && file != "" {
		return nil, fmt.Errorf("provide only one of --file or --json")
	}
	if inline != "" {
		return []byte(inline), nil
	}
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("read --file: %w", err)
		}
		return b, nil
	}
	return nil, fmt.Errorf("one of --file or --json is required")
}

func runKBWriteEnrichment(_ *cobra.Command, _ []string) error {
	if writeEnrichID == 0 || writeEnrichApp == "" {
		return fmt.Errorf("--id and --app are required")
	}
	parsed, err := loadParsedJSON(writeEnrichFile, writeEnrichJSON)
	if err != nil {
		return err
	}

	db, err := kbOpenDB(writeEnrichDB)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	// sha256 is optional: look it up from the modules row when omitted so
	// callers (Task subagents) don't have to parse it out of dump text.
	sha := writeEnrichSHA
	if sha == "" {
		if qerr := db.QueryRow(`SELECT body_sha256 FROM modules WHERE id = $1`,
			writeEnrichID).Scan(&sha); qerr != nil {
			return fmt.Errorf("look up sha256 for id=%d: %w", writeEnrichID, qerr)
		}
	}

	if err := kbenrich.WriteEnrichmentJSON(db, writeEnrichID, writeEnrichApp,
		sha, string(parsed), writeEnrichModel, parsed); err != nil {
		return fmt.Errorf("write enrichment id=%d: %w", writeEnrichID, err)
	}
	fmt.Printf("wrote enrichment id=%d app=%s model=%s bytes=%d\n",
		writeEnrichID, writeEnrichApp, writeEnrichModel, len(parsed))
	return nil
}
