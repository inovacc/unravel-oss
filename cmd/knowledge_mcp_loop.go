/*
Copyright (c) 2026 Security Research
*/
// cmd/knowledge_mcp_loop.go is the CLI passthrough for the kb_pull_gap /
// kb_push_answer MCP tools. It lets analysts drain the gap queue without
// going through an MCP client, which is mostly useful for shell-driven
// experimentation and CI smoke tests.
//
// v2.17 thin-client B7-P1: the wrapper shims that used to live in
// pkg/mcp/tools/kb_loop.go (PullOpenGapForCLI / PushAnswerForCLI) have been
// inlined here so pkg/mcp/tools no longer reaches into kbdb/kbstore for
// CLI-only call paths. The MCP tool path (over the supervisor) is
// unaffected — this code is only reached by `unravel knowledge mcp-loop`.
package cmd

import (
	"context"
	"encoding/json"
	"fmt"

	kbdb "github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"
	kbstore "github.com/inovacc/unravel-oss/pkg/knowledge/kb/store"

	"github.com/spf13/cobra"
)

var (
	mcpLoopDB         string
	mcpLoopApp        string
	mcpLoopOp         string
	mcpLoopGapID      int64
	mcpLoopValue      string
	mcpLoopConfidence float64
	mcpLoopSource     string
	mcpLoopEvidence   []int64
)

var kbMcpLoopCmd = &cobra.Command{
	Use:   "mcp-loop",
	Short: "Drive the gap-resolution loop without an MCP client (debug)",
}

var kbMcpLoopPullCmd = &cobra.Command{
	Use:   "pull",
	Short: "Run the equivalent of unravel_kb_pull_gap and print JSON",
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx := context.Background()
		db, err := kbdb.Open(ctx, mcpLoopDB)
		if err != nil {
			return fmt.Errorf("open kb: %w", err)
		}
		defer func() { _ = db.Close() }()
		out, err := kbstore.PullGap(ctx, db, kbstore.PullGapOptions{
			App: mcpLoopApp,
			Op:  mcpLoopOp,
		})
		if err != nil {
			return err
		}
		raw, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(raw))
		return nil
	},
}

var kbMcpLoopPushCmd = &cobra.Command{
	Use:   "push",
	Short: "Run the equivalent of unravel_kb_push_answer",
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx := context.Background()
		db, err := kbdb.Open(ctx, mcpLoopDB)
		if err != nil {
			return fmt.Errorf("open kb: %w", err)
		}
		defer func() { _ = db.Close() }()
		out, err := kbstore.PushAnswer(ctx, db, kbstore.PushAnswerOptions{
			GapID:       mcpLoopGapID,
			Value:       mcpLoopValue,
			EvidenceIDs: mcpLoopEvidence,
			Confidence:  mcpLoopConfidence,
			SourceStep:  mcpLoopSource,
		})
		if err != nil {
			return err
		}
		raw, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(raw))
		return nil
	},
}

func init() {
	kbMcpLoopPullCmd.Flags().StringVar(&mcpLoopDB, "database", "", "knowledge.db path (required)")
	kbMcpLoopPullCmd.Flags().StringVar(&mcpLoopApp, "app", "", "app slug (required)")
	kbMcpLoopPullCmd.Flags().StringVar(&mcpLoopOp, "op", "fact_resolve", "prompt op id")
	_ = kbMcpLoopPullCmd.MarkFlagRequired("database")
	_ = kbMcpLoopPullCmd.MarkFlagRequired("app")

	kbMcpLoopPushCmd.Flags().StringVar(&mcpLoopDB, "database", "", "knowledge.db path (required)")
	kbMcpLoopPushCmd.Flags().Int64Var(&mcpLoopGapID, "gap-id", 0, "app_facts.id to update (required)")
	kbMcpLoopPushCmd.Flags().StringVar(&mcpLoopValue, "value", "", "resolved value (required)")
	kbMcpLoopPushCmd.Flags().Float64Var(&mcpLoopConfidence, "confidence", 0, "0..1 confidence")
	kbMcpLoopPushCmd.Flags().StringVar(&mcpLoopSource, "source-step", "claude_mcp", "fact_history source label")
	kbMcpLoopPushCmd.Flags().Int64SliceVar(&mcpLoopEvidence, "evidence-ids", nil, "module ids supporting the value")
	_ = kbMcpLoopPushCmd.MarkFlagRequired("database")
	_ = kbMcpLoopPushCmd.MarkFlagRequired("gap-id")
	_ = kbMcpLoopPushCmd.MarkFlagRequired("value")

	kbMcpLoopCmd.AddCommand(kbMcpLoopPullCmd, kbMcpLoopPushCmd)
	kbEnrichCmd.AddCommand(kbMcpLoopCmd)
}
