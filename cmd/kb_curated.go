/*
Copyright (c) 2026 Security Research
*/

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/inovacc/unravel-oss/cmd/kb_output"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/curatedstore"
	kbdb "github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/fsutil"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/identity"
)

var (
	curatedDSN      string
	curatedJSON     bool
	curatedMaxItems int
	curatedMaxBytes int64
)

var kbCuratedCmd = &cobra.Command{
	Use:   "curated",
	Short: "Read-only retrieval of curated kb-store artifacts for a kb_id",
}

var kbCuratedListCmd = &cobra.Command{
	Use:   "list <kb_id>",
	Short: "List curated artifacts available for a kb_id (alias-resolved, bounded)",
	Args:  cobra.ExactArgs(1),
	RunE:  runKbCuratedList,
}

var kbCuratedGetCmd = &cobra.Command{
	Use:   "get <kb_id> <relpath>",
	Short: "Stream a single curated artifact (path-contained, byte-bounded)",
	Args:  cobra.ExactArgs(2),
	RunE:  runKbCuratedGet,
}

func init() {
	kbCmd.AddCommand(kbCuratedCmd)
	kbCuratedCmd.AddCommand(kbCuratedListCmd)
	kbCuratedCmd.AddCommand(kbCuratedGetCmd)
	kb_output.BindJSONFlag(kbCuratedListCmd, &curatedJSON)
	kb_output.BindDSNFlag(kbCuratedListCmd, &curatedDSN)
	kb_output.BindDSNFlag(kbCuratedGetCmd, &curatedDSN)
	kbCuratedListCmd.Flags().IntVar(&curatedMaxItems, "max-entries", 1000, "max entries (0 = unlimited)")
	kbCuratedGetCmd.Flags().Int64Var(&curatedMaxBytes, "max-bytes", 8<<20, "max bytes to stream (0 = unlimited)")
}

func curatedResolveRoot(ctx context.Context, kbIDArg string) (string, error) {
	dsn, err := kb_output.ResolveDSN(curatedDSN)
	if err != nil {
		return "", fmt.Errorf("resolve dsn: %w", err)
	}
	db, err := kbdb.Open(ctx, dsn)
	if err != nil {
		return "", fmt.Errorf("open kb db: %w", err)
	}
	defer func() { _ = db.Close() }()
	canonical, err := identity.ResolveAlias(ctx, db, kbIDArg)
	if err != nil {
		return "", fmt.Errorf("resolve alias: %w", err)
	}
	base, err := fsutil.KBStoreRoot()
	if err != nil {
		return "", fmt.Errorf("resolve kb-store root: %w", err)
	}
	return curatedstore.Root(base, canonical), nil
}

func runKbCuratedList(cmd *cobra.Command, args []string) error {
	root, err := curatedResolveRoot(cmd.Context(), args[0])
	if err != nil {
		return err
	}
	entries, truncated, exists, err := curatedstore.List(root, curatedMaxItems)
	if err != nil {
		return fmt.Errorf("list curated: %w", err)
	}
	if !exists {
		if curatedJSON {
			return kb_output.WriteJSON(cmd.OutOrStdout(), 1, map[string]any{
				"kb_id": args[0], "exists": false, "entries": []any{}, "truncated": false,
			})
		}
		fmt.Fprintf(cmd.OutOrStdout(), "no curated artifacts for %s (no kb-store tree)\n", args[0])
		return nil
	}
	if curatedJSON {
		return kb_output.WriteJSON(cmd.OutOrStdout(), 1, map[string]any{
			"kb_id": args[0], "exists": true, "truncated": truncated, "entries": entries,
		})
	}
	for _, e := range entries {
		fmt.Fprintf(cmd.OutOrStdout(), "%-12s %10d  %s\n", e.Category, e.Size, e.Path)
	}
	if truncated {
		fmt.Fprintf(cmd.OutOrStdout(), "[truncated at %d entries]\n", curatedMaxItems)
	}
	return nil
}

func runKbCuratedGet(cmd *cobra.Command, args []string) error {
	root, err := curatedResolveRoot(cmd.Context(), args[0])
	if err != nil {
		return err
	}
	abs, err := curatedstore.SafeJoin(root, args[1])
	if err != nil {
		return fmt.Errorf("curated get %q: %w", args[1], err)
	}
	f, err := os.Open(abs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("curated artifact not found: %s", args[1])
		}
		return fmt.Errorf("open curated artifact: %w", err)
	}
	defer func() { _ = f.Close() }()
	var n int64
	if curatedMaxBytes > 0 {
		n, err = io.Copy(cmd.OutOrStdout(), io.LimitReader(f, curatedMaxBytes))
	} else {
		n, err = io.Copy(cmd.OutOrStdout(), f)
	}
	if err != nil {
		return fmt.Errorf("stream curated artifact: %w", err)
	}
	if curatedMaxBytes > 0 && n == curatedMaxBytes {
		fmt.Fprintf(os.Stderr, "[truncated at %d bytes]\n", curatedMaxBytes)
	}
	return nil
}
