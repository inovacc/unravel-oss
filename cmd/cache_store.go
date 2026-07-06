/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/inovacc/unravel-oss/pkg/store"

	"github.com/spf13/cobra"
)

var storeCmd = &cobra.Command{
	Use:   "store",
	Short: "Manage the analysis result cache",
	Long: `Manage cached analysis results stored at %LOCALAPPDATA%/Unravel/cache/.

Each dissect/analyze run can cache its results for later retrieval.
Cache entries are indexed in cache.json with UUIDv7 identifiers.

Subcommands:
  list   - Show all cached entries
  get    - Retrieve a cached entry
  find   - Search cache by source file
  delete - Remove a cached entry
  prune  - Remove entries older than a duration
  path   - Show cache directory paths
  reconcile - Migrate to sharded layout and GC orphaned dirs`,
}

var storeListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all cached analysis entries",
	Run:   runStoreList,
}

var storeGetCmd = &cobra.Command{
	Use:   "get <id>",
	Short: "Show details of a cached entry",
	Args:  cobra.ExactArgs(1),
	Run:   runStoreGet,
}

var storeFindCmd = &cobra.Command{
	Use:   "find <source-path>",
	Short: "Find cached entries for a source file",
	Args:  cobra.ExactArgs(1),
	Run:   runStoreFind,
}

var storeDeleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Delete a cached entry",
	Args:  cobra.ExactArgs(1),
	Run:   runStoreDelete,
}

var storePruneCmd = &cobra.Command{
	Use:   "prune [duration]",
	Short: "Remove entries older than duration (default: 30d)",
	Args:  cobra.MaximumNArgs(1),
	Run:   runStorePrune,
}

var storePathCmd = &cobra.Command{
	Use:   "path",
	Short: "Show cache directory and index paths",
	Run:   runStorePath,
}

var storeReconcileDryRun bool

var storeReconcileCmd = &cobra.Command{
	Use:   "reconcile",
	Short: "Migrate the cache to the sharded layout and GC orphaned dirs",
	Long: `Reconcile moves any legacy flat cache entries into the 256-bucket
sharded layout (cache/{shard}/{id}/), backfills missing entry sizes, and
removes orphaned cache directories not referenced by the index.

Use --dry-run to preview without changing anything.`,
	Run: runStoreReconcile,
}

var storeJSONFormat bool

func init() {
	rootCmd.AddCommand(storeCmd)
	storeCmd.AddCommand(storeListCmd)
	storeCmd.AddCommand(storeGetCmd)
	storeCmd.AddCommand(storeFindCmd)
	storeCmd.AddCommand(storeDeleteCmd)
	storeCmd.AddCommand(storePruneCmd)
	storeCmd.AddCommand(storePathCmd)
	storeCmd.AddCommand(storeReconcileCmd)
	storeReconcileCmd.Flags().BoolVar(&storeReconcileDryRun, "dry-run", false, "Preview without changing anything")

	storeCmd.PersistentFlags().BoolVar(&storeJSONFormat, "json", false, "Output as JSON")
}

func runStoreList(_ *cobra.Command, _ []string) {
	s := store.New()

	entries, err := s.List()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if storeJSONFormat {
		data, _ := json.MarshalIndent(entries, "", "  ")
		fmt.Println(string(data))

		return
	}

	if len(entries) == 0 {
		fmt.Println("No cached entries.")

		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	_, _ = fmt.Fprintf(w, "ID\tTYPE\tSOURCE\tCREATED\n")
	_, _ = fmt.Fprintf(w, "──\t────\t──────\t───────\n")

	for _, e := range entries {
		age := time.Since(e.CreatedAt).Truncate(time.Minute)
		source := e.SourcePath
		if len(source) > 50 {
			source = "..." + source[len(source)-47:]
		}

		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s ago\n", e.ID[:8], e.Type, source, age)
	}

	_ = w.Flush()
	fmt.Printf("\nTotal: %d entries\n", len(entries))
}

func runStoreGet(_ *cobra.Command, args []string) {
	s := store.New()

	// Support partial ID match
	entries, _ := s.List()

	var match *store.Entry

	for i := range entries {
		if entries[i].ID == args[0] || (len(args[0]) >= 8 && entries[i].ID[:len(args[0])] == args[0]) {
			match = &entries[i]

			break
		}
	}

	if match == nil {
		fmt.Printf("Entry not found: %s\n", args[0])
		os.Exit(1)
	}

	if storeJSONFormat {
		data, _ := json.MarshalIndent(match, "", "  ")
		fmt.Println(string(data))

		return
	}

	fmt.Printf("ID:         %s\n", match.ID)
	fmt.Printf("Type:       %s\n", match.Type)
	fmt.Printf("Source:     %s\n", match.SourcePath)
	fmt.Printf("Hash:       %s\n", match.SourceHash)
	fmt.Printf("Size:       %d bytes\n", match.SourceSize)
	fmt.Printf("Created:    %s\n", match.CreatedAt.Format(time.RFC3339))
	fmt.Printf("Cache Dir:  %s\n", match.CacheDir)

	if len(match.Tags) > 0 {
		fmt.Printf("Tags:       %v\n", match.Tags)
	}

	if len(match.Metadata) > 0 {
		fmt.Println("Metadata:")
		for k, v := range match.Metadata {
			fmt.Printf("  %s: %s\n", k, v)
		}
	}
}

func runStoreFind(_ *cobra.Command, args []string) {
	s := store.New()
	matches := s.Find(args[0])

	if storeJSONFormat {
		data, _ := json.MarshalIndent(matches, "", "  ")
		fmt.Println(string(data))

		return
	}

	if len(matches) == 0 {
		fmt.Printf("No cached entries for: %s\n", args[0])

		return
	}

	for _, e := range matches {
		fmt.Printf("%s  %s  %s  %s\n", e.ID[:8], e.Type, e.CreatedAt.Format("2006-01-02"), e.SourcePath)
	}
}

func runStoreDelete(_ *cobra.Command, args []string) {
	s := store.New()

	if err := s.Delete(args[0]); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Deleted: %s\n", args[0])
}

func runStorePrune(_ *cobra.Command, args []string) {
	maxAge := 30 * 24 * time.Hour // 30 days default

	if len(args) > 0 {
		d, err := time.ParseDuration(args[0])
		if err != nil {
			fmt.Printf("Invalid duration: %v\n", err)
			os.Exit(1)
		}

		maxAge = d
	}

	s := store.New()

	pruned, err := s.Prune(maxAge)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Pruned %d entries older than %s\n", pruned, maxAge)
}

func runStoreReconcile(_ *cobra.Command, _ []string) {
	s := store.New()

	rep, err := s.Reconcile(storeReconcileDryRun)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	prefix := ""
	if storeReconcileDryRun {
		prefix = "[dry-run] "
	}

	fmt.Printf("%smigrated=%d size_backfilled=%d orphans_gc=%d bytes_reclaimed=%d\n",
		prefix, rep.Migrated, rep.SizeBackfilled, rep.OrphansGC, rep.BytesReclaimed)
}

func runStorePath(_ *cobra.Command, _ []string) {
	fmt.Printf("Cache directory: %s\n", store.CacheDir())
	fmt.Printf("Index file:      %s\n", store.IndexPath())
}
