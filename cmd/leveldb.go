/*
Copyright © 2026 Security Research
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/inovacc/unravel-oss/pkg/leveldb"

	"github.com/spf13/cobra"
)

var leveldbCmd = &cobra.Command{
	Use:   "leveldb",
	Short: "Parse LevelDB databases",
	Long: `Parse and extract data from LevelDB databases.

LevelDB is used by Chromium for Local Storage, Session Storage,
and IndexedDB.`,
}

var leveldbParseCmd = &cobra.Command{
	Use:   "parse <leveldb_path>",
	Short: "Parse LevelDB and extract key-value pairs",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		dbPath := args[0]

		fmt.Printf("Parsing LevelDB: %s\n\n", dbPath)

		result, err := leveldb.ParseDirectory(dbPath)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		if jsonFormat {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Print(leveldb.FormatSummary(result))

		// Write output files if output dir specified
		if output != "" {
			_ = os.MkdirAll(output, 0755)

			resultPath := filepath.Join(output, "parsed_data.json")
			data, _ := json.MarshalIndent(result, "", "  ")
			_ = os.WriteFile(resultPath, data, 0644)
			fmt.Printf("\nOutput: %s\n", resultPath)
		}

		fmt.Printf("\nTotal: %d entries (%d valid, %d deleted, %d errors)\n",
			result.Stats.TotalEntries, result.Stats.ValidEntries,
			result.Stats.DeletedEntries, result.Stats.ParseErrors)
	},
}

func init() {
	rootCmd.AddCommand(leveldbCmd)
	leveldbCmd.AddCommand(leveldbParseCmd)
	leveldbParseCmd.Flags().BoolVar(&jsonFormat, "json", false, "Output as JSON")
}
