/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var dpapiCmd = &cobra.Command{
	Use:   "dpapi",
	Short: "Windows DPAPI decryption",
	Long: `Decrypt Windows DPAPI protected data.

Used to decrypt Chromium cookies and other protected data on Windows.
Requires running as the same user who encrypted the data.

Note: Requires Windows + CGO for full functionality.
Build with: CGO_ENABLED=1 GOOS=windows go build .`,
}

var dpapiDecryptCmd = &cobra.Command{
	Use:   "decrypt <profile_path>",
	Short: "Decrypt Chromium cookies and passwords",
	Args:  cobra.ExactArgs(1),
	Run:   runDpapiDecrypt,
}

// runDpapiDecrypt is the default (non-CGO/non-Windows) implementation.
// When built with CGO on Windows, dpapi_cgo.go overrides this via init().
var runDpapiDecrypt = func(cmd *cobra.Command, args []string) {
	if runtime.GOOS != "windows" {
		fmt.Println("Error: DPAPI is only available on Windows")
		return
	}

	profilePath := args[0]
	fmt.Printf("Profile: %s\n", profilePath)
	fmt.Println("\nNote: Full DPAPI decryption requires CGO for SQLite support.")
	fmt.Println("Rebuild with: CGO_ENABLED=1 go build .")
}

func init() {
	rootCmd.AddCommand(dpapiCmd)
	dpapiCmd.AddCommand(dpapiDecryptCmd)
}
