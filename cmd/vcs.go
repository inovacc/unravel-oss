/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/inovacc/unravel-oss/pkg/config"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"
	"github.com/inovacc/unravel-oss/pkg/knowledge/svc"

	"github.com/spf13/cobra"
)

var vcsCmd = &cobra.Command{
	Use:   "vcs",
	Short: "Source Version Control for Knowledge Sources (Git-managed)",
}

var vcsStatusCmd = &cobra.Command{
	Use:   "status <app-slug>",
	Short: "Show Git status of an app's Knowledge Source repository",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		service := vcsInitService()
		status, err := service.Status(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if status == "" {
			fmt.Println("Clean (no changes)")
		} else {
			fmt.Print(status)
		}
	},
}

var vcsLogCmd = &cobra.Command{
	Use:   "log <app-slug>",
	Short: "Show Git log (epochs) of an app's Knowledge Source repository",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		service := vcsInitService()
		log, err := service.Log(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(log)
	},
}

var vcsCheckoutCmd = &cobra.Command{
	Use:   "checkout <app-slug> <ref>",
	Short: "Checkout a specific version/ref in the app's repository",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		service := vcsInitService()
		fmt.Printf("Checking out %q for %s...\n", args[1], args[0])
		if err := service.Checkout(args[0], args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Done.")
	},
}

var (
	vcsCaptureVersion string
	vcsCaptureAuthor  string
	vcsCaptureMessage string
)

var vcsCaptureCmd = &cobra.Command{
	Use:   "capture <app-slug> <path>",
	Short: "Capture source code into a Git-managed Knowledge Source",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		slug := args[0]
		path := args[1]

		service := vcsInitService()
		ctx := context.Background()

		fmt.Printf("Capturing %s from %q...\n", slug, path)

		// 1. Ensure target repo exists and is clean-ish
		repoPath, err := service.RepoPath(slug)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		// 2. Mirror files from source to repo (using a simple sync logic for now)
		if err := runShell(fmt.Sprintf("robocopy %q %q /MIR /XD .git /R:1 /W:1 /NP /NFL /NDL", path, repoPath)); err != nil {
			// robocopy returns non-zero for success
		}

		res, err := service.Capture(ctx, svc.CaptureOptions{
			AppSlug: slug,
			Version: vcsCaptureVersion,
			Source:  path,
			Author:  vcsCaptureAuthor,
			Message: vcsCaptureMessage,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Successfully captured %s (Epoch %d, Commit %s)\n", slug, res.Epoch, res.Commit[:8])
		fmt.Printf("Stored at: %s\n", res.Path)
	},
}

var vcsSyncCmd = &cobra.Command{
	Use:   "sync <app-slug>",
	Short: "Synchronize/Reconstruct local Knowledge Source repository from Knowledge Base",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		slug := args[0]
		service := vcsInitService()
		ctx := context.Background()

		fmt.Printf("Synchronizing %s from Knowledge Base...\n", slug)
		if err := service.Sync(ctx, slug); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Done.")
	},
}

var vcsGrepCmd = &cobra.Command{
	Use:   "grep <app-slug> <pattern>",
	Short: "Fast full-text search over the app's code repository (git grep)",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		slug := args[0]
		pattern := args[1]
		service := vcsInitService()

		fmt.Printf("Searching %s for %q...\n", slug, pattern)
		results, err := service.Grep(slug, pattern)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if results == "" {
			fmt.Println("No matches found.")
		} else {
			fmt.Print(results)
		}
	},
}

func runShell(command string) error {
	cmd := exec.Command("powershell", "-NoProfile", "-Command", command)
	return cmd.Run()
}

func vcsInitService() *svc.KSService {
	ctx := context.Background()
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: load config: %v\n", err)
		os.Exit(1)
	}

	dsn, err := cfg.DSN(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: resolve DSN: %v\n", err)
		os.Exit(1)
	}

	conn, err := db.Open(ctx, dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: connect database: %v\n", err)
		os.Exit(1)
	}

	return svc.NewKSService(conn, cfg.KBStorePath())
}

func init() {
	vcsCaptureCmd.Flags().StringVar(&vcsCaptureVersion, "version", "1.0.0", "Version string for this capture")
	vcsCaptureCmd.Flags().StringVar(&vcsCaptureAuthor, "author", "Unravel", "Author name for the Git commit")
	vcsCaptureCmd.Flags().StringVar(&vcsCaptureMessage, "message", "", "Custom commit message")

	rootCmd.AddCommand(vcsCmd)
	vcsCmd.AddCommand(vcsStatusCmd)
	vcsCmd.AddCommand(vcsLogCmd)
	vcsCmd.AddCommand(vcsCheckoutCmd)
	vcsCmd.AddCommand(vcsCaptureCmd)
	vcsCmd.AddCommand(vcsSyncCmd)
	vcsCmd.AddCommand(vcsGrepCmd)
}
