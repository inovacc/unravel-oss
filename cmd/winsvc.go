/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/inovacc/unravel-oss/pkg/winsvc"

	"github.com/spf13/cobra"
)

var winsvcCmd = &cobra.Command{
	Use:   "winsvc",
	Short: "Manage Windows services associated with apps",
}

var winsvcListCmd = &cobra.Command{
	Use:   "list <app-dir>",
	Short: "List services associated with binaries in a directory",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		res, err := winsvc.ScanForServices(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if len(res.Services) == 0 {
			fmt.Println("No services found in this directory.")
			return
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tDISPLAY NAME\tSTATUS\tSTART")
		for _, s := range res.Services {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", s.Name, s.DisplayName, s.Status, s.StartType)
		}
		w.Flush()
	},
}

var winsvcStartCmd = &cobra.Command{
	Use:   "start <name>",
	Short: "Start a Windows service",
	Args:  cobra.ExactArgs(1),
	Run:   runWinSvcControl(winsvc.ActionStart),
}

var winsvcStopCmd = &cobra.Command{
	Use:   "stop <name>",
	Short: "Stop a Windows service",
	Args:  cobra.ExactArgs(1),
	Run:   runWinSvcControl(winsvc.ActionStop),
}

var winsvcRestartCmd = &cobra.Command{
	Use:   "restart <name>",
	Short: "Restart a Windows service",
	Args:  cobra.ExactArgs(1),
	Run:   runWinSvcControl(winsvc.ActionRestart),
}

func runWinSvcControl(action winsvc.ServiceAction) func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		name := args[0]
		fmt.Printf("%sing service %q...\n", string(action), name)
		if err := winsvc.ControlService(name, action); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Done.")
	}
}

func init() {
	rootCmd.AddCommand(winsvcCmd)
	winsvcCmd.AddCommand(winsvcListCmd)
	winsvcCmd.AddCommand(winsvcStartCmd)
	winsvcCmd.AddCommand(winsvcStopCmd)
	winsvcCmd.AddCommand(winsvcRestartCmd)
}
