/*
Copyright © 2026 Security Research
*/
package cmd

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/pkg/httpshell"

	"github.com/spf13/cobra"
)

var (
	httpshellPort string
	httpshellURL  string
	httpshellID   string
)

var httpshellCmd = &cobra.Command{
	Use:   "httpshell",
	Short: "Secure cross-platform command execution over HTTPS",
	Long: `HTTP Shell v` + httpshell.Version + ` - Secure Cross-Platform Command Execution over HTTPS

A tool for local development testing across different operating systems.

Security Features:
  - Authentication: 6-character Auth ID generated at startup
  - Network restriction: Only 192.168.15.100-109 allowed
  - Path restriction: Only /home/*, B:\*, C:\Users\* accessible
  - Transport: HTTPS with auto-generated self-signed certificate`,
}

var httpshellServerCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the HTTPS shell server",
	Long:  "Start the HTTPS shell server with authentication and security features.",
	Run:   runHTTPShellServer,
}

var httpshellClientCmd = &cobra.Command{
	Use:   "client [command]",
	Short: "Connect to a remote HTTP shell server",
	Long: `Connect to a remote HTTP shell server with authentication.

If no command is provided, starts an interactive session.
If a command is provided, executes it and exits.

Examples:
  unravel httpshell client --url https://192.168.15.101:8765 --id ABC123
  unravel httpshell client --url https://192.168.15.101:8765 --id ABC123 "uname -a"`,
	Run: runHTTPShellClient,
}

var httpshellInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show remote server information",
	Long: `Display information about a remote HTTP shell server.

Examples:
  unravel httpshell info --url https://192.168.15.101:8765 --id ABC123`,
	Run: runHTTPShellInfo,
}

func init() {
	rootCmd.AddCommand(httpshellCmd)
	httpshellCmd.AddCommand(httpshellServerCmd)
	httpshellCmd.AddCommand(httpshellClientCmd)
	httpshellCmd.AddCommand(httpshellInfoCmd)

	httpshellServerCmd.Flags().StringVarP(&httpshellPort, "port", "p", "8765", "Port to listen on")

	httpshellClientCmd.Flags().StringVarP(&httpshellURL, "url", "u", "", "Server URL (required)")
	httpshellClientCmd.Flags().StringVarP(&httpshellID, "id", "i", "", "Auth ID (required)")
	_ = httpshellClientCmd.MarkFlagRequired("url")
	_ = httpshellClientCmd.MarkFlagRequired("id")

	httpshellInfoCmd.Flags().StringVarP(&httpshellURL, "url", "u", "", "Server URL (required)")
	httpshellInfoCmd.Flags().StringVarP(&httpshellID, "id", "i", "", "Auth ID (required)")
	_ = httpshellInfoCmd.MarkFlagRequired("url")
	_ = httpshellInfoCmd.MarkFlagRequired("id")
}

func runHTTPShellServer(_ *cobra.Command, _ []string) {
	server := &httpshell.Server{
		AuthID:    httpshell.GenerateAuthID(),
		StartTime: time.Now(),
		WorkDir:   httpshell.MustGetwd(),
	}

	if !httpshell.IsAllowedPath(server.WorkDir) {
		if runtime.GOOS == "windows" {
			homeDir, _ := os.UserHomeDir()
			if homeDir != "" && httpshell.IsAllowedPath(homeDir) {
				server.WorkDir = homeDir
			} else {
				server.WorkDir = "C:\\Users"
			}
		} else {
			server.WorkDir = "/home"
		}

		fmt.Printf("[!] Initial directory not allowed, defaulting to: %s\n", server.WorkDir)
	}

	for i := 100; i <= 109; i++ {
		server.AllowedIPs = append(server.AllowedIPs, fmt.Sprintf("192.168.15.%d", i))
	}

	server.DetectShell()
	server.LocalIP = httpshell.GetLocalAllowedIP()

	// Security: httpshell is a localhost-only dev tool. Always bind to the
	// loopback address — never to 0.0.0.0 or a LAN interface. Binding to
	// 0.0.0.0 would expose the RCE endpoint to every network-adjacent
	// process on the same LAN even with the IP allowlist in place.
	const bindAddr = "127.0.0.1"

	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)
	server.CertFile = filepath.Join(exeDir, "http_shell.crt")
	server.KeyFile = filepath.Join(exeDir, "http_shell.key")

	_, certErr := os.Stat(server.CertFile)

	_, keyErr := os.Stat(server.KeyFile)
	if os.IsNotExist(certErr) || os.IsNotExist(keyErr) {
		server.Log("INFO", "Generating self-signed certificate...")

		if err := httpshell.GenerateSelfSignedCert(server.CertFile, server.KeyFile); err != nil {
			fmt.Printf("[-] Failed to generate certificate: %v\n", err)
			os.Exit(1)
		}

		server.Log("INFO", "Certificate generated: %s", server.CertFile)
	}

	hostname, _ := os.Hostname()
	localIPs := httpshell.GetLocalIPs()

	fmt.Printf("HTTP Shell Server v%s\n", httpshell.Version)
	fmt.Printf("Auth ID:    %s\n", server.AuthID)
	fmt.Printf("Platform:   %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("Hostname:   %s\n", hostname)
	fmt.Printf("Shell:      %s\n", server.Shell)
	fmt.Printf("WorkDir:    %s\n", server.WorkDir)
	fmt.Println()
	fmt.Println("Machine IPs:")

	for _, ip := range localIPs {
		marker := "  "
		if httpshell.IsAllowedIP(ip) {
			marker = "* "
		}

		fmt.Printf("  %s%s\n", marker, ip)
	}

	fmt.Println()
	fmt.Printf("Bind:          %s (loopback only)\n", bindAddr)
	fmt.Printf("Allowed Paths: /home/*, B:\\*, C:\\Users\\*\n")
	fmt.Printf("HTTPS:         https://%s:%s\n", bindAddr, httpshellPort)

	fmt.Println()

	server.Log("INFO", "Server starting...")
	server.Log("INFO", "Auth ID: %s", server.AuthID)
	server.Log("INFO", "Press Ctrl+C to stop server")
	fmt.Println()

	mux := http.NewServeMux()
	mux.HandleFunc("/", server.WithMiddleware(server.HandleInfo))
	mux.HandleFunc("/health", server.WithMiddleware(server.HandleHealth))
	mux.HandleFunc("/exec", server.WithMiddleware(server.HandleExec))
	mux.HandleFunc("/history", server.WithMiddleware(server.HandleHistory))
	mux.HandleFunc("/cd", server.WithMiddleware(server.HandleCD))

	srv := &http.Server{
		Addr:              bindAddr + ":" + httpshellPort,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// WriteTimeout intentionally 0: interactive shell sessions are long-lived; a non-zero WriteTimeout terminates them.
		WriteTimeout: 0,
		IdleTimeout:  120 * time.Second,
	}
	if err := srv.ListenAndServeTLS(server.CertFile, server.KeyFile); err != nil {
		fmt.Printf("[-] Server error: %v\n", err)
		os.Exit(1)
	}
}

func runHTTPShellClient(_ *cobra.Command, args []string) {
	serverURL := strings.TrimSuffix(httpshellURL, "/")

	if !httpshell.IsAllowedURL(serverURL) {
		fmt.Println("[-] Error: Target server must be in range 192.168.15.100-109")
		os.Exit(1)
	}

	authID := httpshell.NormalizeAuthID(httpshellID)
	client := httpshell.NewClient(serverURL, authID)

	if len(args) > 0 {
		command := strings.Join(args, " ")
		if err := client.RunSingleCommand(command); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	} else {
		if err := client.RunInteractive(); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	}
}

func runHTTPShellInfo(_ *cobra.Command, _ []string) {
	serverURL := strings.TrimSuffix(httpshellURL, "/")

	if !httpshell.IsAllowedURL(serverURL) {
		fmt.Println("[-] Error: Target server must be in range 192.168.15.100-109")
		os.Exit(1)
	}

	authID := httpshell.NormalizeAuthID(httpshellID)
	client := httpshell.NewClient(serverURL, authID)

	if err := client.ShowServerInfo(); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}
