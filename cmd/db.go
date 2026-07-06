/*
Copyright (c) 2026 Security Research
*/
// cmd/db.go owns the `unravel db` family of commands that configure the
// Postgres-backed knowledge catalog (config.yaml + OS keychain).
//
// Subcommand map:
//
//	db setup              interactive first-run: prompts host/port/user/dbname/password,
//	                      generates an encryption key in the OS keychain, encrypts the
//	                      password under it, writes %LOCALAPPDATA%\Unravel\config.yaml.
//	db status             show resolved DSN (password REDACTED) and ping the pool.
//	db rotate-password    prompt for a new password, re-encrypt, save.

package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/config"
	"github.com/inovacc/unravel-oss/pkg/crypto"
	"github.com/inovacc/unravel-oss/pkg/keychain"
	kbdb "github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// stdinReader is a single bufio.Reader shared across all prompts so a
// blank-Enter on one prompt does not leave a stale newline that the next
// prompt reads as its own input. Initialised lazily on first prompt.
var stdinReader *bufio.Reader

var dbCmd = &cobra.Command{
	Use:   "db",
	Short: "Configure the Postgres knowledge catalog",
	Long: `Configure the Postgres-backed knowledge catalog.

config.yaml lives at %LOCALAPPDATA%\Unravel\config.yaml (or
$XDG_CONFIG_HOME/unravel/config.yaml on Unix). The Postgres password is
stored as base64 ciphertext in config.yaml.password_enc, encrypted under
a 32-byte AES-256-GCM data key kept in the OS keychain
(service="unravel", account="db-encryption-key").

Override config.yaml at runtime with UNRAVEL_DB_PASSWORD or by passing a
--database postgres://... DSN to any knowledge subcommand.`,
}

var (
	setupHost     string
	setupPort     int
	setupUser     string
	setupDBName   string
	setupSSLMode  string
	setupPassword string
	setupNoPing   bool
)

// dbSetupCmd (`unravel db setup`) lives in db_setup.go and reuses the
// setup* flag vars declared above plus the runDBSetup handler below.

var dbStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show resolved config and ping the Postgres pool",
	RunE:  runDBStatus,
}

var dbRotatePasswordCmd = &cobra.Command{
	Use:   "rotate-password",
	Short: "Prompt for a new Postgres password, re-encrypt, save",
	RunE:  runDBRotatePassword,
}

func init() {
	dbCmd.AddCommand(dbStatusCmd)
	dbCmd.AddCommand(dbRotatePasswordCmd)
	rootCmd.AddCommand(dbCmd)
}

func runDBSetup(_ *cobra.Command, _ []string) error {
	cfg, err := config.Load()
	if errors.Is(err, config.ErrConfigNotFound) {
		cfg = config.Default()
	} else if err != nil {
		return err
	}

	// Resolve each field: flag > existing config > built-in default. Only
	// fall back to interactive prompt when stdin is a real terminal AND
	// the user gave neither flag nor existing config — avoids the freeze
	// on shells where stdin doesn't surface input cleanly.
	host := pickString(setupHost, cfg.Database.Host, config.DefaultHost, "Postgres host")
	port := pickInt(setupPort, cfg.Database.Port, config.DefaultPort, "Postgres port")
	user := pickString(setupUser, cfg.Database.User, config.DefaultUser, "Postgres user")
	dbname := pickString(setupDBName, cfg.Database.DBName, config.DefaultDBName, "Database name")
	sslmode := pickString(setupSSLMode, cfg.Database.SSLMode, config.DefaultSSLMode, "SSL mode (prefer|require|disable|verify-full)")

	password := setupPassword
	if password == "" {
		password = os.Getenv("UNRAVEL_DB_PASSWORD")
	}
	if password == "" {
		// Last resort — prompt only if we have a real TTY. On a non-TTY
		// the call would otherwise freeze; fail fast with a clear hint.
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return fmt.Errorf("no --password / UNRAVEL_DB_PASSWORD set and stdin is not a terminal")
		}
		pw, err := readPassword("Postgres password: ")
		if err != nil {
			return fmt.Errorf("read password: %w", err)
		}
		password = pw
	}
	if password == "" {
		return fmt.Errorf("password required")
	}

	cfg.Database.Host = strings.TrimSpace(host)
	cfg.Database.Port = port
	cfg.Database.User = strings.TrimSpace(user)
	cfg.Database.DBName = strings.TrimSpace(dbname)
	cfg.Database.SSLMode = strings.TrimSpace(sslmode)

	// Generate/load the keychain data key — first call creates a 32-byte
	// AES-256-GCM key under keychain.AccountEncryptionKey.
	if _, err := crypto.LoadOrGenerateDataKey(); err != nil {
		return fmt.Errorf("data key: %w", err)
	}

	// Remove any legacy plaintext password mirror from prior installs. The
	// password is stored only as config.yaml.password_enc ciphertext; the
	// keychain holds just the AES-256-GCM data key (AccountEncryptionKey).
	// Best-effort: never fail setup because a stale entry can't be removed.
	if err := keychain.Delete(keychain.AccountDBPassword); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not remove legacy db-password keychain mirror: %v\n", err)
	}

	if err := cfg.SetPassword(password); err != nil {
		return fmt.Errorf("encrypt password: %w", err)
	}
	if err := config.Save(cfg); err != nil {
		return err
	}

	fmt.Printf("config.yaml written to %s\n", config.Path())
	fmt.Printf("DSN: %s\n", cfg.Redacted())

	// Eager ping so the user knows immediately whether the credentials are
	// good against a live cluster — better feedback than waiting for the
	// next `unravel knowledge` invocation to fail.
	conn, err := kbdb.Open(context.Background(), "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: open failed: %v\n", err)
		return nil
	}
	defer func() { _ = conn.Close() }()
	if err := kbdb.Ping(context.Background(), conn); err != nil {
		fmt.Fprintf(os.Stderr, "warn: ping failed: %v\n", err)
		return nil
	}
	fmt.Println("ping OK — schema applied, pool reachable")
	return nil
}

func runDBStatus(_ *cobra.Command, _ []string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	fmt.Printf("config: %s\n", config.Path())
	fmt.Printf("dsn:    %s\n", cfg.Redacted())

	conn, err := kbdb.Open(context.Background(), "")
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if err := kbdb.Ping(context.Background(), conn); err != nil {
		return err
	}
	fmt.Println("ping:   OK")
	return nil
}

func runDBRotatePassword(_ *cobra.Command, _ []string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	password, err := readPassword("New Postgres password: ")
	if err != nil {
		return fmt.Errorf("read password: %w", err)
	}
	if password == "" {
		return fmt.Errorf("password required")
	}
	// Remove any legacy plaintext password mirror (best-effort; see db setup).
	if err := keychain.Delete(keychain.AccountDBPassword); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not remove legacy db-password keychain mirror: %v\n", err)
	}
	if err := cfg.SetPassword(password); err != nil {
		return err
	}
	if err := config.Save(cfg); err != nil {
		return err
	}
	fmt.Println("password rotated. Restart any long-running unravel processes.")
	return nil
}

// pickString resolves a config field by flag > existing > builtin default,
// falling back to an interactive prompt only when stdin is a real TTY.
// Non-TTY callers (CI, wrappers, mintty without proper console binding)
// silently take the existing or builtin default to avoid a freeze.
func pickString(flag, existing, builtin, prompt string) string {
	if flag != "" {
		return flag
	}
	def := existing
	if def == "" {
		def = builtin
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return def
	}
	return promptDefault(prompt, def)
}

// pickInt mirrors pickString for integer fields.
func pickInt(flag, existing, builtin int, prompt string) int {
	if flag != 0 {
		return flag
	}
	def := existing
	if def == 0 {
		def = builtin
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return def
	}
	s := promptDefault(prompt, strconv.Itoa(def))
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 && n <= 65535 {
		return n
	}
	return def
}

// promptDefault prints "prompt [default]: " and returns the user's reply,
// falling back to def when the reply is blank.
//
// Uses bufio.Reader.ReadString('\n') instead of fmt.Fscanln (which blocks
// on blank input) and explicitly writes the prompt to os.Stdout so the
// terminal flushes before we block on read — the prior Stderr-only path
// looked like a freeze on Windows because Stderr is line-buffered when
// the parent process owns the console.
func promptDefault(prompt, def string) string {
	if stdinReader == nil {
		stdinReader = bufio.NewReader(os.Stdin)
	}
	if def == "" {
		fmt.Fprintf(os.Stdout, "%s: ", prompt)
	} else {
		fmt.Fprintf(os.Stdout, "%s [%s]: ", prompt, def)
	}
	_ = os.Stdout.Sync()
	line, err := stdinReader.ReadString('\n')
	if err != nil && line == "" {
		return def
	}
	line = strings.TrimRight(line, "\r\n ")
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

// readPassword reads a password from stdin. Tries non-echo terminal mode
// first; falls back to plain ReadString when stdin is not a console
// (mintty, ConEmu, piped input). Falls back to UNRAVEL_DB_PASSWORD env
// var when stdin is fully detached.
func readPassword(prompt string) (string, error) {
	if v := os.Getenv("UNRAVEL_DB_PASSWORD"); v != "" {
		return v, nil
	}
	fmt.Fprint(os.Stdout, prompt)
	_ = os.Stdout.Sync()

	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		pw, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stdout)
		if err != nil {
			return "", err
		}
		return string(pw), nil
	}
	// Non-terminal stdin (e.g. piped, mintty): fall back to echoed read.
	if stdinReader == nil {
		stdinReader = bufio.NewReader(os.Stdin)
	}
	line, err := stdinReader.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n ")
	return line, nil
}
