/*
Copyright (c) 2026 Security Research

Test-only helper that lets integration tests inject a DSN via config.yaml,
since the production CLI no longer reads --dsn / UNRAVEL_KB_DSN.
*/

package cmd

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// pinDSNViaConfig writes a temp config.yaml describing dsn (a postgres URL)
// and points UNRAVEL_CONFIG / UNRAVEL_DB_PASSWORD at it for the duration of
// the test. Replaces the legacy `t.Setenv("UNRAVEL_KB_DSN", dsn)` pattern
// after the production code went config-only.
func pinDSNViaConfig(t *testing.T, dsn string) {
	t.Helper()

	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse test dsn %q: %v", dsn, err)
	}

	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	user := u.User.Username()
	pw, _ := u.User.Password()
	dbname := ""
	if len(u.Path) > 1 {
		dbname = u.Path[1:]
	}
	sslmode := u.Query().Get("sslmode")
	if sslmode == "" {
		sslmode = "disable"
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	yaml := fmt.Sprintf(
		"database:\n  host: %s\n  port: %d\n  user: %s\n  dbname: %s\n  sslmode: %s\n",
		host, port, user, dbname, sslmode,
	)
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write test config.yaml: %v", err)
	}

	t.Setenv("UNRAVEL_CONFIG", cfgPath)
	t.Setenv("UNRAVEL_DB_PASSWORD", pw) // bypass keychain in tests
}
