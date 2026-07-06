// Package config loads/saves %LOCALAPPDATA%\Unravel\config.yaml.
//
// The Postgres password is stored as base64 ciphertext in PasswordEnc,
// encrypted under the AES-256-GCM data key from
// keychain.AccountEncryptionKey. Decrypt via DSN(ctx) which returns a
// fully-resolved DSN ready for pgxpool.ParseConfig.
package config

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/crypto"

	"gopkg.in/yaml.v3"
)

// DefaultHost / DefaultPort are the project-default Postgres endpoint
// (the local lab box). `unravel db setup` writes them on first run.
const (
	DefaultHost    = "192.168.15.100"
	DefaultPort    = 5432
	DefaultUser    = "unravel_app"
	DefaultDBName  = "unravel"
	DefaultSSLMode = "prefer"
)

// Database is the database section of config.yaml.
type Database struct {
	Host        string `yaml:"host"`
	Port        int    `yaml:"port"`
	User        string `yaml:"user"`
	DBName      string `yaml:"dbname"`
	SSLMode     string `yaml:"sslmode"`
	PasswordEnc string `yaml:"password_enc,omitempty"` // base64 AES-GCM ciphertext
}

// Config is the top-level config.yaml shape.
type Config struct {
	Database Database `yaml:"database"`
}

// ErrConfigNotFound — config.yaml does not exist on disk. Run `unravel db setup`.
var ErrConfigNotFound = errors.New("config: config.yaml not found — run `unravel db setup`")

// Path returns %LOCALAPPDATA%\Unravel\config.yaml on Windows, or
// $XDG_CONFIG_HOME/unravel/config.yaml / $HOME/.config/unravel/config.yaml
// on Unix.
func Path() string {
	if v := os.Getenv("UNRAVEL_CONFIG"); v != "" {
		return v
	}
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		return filepath.Join(local, "Unravel", "config.yaml")
	}
	if home, err := os.UserConfigDir(); err == nil {
		return filepath.Join(home, "unravel", "config.yaml")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config", "unravel", "config.yaml")
	}
	return filepath.Join(os.TempDir(), "unravel", "config.yaml")
}

// Default returns a Config seeded with project defaults (host/port set,
// password fields empty — caller must run `unravel db setup`).
func Default() Config {
	return Config{Database: Database{
		Host:    DefaultHost,
		Port:    DefaultPort,
		User:    DefaultUser,
		DBName:  DefaultDBName,
		SSLMode: DefaultSSLMode,
	}}
}

// Load reads config.yaml. Returns ErrConfigNotFound when the file is
// missing; other I/O / parse errors are wrapped verbatim.
func Load() (Config, error) {
	return LoadFrom(Path())
}

// LoadFrom is Load with an explicit path (used by tests).
func LoadFrom(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Config{}, ErrConfigNotFound
		}
		return Config{}, fmt.Errorf("config read %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("config parse %s: %w", path, err)
	}
	cfg.applyDefaults()
	return cfg, nil
}

// Save writes cfg to Path() with 0600 permissions.
func Save(cfg Config) error {
	return SaveTo(cfg, Path())
}

// SaveTo is Save with an explicit path.
func SaveTo(cfg Config, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("config mkdir: %w", err)
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("config marshal: %w", err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return fmt.Errorf("config write %s: %w", path, err)
	}
	return nil
}

func (c *Config) applyDefaults() {
	if c.Database.Host == "" {
		c.Database.Host = DefaultHost
	}
	if c.Database.Port == 0 {
		c.Database.Port = DefaultPort
	}
	if c.Database.User == "" {
		c.Database.User = DefaultUser
	}
	if c.Database.DBName == "" {
		c.Database.DBName = DefaultDBName
	}
	if c.Database.SSLMode == "" {
		c.Database.SSLMode = DefaultSSLMode
	}
}

// SetPassword encrypts plaintext under the keychain data key and stores
// the base64 ciphertext in c.Database.PasswordEnc.
func (c *Config) SetPassword(plaintext string) error {
	key, err := crypto.LoadOrGenerateDataKey()
	if err != nil {
		return fmt.Errorf("set password: %w", err)
	}
	enc, err := crypto.EncryptString(plaintext, key)
	if err != nil {
		return fmt.Errorf("set password: %w", err)
	}
	c.Database.PasswordEnc = enc
	return nil
}

// Password returns the decrypted Postgres password. Allows env override
// UNRAVEL_DB_PASSWORD for headless / container deployments.
func (c Config) Password() (string, error) {
	if v := os.Getenv("UNRAVEL_DB_PASSWORD"); v != "" {
		return v, nil
	}
	if c.Database.PasswordEnc == "" {
		return "", fmt.Errorf("config: password not set — run `unravel db setup`")
	}
	key, err := crypto.LoadOrGenerateDataKey()
	if err != nil {
		return "", fmt.Errorf("decrypt password: %w", err)
	}
	pw, err := crypto.DecryptString(c.Database.PasswordEnc, key)
	if err != nil {
		return "", fmt.Errorf("decrypt password: %w", err)
	}
	return pw, nil
}

// DSN returns a postgres URL DSN ready for pgxpool.ParseConfig. The ctx
// is currently unused but reserved for future async-decrypt paths.
func (c Config) DSN(_ context.Context) (string, error) {
	pw, err := c.Password()
	if err != nil {
		return "", err
	}
	u := url.URL{
		Scheme: "postgres",
		Host:   fmt.Sprintf("%s:%d", c.Database.Host, c.Database.Port),
		User:   url.UserPassword(c.Database.User, pw),
		Path:   "/" + c.Database.DBName,
	}
	q := u.Query()
	if c.Database.SSLMode != "" {
		q.Set("sslmode", c.Database.SSLMode)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Redacted returns a DSN-shaped string with the password replaced by
// "REDACTED" — safe to log.
func (c Config) Redacted() string {
	host := c.Database.Host
	if !strings.ContainsRune(host, ':') {
		host = fmt.Sprintf("%s:%d", host, c.Database.Port)
	}
	return fmt.Sprintf("postgres://%s:REDACTED@%s/%s?sslmode=%s",
		c.Database.User, host, c.Database.DBName, c.Database.SSLMode)
}

// KBStorePath returns the root directory for versioned application captures.
func (c Config) KBStorePath() string {
	if v := os.Getenv("UNRAVEL_KB_STORE"); v != "" {
		return v
	}
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		return filepath.Join(local, "Unravel", "kb-store", "apps")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, "unravel", "kb-store", "apps")
	}
	return filepath.Join(os.TempDir(), "unravel", "kb-store", "apps")
}
