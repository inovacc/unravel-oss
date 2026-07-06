/*
Copyright (c) 2026 Security Research
*/

package kb_output

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/inovacc/unravel-oss/pkg/config"
)

// ParseSince converts a duration string (e.g. "30d", "2y", "1h") or RFC3339
// timestamp into a time.Time. Supports 'd', 'w', 'y' units.
func ParseSince(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}

	// Try RFC3339
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}

	// Custom duration handling for 'd', 'w', 'y'
	if len(s) >= 2 {
		last := s[len(s)-1]
		if last == 'd' || last == 'w' || last == 'y' {
			val, err := strconv.ParseInt(s[:len(s)-1], 10, 64)
			if err == nil {
				var d time.Duration
				switch last {
				case 'd':
					d = time.Duration(val) * 24 * time.Hour
				case 'w':
					d = time.Duration(val) * 7 * 24 * time.Hour
				case 'y':
					d = time.Duration(val) * 365 * 24 * time.Hour
				}
				return time.Now().Add(-d), nil
			}
		}
	}

	// Standard Go duration
	d, err := time.ParseDuration(s)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid duration: %w", err)
	}
	return time.Now().Add(-d), nil
}

// WriteTable renders aligned columns to the given writer.
func WriteTable(w io.Writer, headers []string, rows [][]string) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	// Write headers
	for i, h := range headers {
		if i > 0 {
			if _, err := fmt.Fprint(tw, "\t"); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprint(tw, h); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(tw); err != nil {
		return err
	}

	// Write rows
	for _, row := range rows {
		for i, cell := range row {
			if i > 0 {
				if _, err := fmt.Fprint(tw, "\t"); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprint(tw, cell); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(tw); err != nil {
			return err
		}
	}

	return tw.Flush()
}

// WriteJSON injects schema_version into the top-level object and encodes it.
// Rejects payloads that do not marshal to a JSON object.
func WriteJSON(w io.Writer, schemaVersion int, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return errors.New("payload must marshal to JSON object")
	}

	m["schema_version"] = schemaVersion

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(m)
}

// BindJSONFlag binds the --json flag to the command.
func BindJSONFlag(cmd *cobra.Command, target *bool) {
	cmd.Flags().BoolVar(target, "json", false, "emit result as JSON (schema_version embedded)")
}

// BindDSNFlag is retained as a no-op for source-compat with kb subcommand
// init() routines. The --dsn flag is no longer exposed; DSN comes from
// config.yaml exclusively. Tests inject via UNRAVEL_CONFIG pointing at a
// temp config.yaml.
func BindDSNFlag(_ *cobra.Command, _ *string) {}

// ResolveDSN returns the DSN from config.yaml (DPAPI-decrypted password via
// pkg/config). The legacy flag/env fallbacks have been removed — `unravel db
// setup` is the only authoring path. The argument is ignored and retained
// only for source-compat with existing call sites.
func ResolveDSN(_ string) (string, error) {
	cfg, err := config.Load()
	if err != nil {
		if errors.Is(err, config.ErrConfigNotFound) {
			return "", errors.New("dsn unavailable: run `unravel db setup` to write config.yaml")
		}
		return "", fmt.Errorf("load config: %w", err)
	}
	dsn, err := cfg.DSN(context.Background())
	if err != nil {
		return "", fmt.Errorf("resolve dsn from config: %w", err)
	}
	return dsn, nil
}

// Sparkline renders a sequence of values as a sparkline string.
func Sparkline(values []float64) string {
	if len(values) == 0 {
		return ""
	}

	runes := []rune("▁▂▃▄▅▆▇█")
	minV := values[0]
	maxV := values[0]
	for _, v := range values {
		if v < minV {
			minV = v
		}
		if v > maxV {
			maxV = v
		}
	}

	diff := maxV - minV
	result := make([]rune, len(values))
	for i, v := range values {
		if diff == 0 {
			result[i] = runes[0]
			continue
		}
		// Normalize (v-min)/(max-min) * 7
		idx := min(max(int(math.Floor(((v-minV)/diff)*7)), 0), 7)
		result[i] = runes[idx]
	}
	return string(result)
}
