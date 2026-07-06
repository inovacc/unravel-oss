/*
Copyright (c) 2026 Security Research
*/
package supervisor

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/inovacc/unravel-oss/internal/ipc"
	kbstore "github.com/inovacc/unravel-oss/pkg/knowledge/kb/store"
)

// ---------- request / response shapes ----------

// DaemonDoctorParams is the request body for daemon.doctor.
type DaemonDoctorParams struct {
	App     string `json:"app,omitempty"`
	Verbose bool   `json:"verbose,omitempty"`
}

// DaemonDoctorAppRow is one app's row in the modules_by_app slice.
type DaemonDoctorAppRow struct {
	App        string  `json:"app"`
	Total      int     `json:"total"`
	Summarised int     `json:"summarised"`
	Pending    int     `json:"pending"`
	Pct        float64 `json:"pct"`
	UniqHashes int     `json:"uniq_hashes"`
	AvgBytes   float64 `json:"avg_bytes,omitempty"`
}

// DaemonDoctorResult is the response body for daemon.doctor. Server-side
// aggregation of the four DB-touching operations the legacy plugin_doctor
// MCP handler did inline: open + ping + Stats + 3 enrich_runs queries.
//
// The MCP tool (pkg/mcp/tools/plugin_doctor.go) consumes this and slots
// it into its operator-facing envelope alongside the static binary/env/
// plugin_contract sections it computes client-side. (v2.17 thin-client B7-P3.)
type DaemonDoctorResult struct {
	KBReachable     bool                 `json:"kb_reachable"`
	PingError       string               `json:"ping_error,omitempty"`
	ModulesByApp    []DaemonDoctorAppRow `json:"modules_by_app,omitempty"`
	TotalModules    int                  `json:"total_modules"`
	TotalSummarised int                  `json:"total_summarised"`
	EnrichRunsTotal int                  `json:"enrich_runs_total"`
	StaleInProgress int                  `json:"stale_in_progress"`
	LastRunAt       string               `json:"last_run_at,omitempty"`
}

// ---------- registration ----------

// registerDaemonVerbs wires the daemon.* verb group. Called from New().
func (sv *Supervisor) registerDaemonVerbs() {
	sv.RegisterVerb("daemon.doctor", sv.daemonDoctor)
}

// ---------- handler ----------

func (sv *Supervisor) daemonDoctor(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	var p DaemonDoctorParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "daemon.doctor: " + err.Error()}
		}
	}

	if sv.db == nil {
		// Unreachable but well-formed: caller sees KBReachable=false +
		// PingError pointing to the missing pool. No error envelope so the
		// MCP tool can still assemble the rest of its doctor report.
		return DaemonDoctorResult{
			KBReachable: false,
			PingError:   "supervisor has no DB pool (Config.DSN empty)",
		}, nil
	}

	out := DaemonDoctorResult{KBReachable: true}

	// Ping (5s budget so a hung pool surfaces fast).
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := sv.db.PingContext(pingCtx); err != nil {
		out.KBReachable = false
		out.PingError = err.Error()
		return out, nil
	}

	// Per-app stats — reuse the kbstore helper.
	stats, err := kbstore.Stats(sv.db)
	if err == nil {
		out.ModulesByApp = make([]DaemonDoctorAppRow, 0, len(stats))
		for _, s := range stats {
			pending := s.Total - s.Summarized
			pct := 0.0
			if s.Total > 0 {
				pct = float64(s.Summarized) / float64(s.Total) * 100.0
			}
			row := DaemonDoctorAppRow{
				App:        s.App,
				Total:      s.Total,
				Summarised: s.Summarized,
				Pending:    pending,
				Pct:        pct,
				UniqHashes: s.UniqHashes,
			}
			if p.Verbose {
				row.AvgBytes = s.AvgBytes
			}
			out.ModulesByApp = append(out.ModulesByApp, row)
			out.TotalModules += s.Total
			out.TotalSummarised += s.Summarized
		}
	}

	// Enrich run counts + last run timestamp. All three queries are
	// best-effort — a missing column or zero rows is not fatal.
	_ = sv.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM enrich_runs`).Scan(&out.EnrichRunsTotal)
	_ = sv.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM enrich_runs
		 WHERE status='in_progress'
		   AND last_heartbeat_at < (now() - interval '10 minutes')`).Scan(&out.StaleInProgress)
	var lastRunAt sql.NullTime
	_ = sv.db.QueryRowContext(ctx,
		`SELECT MAX(started_at) FROM enrich_runs`).Scan(&lastRunAt)
	if lastRunAt.Valid {
		out.LastRunAt = lastRunAt.Time.Format(time.RFC3339)
	}

	_ = fmt.Sprintf // silence unused-import when daemon_dispatch.go grows new verbs
	return out, nil
}
