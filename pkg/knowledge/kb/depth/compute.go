/*
Copyright (c) 2026 Security Research

ComputeDepth aggregator: runs all 12 probes in declared order and returns
the equal-weight depth score plus covered/missing dimension names.

D-30-DEPTH-FORMULA: score = round((covered/12) * 100), no framework
conditioning. Half-up rounding via math.Round.

Plan 30-03 caller contract: *sql.Tx has no .Conn() method. The ingest
writer opens a *sql.Conn via db.Conn(ctx) BEFORE BeginTx, passes that conn
here, and uses tx for the rest of the ingest SQL. Both must be closed by
the caller.

License: BSD-3-Clause.
*/
package depth

import (
	"context"
	"database/sql"
	"log/slog"
	"math"
)

// ComputeDepth runs all 12 probes against ksDir + conn and returns the
// equal-weight depth score along with covered / missing dimension names.
//
// conn may be nil for probes that only need filesystem signal (everything
// except probeIdentity). probeIdentity returns false when conn is nil.
//
// Returns (0, [], <all 12 names>, nil) on empty ksDir.
func ComputeDepth(ctx context.Context, ksDir string, conn *sql.Conn) (score int, covered []string, missing []string, err error) {
	covered = make([]string, 0, len(AllProbes))
	missing = make([]string, 0, len(AllProbes))

	for _, p := range AllProbes {
		// Honour cancellation between probes; cheap to check.
		if cerr := ctx.Err(); cerr != nil {
			return 0, nil, nil, cerr
		}
		ok, evidence := p.Fn(ksDir, conn)
		slog.DebugContext(ctx, "depth probe",
			slog.String("dim", p.Name),
			slog.Bool("covered", ok),
			slog.String("evidence", evidence),
		)
		if ok {
			covered = append(covered, p.Name)
		} else {
			missing = append(missing, p.Name)
		}
	}

	score = int(math.Round(float64(len(covered)) / 12.0 * 100.0))
	return score, covered, missing, nil
}
