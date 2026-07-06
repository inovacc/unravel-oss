package findings

import (
	"database/sql"
	"fmt"
)

const defaultLimit = 500

func clampLimit(n int) int {
	if n <= 0 {
		return defaultLimit
	}
	if n > defaultLimit {
		return defaultLimit
	}
	return n
}

// Record inserts a new finding row and returns its generated id.
// CreatedAt must be set to epoch-ms by the caller.
func Record(db *sql.DB, f Finding) (int64, error) {
	var id int64
	err := db.QueryRow(`
INSERT INTO kb_ai_findings
    (app, module_id, scope, target_kind, target_ref, claim,
     stance, finding, evidence, confidence, severity,
     iterations, converged, model_used, run_id,
     status, created_at, resolved_at, resolved_by)
VALUES
    ($1, $2, $3, $4, $5, $6,
     $7, $8, $9, $10, $11,
     $12, $13, $14, $15::uuid,
     $16, $17, $18, $19)
RETURNING id`,
		f.App,
		nullInt64(f.ModuleID),
		scopeOrDefault(f.Scope),
		f.TargetKind,
		nullString(f.TargetRef),
		f.Claim,
		string(f.Stance),
		f.Finding,
		nullString(f.Evidence),
		nullFloat64(f.Confidence),
		nullString(f.Severity),
		iterOrDefault(f.Iterations),
		f.Converged,
		nullString(f.ModelUsed),
		nullString(f.RunID),
		statusOrDefault(f.Status),
		f.CreatedAt,
		nullInt64Ptr(f.ResolvedAt),
		nullString(f.ResolvedBy),
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("findings.Record: %w", err)
	}
	return id, nil
}

// RecordIteration upserts one per-pass trail row. Idempotent: a second call
// with the same (finding_id, iter) is a no-op (ON CONFLICT DO NOTHING).
// CreatedAt must be set to epoch-ms by the caller.
func RecordIteration(db *sql.DB, it Iteration) error {
	_, err := db.Exec(`
INSERT INTO kb_ai_finding_iterations
    (finding_id, iter, interim_stance, interim_conf, challenger, changed, note, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (finding_id, iter) DO NOTHING`,
		it.FindingID,
		it.Iter,
		nullString(it.InterimStance),
		nullFloat64(it.InterimConf),
		nullString(it.Challenger),
		it.Changed,
		nullString(it.Note),
		it.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("findings.RecordIteration: %w", err)
	}
	return nil
}

// List returns findings matching the given Filter. Rows are ordered by
// created_at DESC then id DESC. An empty Filter returns all findings up to
// the default limit.
func List(db *sql.DB, filter Filter) ([]Finding, error) {
	limit := clampLimit(filter.Limit)
	args := []any{}
	q := `
SELECT id, app, module_id, scope, target_kind, target_ref, claim,
       stance, finding, evidence, confidence, severity,
       iterations, converged, model_used, run_id,
       status, created_at, resolved_at, resolved_by
  FROM kb_ai_findings
 WHERE 1=1`

	if filter.App != "" {
		args = append(args, filter.App)
		q += fmt.Sprintf(" AND app = $%d", len(args))
	}
	if filter.ModuleID != 0 {
		args = append(args, filter.ModuleID)
		q += fmt.Sprintf(" AND module_id = $%d", len(args))
	}
	if filter.Stance != "" {
		args = append(args, filter.Stance)
		q += fmt.Sprintf(" AND stance = $%d", len(args))
	}
	if filter.Status != "" {
		args = append(args, filter.Status)
		q += fmt.Sprintf(" AND status = $%d", len(args))
	}
	args = append(args, limit)
	q += fmt.Sprintf(" ORDER BY created_at DESC, id DESC LIMIT $%d", len(args))

	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("findings.List: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, fmt.Errorf("findings.List scan: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// Resolve sets the status and resolved_by on a finding. resolvedAt must be
// epoch-ms (caller-supplied). Passing an unrecognised status returns an error
// before touching the database.
func Resolve(db *sql.DB, id int64, status, by string, resolvedAt int64) error {
	if err := ValidStatus(status); err != nil {
		return fmt.Errorf("findings.Resolve: %w", err)
	}
	res, err := db.Exec(`
UPDATE kb_ai_findings
   SET status = $1, resolved_by = $2, resolved_at = $3
 WHERE id = $4`,
		status, nullString(by), resolvedAt, id)
	if err != nil {
		return fmt.Errorf("findings.Resolve: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("findings.Resolve: no finding with id=%d", id)
	}
	return nil
}

// Summary returns aggregated counts (by stance, by status) for all findings
// belonging to app. An empty app returns counts across all apps (still grouped
// as a single SummaryResult with App="").
func Summary(db *sql.DB, app string) (SummaryResult, error) {
	args := []any{}
	whereClause := ""
	if app != "" {
		args = append(args, app)
		whereClause = " WHERE app = $1"
	}

	sum := SummaryResult{
		App:      app,
		ByStance: map[string]int{},
		ByStatus: map[string]int{},
	}

	// counts by stance
	rows, err := db.Query(`SELECT stance, COUNT(*) FROM kb_ai_findings`+whereClause+` GROUP BY stance`, args...)
	if err != nil {
		return sum, fmt.Errorf("findings.Summary stance: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var stance string
		var cnt int
		if err := rows.Scan(&stance, &cnt); err != nil {
			return sum, fmt.Errorf("findings.Summary stance scan: %w", err)
		}
		sum.ByStance[stance] = cnt
		sum.TotalFindings += cnt
	}
	if err := rows.Err(); err != nil {
		return sum, fmt.Errorf("findings.Summary stance rows: %w", err)
	}

	// counts by status — reuse args (same WHERE clause)
	srows, err := db.Query(`SELECT status, COUNT(*) FROM kb_ai_findings`+whereClause+` GROUP BY status`, args...)
	if err != nil {
		return sum, fmt.Errorf("findings.Summary status: %w", err)
	}
	defer func() { _ = srows.Close() }()
	for srows.Next() {
		var status string
		var cnt int
		if err := srows.Scan(&status, &cnt); err != nil {
			return sum, fmt.Errorf("findings.Summary status scan: %w", err)
		}
		sum.ByStatus[status] = cnt
	}
	return sum, srows.Err()
}

// scanFinding reads one Finding from a *sql.Rows.
func scanFinding(rows *sql.Rows) (Finding, error) {
	var f Finding
	var moduleID sql.NullInt64
	var targetRef, evidence, severity, modelUsed, runID, resolvedBy sql.NullString
	var confidence sql.NullFloat64
	var resolvedAt sql.NullInt64

	err := rows.Scan(
		&f.ID, &f.App, &moduleID, &f.Scope, &f.TargetKind, &targetRef, &f.Claim,
		&f.Stance, &f.Finding, &evidence, &confidence, &severity,
		&f.Iterations, &f.Converged, &modelUsed, &runID,
		&f.Status, &f.CreatedAt, &resolvedAt, &resolvedBy,
	)
	if err != nil {
		return f, err
	}
	if moduleID.Valid {
		v := moduleID.Int64
		f.ModuleID = &v
	}
	f.TargetRef = targetRef.String
	f.Evidence = evidence.String
	f.Confidence = confidence.Float64
	f.Severity = severity.String
	f.ModelUsed = modelUsed.String
	f.RunID = runID.String
	f.ResolvedBy = resolvedBy.String
	if resolvedAt.Valid {
		v := resolvedAt.Int64
		f.ResolvedAt = &v
	}
	return f, nil
}

// --- nullable helpers (avoids importing a separate nulls package) ---

func nullInt64(p *int64) sql.NullInt64 {
	if p == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *p, Valid: true}
}

func nullInt64Ptr(p *int64) sql.NullInt64 {
	return nullInt64(p)
}

func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func nullFloat64(f float64) sql.NullFloat64 {
	if f == 0 {
		return sql.NullFloat64{}
	}
	return sql.NullFloat64{Float64: f, Valid: true}
}

func scopeOrDefault(s string) string {
	if s == "" {
		return "module"
	}
	return s
}

func iterOrDefault(n int) int {
	if n <= 0 {
		return 1
	}
	return n
}

func statusOrDefault(s Status) string {
	if s == "" {
		return string(StatusOpen)
	}
	return string(s)
}
