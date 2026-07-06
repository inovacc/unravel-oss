/*
Copyright (c) 2026 Security Research
*/
package store

import (
	"context"
	"database/sql"
	"fmt"
)

// VendoredCandidatesOptions controls the body_sha256 occurrence-count
// query used by the unravel_kb_vendored_candidates MCP tool. App is an
// optional filter; MinCount is the floor on occurrences (default 3, hard
// floor 2); Top caps the result set (default 50, hard cap 200).
type VendoredCandidatesOptions struct {
	App      string
	MinCount int
	Top      int
}

// VendoredCandidate is one row of the response: a body_sha256 group,
// how many modules share it, and a sample module name for operator
// orientation.
type VendoredCandidate struct {
	SHA256      string `json:"sha256"`
	Occurrences int    `json:"occurrences"`
	SampleName  string `json:"sample_name"`
}

// VendoredCandidatesPayload is the wire shape returned by
// VendoredCandidates and aliased by the supervisor's
// kb.vendored_candidates verb (v2.17 thin-client B7-P2).
type VendoredCandidatesPayload struct {
	Candidates           []VendoredCandidate `json:"candidates"`
	TotalHashes          int                 `json:"total_hashes"`
	TotalVendoredModules int                 `json:"total_vendored_modules"`
	App                  string              `json:"app,omitempty"`
	MinCount             int                 `json:"min_count"`
	Top                  int                 `json:"top"`
}

// VendoredCandidates groups modules by body_sha256, retains only groups
// whose occurrence count >= opts.MinCount, and returns the top
// opts.Top groups ordered by occurrences DESC.
//
// Extracted from pkg/mcp/tools/kb_vendored_candidates.go in v2.17
// thin-client B7-P2 so the MCP tool can route through the supervisor
// kb.vendored_candidates verb without direct DB access.
func VendoredCandidates(ctx context.Context, db *sql.DB, opts VendoredCandidatesOptions) (*VendoredCandidatesPayload, error) {
	if db == nil {
		return nil, fmt.Errorf("VendoredCandidates: nil db")
	}
	minCount := opts.MinCount
	if minCount < 2 {
		minCount = 3
	}
	top := opts.Top
	if top < 1 {
		top = 50
	}
	if top > 200 {
		top = 200
	}

	q := `
SELECT
  m.body_sha256,
  COUNT(*) AS occurrences,
  (ARRAY_AGG(m.name ORDER BY m.id))[1] AS sample_name
FROM modules m
WHERE m.body_sha256 IS NOT NULL
  AND m.body_sha256 <> ''
  AND ($1::text IS NULL OR $1 = '' OR m.app = $1)
GROUP BY m.body_sha256
HAVING COUNT(*) >= $2
ORDER BY occurrences DESC
LIMIT $3`

	var appArg any
	if opts.App != "" {
		appArg = opts.App
	}
	rows, err := db.QueryContext(ctx, q, appArg, minCount, top)
	if err != nil {
		return nil, fmt.Errorf("query vendored candidates: %w", err)
	}
	defer func() { _ = rows.Close() }()

	candidates := []VendoredCandidate{}
	total := 0
	for rows.Next() {
		var c VendoredCandidate
		if err := rows.Scan(&c.SHA256, &c.Occurrences, &c.SampleName); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		candidates = append(candidates, c)
		total += c.Occurrences
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows: %w", err)
	}
	return &VendoredCandidatesPayload{
		Candidates:           candidates,
		TotalHashes:          len(candidates),
		TotalVendoredModules: total,
		App:                  opts.App,
		MinCount:             minCount,
		Top:                  top,
	}, nil
}
