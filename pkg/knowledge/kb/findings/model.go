// Package findings provides the data model and store for KB AI adjudication
// findings — structured AI verdicts (affirm/contradict/augment/uncertain) over
// KB claims, plus a per-pass iteration trail.
package findings

import (
	"fmt"
	"slices"
)

// Stance is the verdict an AI auditor assigned to a KB claim.
type Stance string

const (
	StanceAffirm     Stance = "affirm"
	StanceContradict Stance = "contradict"
	StanceAugment    Stance = "augment"
	StanceUncertain  Stance = "uncertain"
)

// ValidStances is the canonical set of allowed Stance values.
var ValidStances = []Stance{StanceAffirm, StanceContradict, StanceAugment, StanceUncertain}

// Status is the lifecycle state of a Finding.
type Status string

const (
	StatusOpen       Status = "open"
	StatusAccepted   Status = "accepted"
	StatusRejected   Status = "rejected"
	StatusApplied    Status = "applied"
	StatusSuperseded Status = "superseded"
)

// ValidStatuses is the canonical set of allowed Status values.
var ValidStatuses = []Status{StatusOpen, StatusAccepted, StatusRejected, StatusApplied, StatusSuperseded}

// ValidStance returns an error if s is not a recognised Stance value.
func ValidStance(s string) error {
	if slices.Contains(ValidStances, Stance(s)) {
		return nil
	}
	return fmt.Errorf("invalid stance %q: must be one of affirm|contradict|augment|uncertain", s)
}

// ValidStatus returns an error if s is not a recognised Status value.
func ValidStatus(s string) error {
	if slices.Contains(ValidStatuses, Status(s)) {
		return nil
	}
	return fmt.Errorf("invalid status %q: must be one of open|accepted|rejected|applied|superseded", s)
}

// Finding is one row from kb_ai_findings. All epoch-ms timestamps are passed
// in by the caller — no time.Now() inside pure helpers.
type Finding struct {
	ID         int64   `json:"id"`
	App        string  `json:"app"`
	ModuleID   *int64  `json:"module_id,omitempty"`  // NULL for app-level findings
	Scope      string  `json:"scope"`                // module | app | cross-module
	TargetKind string  `json:"target_kind"`          // summary|role|side_effect|dep|input|output|security|vendored|app_fact|other
	TargetRef  string  `json:"target_ref,omitempty"` // specific claim reference
	Claim      string  `json:"claim"`                // KB assertion under scrutiny
	Stance     Stance  `json:"stance"`               // affirm|contradict|augment|uncertain
	Finding    string  `json:"finding"`              // verdict + reasoning
	Evidence   string  `json:"evidence,omitempty"`   // citations
	Confidence float64 `json:"confidence"`           // 0..1
	Severity   string  `json:"severity,omitempty"`   // info|low|medium|high
	Iterations int     `json:"iterations"`           // passes to converge
	Converged  bool    `json:"converged"`            // stable vs hit max-iter cap
	ModelUsed  string  `json:"model_used,omitempty"`
	RunID      string  `json:"run_id,omitempty"` // UUID grouping one audit run
	Status     Status  `json:"status"`
	CreatedAt  int64   `json:"created_at"`            // epoch ms
	ResolvedAt *int64  `json:"resolved_at,omitempty"` // epoch ms
	ResolvedBy string  `json:"resolved_by,omitempty"`
}

// Iteration is one row from kb_ai_finding_iterations.
type Iteration struct {
	FindingID     int64   `json:"finding_id"`
	Iter          int     `json:"iter"`                     // 1..N
	InterimStance string  `json:"interim_stance,omitempty"` // verdict at this pass
	InterimConf   float64 `json:"interim_conf"`
	Challenger    string  `json:"challenger,omitempty"` // which lens/adversary ran this pass
	Changed       bool    `json:"changed"`              // did verdict flip vs prior pass
	Note          string  `json:"note,omitempty"`       // what the challenge found
	CreatedAt     int64   `json:"created_at"`           // epoch ms
}

// Filter controls which rows List returns.
type Filter struct {
	App      string // filter by KB app slug (empty = all)
	ModuleID int64  // filter by module id (0 = all)
	Stance   string // filter by stance (empty = all)
	Status   string // filter by status (empty = all)
	Limit    int    // 0 → default cap (500)
}

// SummaryResult groups counts by stance and status for an app.
type SummaryResult struct {
	App           string         `json:"app"`
	ByStance      map[string]int `json:"by_stance"`
	ByStatus      map[string]int `json:"by_status"`
	TotalFindings int            `json:"total_findings"`
}
