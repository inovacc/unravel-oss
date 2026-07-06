/*
Copyright (c) 2026 Security Research
*/
package clients

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/inovacc/unravel-oss/internal/ipc"
	"github.com/inovacc/unravel-oss/internal/supervisor"
)

// ErrKBNotImplemented is returned when a verb in the kb.* surface is
// registered but not yet backed by a store implementation (CodeUpstream).
var ErrKBNotImplemented = errors.New("kb: not_implemented")

// ErrKBUnavailable is returned when the supervisor was started without a
// DSN (CodeUnavailable).
var ErrKBUnavailable = errors.New("kb: supervisor has no DB pool")

// translateKBErr layers kb-specific sentinel mapping on top of translateErr.
// CodeUpstream ("not_implemented") and CodeUnavailable ("no DB pool")
// are distinct from the generic not-found / bad-request cases.
func translateKBErr(err error, notFound error) error {
	if err == nil {
		return nil
	}
	var eb *ipc.ErrorBody
	if errors.As(err, &eb) {
		switch eb.Code {
		case ipc.CodeUpstream:
			return errors.Join(ErrKBNotImplemented, eb)
		case ipc.CodeUnavailable:
			return errors.Join(ErrKBUnavailable, eb)
		}
	}
	return translateErr(err, notFound)
}

// KBClient wraps the kb.* verbs.
type KBClient struct {
	bus ipc.Bus
}

// NewKBClient returns a wrapper over bus for the kb.* verb group.
func NewKBClient(bus ipc.Bus) *KBClient {
	return &KBClient{bus: bus}
}

// Search calls kb.search with the full param struct (v2.17 B1.1).
func (c *KBClient) Search(ctx context.Context, p supervisor.KBSearchParams) (*supervisor.KBSearchResult, error) {
	raw, err := c.bus.Call(ctx, "kb.search", p)
	if err != nil {
		return nil, translateKBErr(err, nil)
	}
	var out supervisor.KBSearchResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Facts calls kb.facts.
func (c *KBClient) Facts(ctx context.Context, p supervisor.KBFactsParams) (*supervisor.KBFactsResult, error) {
	raw, err := c.bus.Call(ctx, "kb.facts", p)
	if err != nil {
		return nil, translateKBErr(err, nil)
	}
	var out supervisor.KBFactsResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Gaps calls kb.gaps.
func (c *KBClient) Gaps(ctx context.Context, p supervisor.KBFactsParams) (*supervisor.KBGapsResult, error) {
	raw, err := c.bus.Call(ctx, "kb.gaps", p)
	if err != nil {
		return nil, translateKBErr(err, nil)
	}
	var out supervisor.KBGapsResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Stats calls kb.stats.
func (c *KBClient) Stats(ctx context.Context, app string) (*supervisor.KBStatsResult, error) {
	raw, err := c.bus.Call(ctx, "kb.stats", supervisor.KBStatsParams{App: app})
	if err != nil {
		return nil, translateKBErr(err, nil)
	}
	var out supervisor.KBStatsResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Apps calls kb.apps. The optional params filter rows by platform /
// framework / risk / tag / since / limit; pass a zero-value
// supervisor.KBAppsParams to return the most recent apps (capped by the
// default limit of 100).
func (c *KBClient) Apps(ctx context.Context, p supervisor.KBAppsParams) (*supervisor.KBAppsResult, error) {
	raw, err := c.bus.Call(ctx, "kb.apps", p)
	if err != nil {
		return nil, translateKBErr(err, nil)
	}
	var out supervisor.KBAppsResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Diff calls kb.diff (v2.17.1).
func (c *KBClient) Diff(ctx context.Context, p supervisor.KBDiffParams) (*supervisor.KBDiffResult, error) {
	raw, err := c.bus.Call(ctx, "kb.diff", p)
	if err != nil {
		return nil, translateKBErr(err, nil)
	}
	var out supervisor.KBDiffResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// VendoredCandidates calls kb.vendored_candidates.
func (c *KBClient) VendoredCandidates(ctx context.Context, p supervisor.KBVendoredCandidatesParams) (*supervisor.KBVendoredCandidatesResult, error) {
	raw, err := c.bus.Call(ctx, "kb.vendored_candidates", p)
	if err != nil {
		return nil, translateKBErr(err, nil)
	}
	var out supervisor.KBVendoredCandidatesResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Dump calls kb.dump.
func (c *KBClient) Dump(ctx context.Context, id int) (*supervisor.KBDumpResult, error) {
	raw, err := c.bus.Call(ctx, "kb.dump", supervisor.KBDumpParams{ID: id})
	if err != nil {
		return nil, translateKBErr(err, nil)
	}
	var out supervisor.KBDumpResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Doctor calls kb.doctor.
func (c *KBClient) Doctor(ctx context.Context, p supervisor.KBDoctorParams) (*supervisor.KBDoctorResult, error) {
	raw, err := c.bus.Call(ctx, "kb.doctor", p)
	if err != nil {
		return nil, translateKBErr(err, nil)
	}
	var out supervisor.KBDoctorResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DiffApps calls kb.diff_apps with the full request body so callers can
// thread category / limit filters through to the supervisor.
func (c *KBClient) DiffApps(ctx context.Context, p supervisor.KBDiffAppsParams) (*supervisor.KBDiffAppsResult, error) {
	raw, err := c.bus.Call(ctx, "kb.diff_apps", p)
	if err != nil {
		return nil, translateKBErr(err, nil)
	}
	var out supervisor.KBDiffAppsResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Export calls kb.export. p.KBID is required; p.LatestOnly mirrors the
// legacy `--latest-only` CLI flag (when true, only the newest epoch is
// included).
func (c *KBClient) Export(ctx context.Context, p supervisor.KBExportParams) (*supervisor.KBExportResult, error) {
	raw, err := c.bus.Call(ctx, "kb.export", p)
	if err != nil {
		return nil, translateKBErr(err, nil)
	}
	var out supervisor.KBExportResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Import calls kb.import.
func (c *KBClient) Import(ctx context.Context, p supervisor.KBImportParams) (*supervisor.KBImportResult, error) {
	raw, err := c.bus.Call(ctx, "kb.import", p)
	if err != nil {
		return nil, translateKBErr(err, nil)
	}
	var out supervisor.KBImportResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Timeline calls kb.timeline. p.KbID is required and must already be the
// canonical id (alias resolution is the caller's job — see
// pkg/knowledge/kb/identity.ResolveAlias). p.Reverse mirrors the legacy
// `--reverse` CLI flag.
func (c *KBClient) Timeline(ctx context.Context, p supervisor.KBTimelineParams) (*supervisor.KBTimelineResult, error) {
	raw, err := c.bus.Call(ctx, "kb.timeline", p)
	if err != nil {
		return nil, translateKBErr(err, nil)
	}
	var out supervisor.KBTimelineResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PullGap calls kb.pull_gap. p.App is required; p.Op selects the prompt
// template (defaults to fact_resolve when empty).
func (c *KBClient) PullGap(ctx context.Context, p supervisor.KBPullGapParams) (*supervisor.KBPullGapResult, error) {
	raw, err := c.bus.Call(ctx, "kb.pull_gap", p)
	if err != nil {
		return nil, translateKBErr(err, nil)
	}
	var out supervisor.KBPullGapResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PushAnswer calls kb.push_answer. p.GapID and p.Value are required; the
// remaining fields mirror the legacy kb_push_answer MCP tool inputs.
func (c *KBClient) PushAnswer(ctx context.Context, p supervisor.KBPushAnswerParams) (*supervisor.KBPushAnswerResult, error) {
	raw, err := c.bus.Call(ctx, "kb.push_answer", p)
	if err != nil {
		return nil, translateKBErr(err, nil)
	}
	var out supervisor.KBPushAnswerResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
