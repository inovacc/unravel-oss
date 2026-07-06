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
	"github.com/inovacc/unravel-oss/pkg/knowledge/kbenrich"
)

// ErrEnrichUnavailable is returned when the supervisor was started without
// a DSN (CodeUnavailable) so the enrich.* verbs can't reach the DB.
var ErrEnrichUnavailable = errors.New("enrich: supervisor has no DB pool")

// translateEnrichErr layers enrich-specific sentinel mapping on top of
// translateErr. CodeUnavailable is mapped to ErrEnrichUnavailable (joined
// with the raw ipc.ErrorBody so callers can drill into the wire details).
func translateEnrichErr(err error, notFound error) error {
	if err == nil {
		return nil
	}
	var eb *ipc.ErrorBody
	if errors.As(err, &eb) && eb.Code == ipc.CodeUnavailable {
		return errors.Join(ErrEnrichUnavailable, eb)
	}
	return translateErr(err, notFound)
}

// EnrichClient wraps the enrich.* verbs. Construct one per ipc.Bus.
type EnrichClient struct {
	bus ipc.Bus
}

// NewEnrichClient returns a wrapper over bus for the enrich.* verb group.
func NewEnrichClient(bus ipc.Bus) *EnrichClient {
	return &EnrichClient{bus: bus}
}

// Pending calls enrich.pending.
func (c *EnrichClient) Pending(ctx context.Context, p supervisor.EnrichPendingParams) (*supervisor.EnrichPendingResult, error) {
	raw, err := c.bus.Call(ctx, "enrich.pending", p)
	if err != nil {
		return nil, translateEnrichErr(err, nil)
	}
	var out supervisor.EnrichPendingResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Write calls enrich.write.
func (c *EnrichClient) Write(ctx context.Context, p supervisor.EnrichWriteParams) (*supervisor.EnrichWriteResult, error) {
	raw, err := c.bus.Call(ctx, "enrich.write", p)
	if err != nil {
		return nil, translateEnrichErr(err, ErrEnrichModuleNotFound)
	}
	var out supervisor.EnrichWriteResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Status calls enrich.status.
func (c *EnrichClient) Status(ctx context.Context, p supervisor.EnrichStatusParams) (*supervisor.EnrichStatusResult, error) {
	raw, err := c.bus.Call(ctx, "enrich.status", p)
	if err != nil {
		return nil, translateEnrichErr(err, ErrEnrichRunNotFound)
	}
	var out supervisor.EnrichStatusResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Retry calls enrich.retry.
func (c *EnrichClient) Retry(ctx context.Context, p supervisor.EnrichRetryParams) (*supervisor.EnrichRetryResult, error) {
	raw, err := c.bus.Call(ctx, "enrich.retry", p)
	if err != nil {
		return nil, translateEnrichErr(err, ErrEnrichRunNotFound)
	}
	var out supervisor.EnrichRetryResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Record calls enrich.record.
func (c *EnrichClient) Record(ctx context.Context, p supervisor.EnrichRecordParams) (json.RawMessage, error) {
	raw, err := c.bus.Call(ctx, "enrich.record", p)
	if err != nil {
		return nil, translateEnrichErr(err, ErrEnrichRunNotFound)
	}
	return raw, nil
}

// HumanReview calls enrich.human_review.
func (c *EnrichClient) HumanReview(ctx context.Context, p supervisor.EnrichHumanReviewParams) (*supervisor.EnrichHumanReviewResult, error) {
	raw, err := c.bus.Call(ctx, "enrich.human_review", p)
	if err != nil {
		return nil, translateEnrichErr(err, ErrEnrichModuleNotFound)
	}
	var out supervisor.EnrichHumanReviewResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RecordCost calls enrich.record_cost.
func (c *EnrichClient) RecordCost(ctx context.Context, p supervisor.EnrichRecordCostParams) (*kbenrich.RecordCostPayload, error) {
	raw, err := c.bus.Call(ctx, "enrich.record_cost", p)
	if err != nil {
		return nil, translateEnrichErr(err, ErrEnrichRunNotFound)
	}
	var out kbenrich.RecordCostPayload
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CostReport calls enrich.cost_report.
func (c *EnrichClient) CostReport(ctx context.Context, p supervisor.EnrichCostReportParams) (*supervisor.EnrichCostReportResult, error) {
	raw, err := c.bus.Call(ctx, "enrich.cost_report", p)
	if err != nil {
		return nil, translateEnrichErr(err, ErrEnrichRunNotFound)
	}
	var out supervisor.EnrichCostReportResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
