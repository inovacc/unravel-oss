-- Phase G — drift detection foundations.
-- Additive; existing rows unaffected.

-- 1. Cost per attempt. Required for the mean_cost_micro_usd drift metric.
--    Default 0 so historical rows continue to read sensibly.
ALTER TABLE enrich_attempts
    ADD COLUMN IF NOT EXISTS cost_micro_usd bigint NOT NULL DEFAULT 0;

-- 2. Baseline tag on enrich_runs. NULL on most rows; non-null on the one
--    row per app designated as baseline. Forward-compat: column type is
--    text in case a future schema rev uses it as a label.
ALTER TABLE enrich_runs
    ADD COLUMN IF NOT EXISTS baseline_for text NULL;

-- One baseline per app.
CREATE UNIQUE INDEX IF NOT EXISTS uq_enrich_runs_baseline_per_app
    ON enrich_runs (app)
    WHERE baseline_for IS NOT NULL;

-- 3. Persisted alert history. One row per drifted metric per run.
CREATE TABLE IF NOT EXISTS drift_alerts (
    id                  bigserial PRIMARY KEY,
    app                 text NOT NULL,
    -- enrich_runs PK is run_id (uuid), not an int id (see migration 000013).
    run_id              uuid NOT NULL REFERENCES enrich_runs(run_id) ON DELETE CASCADE,
    baseline_run_id     uuid NOT NULL REFERENCES enrich_runs(run_id),
    metric              text NOT NULL CHECK (metric IN
                          ('success_rate', 'escalation_rate',
                           'human_review_rate', 'mean_cost_micro_usd')),
    baseline_value      double precision NOT NULL,
    recent_value        double precision NOT NULL,
    relative_delta      double precision NOT NULL,
    threshold_relative  double precision NOT NULL DEFAULT 0.20,
    created_at          timestamptz NOT NULL DEFAULT now(),
    notes               text NULL
);

CREATE INDEX IF NOT EXISTS idx_drift_alerts_app_created
    ON drift_alerts (app, created_at DESC);
