DROP INDEX IF EXISTS idx_drift_alerts_app_created;
DROP TABLE IF EXISTS drift_alerts;
DROP INDEX IF EXISTS uq_enrich_runs_baseline_per_app;
ALTER TABLE enrich_runs DROP COLUMN IF EXISTS baseline_for;
ALTER TABLE enrich_attempts DROP COLUMN IF EXISTS cost_micro_usd;
