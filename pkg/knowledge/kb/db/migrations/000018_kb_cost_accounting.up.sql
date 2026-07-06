-- KB-COST-ACCOUNTING Phase 1 — token + notional-USD accounting.
-- Additive; existing rows unaffected. Picked up by the //go:embed in db.go.

-- 1. Per-attempt token split. NULL on historical rows (cost unknown);
--    cost_micro_usd already added by migration 000017.
ALTER TABLE enrich_attempts
    ADD COLUMN IF NOT EXISTS input_tokens  bigint NULL;
ALTER TABLE enrich_attempts
    ADD COLUMN IF NOT EXISTS output_tokens bigint NULL;

-- 2. Running per-run totals. Bumped incrementally by enrich.record_cost.
ALTER TABLE enrich_runs
    ADD COLUMN IF NOT EXISTS total_tokens         bigint NOT NULL DEFAULT 0;
ALTER TABLE enrich_runs
    ADD COLUMN IF NOT EXISTS total_cost_micro_usd bigint NOT NULL DEFAULT 0;

-- 3. Incremental rollup. One row per ('app',<app>) plus one ('global','all').
--    UPSERT += delta on every record_cost call — the incremental total the
--    user asked for.
CREATE TABLE IF NOT EXISTS kb_cost_rollup (
    scope                text        NOT NULL,
    key                  text        NOT NULL,
    total_tokens         bigint      NOT NULL DEFAULT 0,
    total_cost_micro_usd bigint      NOT NULL DEFAULT 0,
    attempts             bigint      NOT NULL DEFAULT 0,
    updated_at           timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scope, key)
);
