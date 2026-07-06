-- Reverse 000018. DROP the rollup table and the added columns.
DROP TABLE IF EXISTS kb_cost_rollup;

ALTER TABLE enrich_runs      DROP COLUMN IF EXISTS total_cost_micro_usd;
ALTER TABLE enrich_runs      DROP COLUMN IF EXISTS total_tokens;
ALTER TABLE enrich_attempts  DROP COLUMN IF EXISTS output_tokens;
ALTER TABLE enrich_attempts  DROP COLUMN IF EXISTS input_tokens;
