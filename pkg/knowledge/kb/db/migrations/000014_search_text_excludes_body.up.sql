-- Redefine modules.search_text to exclude body_excerpt.
--
-- Original generated definition (migration 1) folded body_excerpt into
-- search_text, which broke the two-tier search design: the ranked path
-- (trigram + ILIKE over search_text) always matched anything FTS
-- fallback (ILIKE over body_excerpt) could find, so the fallback path
-- was dead code. Repro: TestKbSearchMCPFTSFallback.
--
-- Fix: drop the column + index, re-add with body_excerpt removed, then
-- re-create the trigram index. Generated values rebuild from the row's
-- other columns — no data backfill needed.

DROP INDEX IF EXISTS modules_search_trgm_idx;

ALTER TABLE modules DROP COLUMN IF EXISTS search_text;

ALTER TABLE modules ADD COLUMN search_text TEXT GENERATED ALWAYS AS (
    coalesce(name,'') || ' ' ||
    coalesce(synthetic_name,'') || ' ' ||
    coalesce(symbols_json,'') || ' ' ||
    coalesce(summary,'') || ' ' ||
    coalesce(tags,'')
) STORED;

CREATE INDEX modules_search_trgm_idx ON modules USING GIN (search_text gin_trgm_ops);
