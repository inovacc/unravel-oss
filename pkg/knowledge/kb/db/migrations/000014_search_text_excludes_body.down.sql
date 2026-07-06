-- Restore the migration-1 search_text definition (body_excerpt included).

DROP INDEX IF EXISTS modules_search_trgm_idx;

ALTER TABLE modules DROP COLUMN IF EXISTS search_text;

ALTER TABLE modules ADD COLUMN search_text TEXT GENERATED ALWAYS AS (
    coalesce(name,'') || ' ' ||
    coalesce(synthetic_name,'') || ' ' ||
    coalesce(body_excerpt,'') || ' ' ||
    coalesce(symbols_json,'') || ' ' ||
    coalesce(summary,'') || ' ' ||
    coalesce(tags,'')
) STORED;

CREATE INDEX modules_search_trgm_idx ON modules USING GIN (search_text gin_trgm_ops);
