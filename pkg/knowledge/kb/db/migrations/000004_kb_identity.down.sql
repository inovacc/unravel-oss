-- Down migration for 000004_kb_identity.

DROP INDEX IF EXISTS kb_aliases_canonical_idx;
DROP TABLE IF EXISTS kb_aliases;

DROP INDEX IF EXISTS knowledge_sources_depth_idx;
DROP INDEX IF EXISTS knowledge_sources_framework_idx;
DROP INDEX IF EXISTS knowledge_sources_risk_idx;
DROP INDEX IF EXISTS knowledge_sources_kb_id_idx;
DROP INDEX IF EXISTS knowledge_sources_kb_epoch_uq;
DROP INDEX IF EXISTS knowledge_sources_ks_id_uq;

ALTER TABLE knowledge_sources
  DROP CONSTRAINT IF EXISTS knowledge_sources_kb_id_fkey;

ALTER TABLE knowledge_sources
  DROP COLUMN IF EXISTS binary_sha256,
  DROP COLUMN IF EXISTS depth_missing,
  DROP COLUMN IF EXISTS depth_covered,
  DROP COLUMN IF EXISTS depth_score,
  DROP COLUMN IF EXISTS risk_level,
  DROP COLUMN IF EXISTS risk_score,
  DROP COLUMN IF EXISTS framework,
  DROP COLUMN IF EXISTS ks_id,
  DROP COLUMN IF EXISTS kb_id;

DROP TABLE IF EXISTS kb_apps;

-- Note: pgcrypto extension intentionally left installed; other code
-- may depend on it. Manually drop with `DROP EXTENSION pgcrypto;` if
-- a clean teardown is required.
