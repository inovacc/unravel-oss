DROP VIEW IF EXISTS knowledge_source_evolution;
DROP INDEX IF EXISTS module_sightings_source_idx;
ALTER TABLE module_sightings DROP COLUMN IF EXISTS source_id;
DROP INDEX IF EXISTS modules_last_source_idx;
DROP INDEX IF EXISTS modules_first_source_idx;
ALTER TABLE modules
  DROP COLUMN IF EXISTS first_source_id,
  DROP COLUMN IF EXISTS last_source_id;
DROP INDEX IF EXISTS knowledge_sources_captured_idx;
DROP INDEX IF EXISTS knowledge_sources_app_idx;
DROP TABLE IF EXISTS knowledge_sources;
