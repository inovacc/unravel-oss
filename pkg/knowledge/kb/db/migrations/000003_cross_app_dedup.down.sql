-- Reverse migration 000003. Drops the cross-app dedup tables and views.
-- Legacy modules / module_sightings / module_bodies data is preserved —
-- those tables were not modified by 000003 (no ADD COLUMN, no rename).

DROP VIEW IF EXISTS knowledge_capture_summary;
DROP VIEW IF EXISTS module_body_reuse;

DROP TABLE IF EXISTS module_app_refs;
DROP TABLE IF EXISTS file_app_refs;
DROP TABLE IF EXISTS files;
