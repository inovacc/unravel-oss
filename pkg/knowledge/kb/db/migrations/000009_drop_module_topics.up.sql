-- 000009_drop_module_topics.up.sql
-- Removes the module_topics table per ADR-0006 (v2.7 P44 deprecation).
-- Calendar gate (2026-06-05) skipped per CLEAN-02 commit: app pre-release,
-- no external consumers. Backfill into module_components already ran in 000007.

DROP TABLE IF EXISTS module_topics CASCADE;
