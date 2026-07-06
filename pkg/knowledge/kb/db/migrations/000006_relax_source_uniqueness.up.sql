-- ─────────────────────────────────────────────────────────────────────────
-- Migration 000006: relax knowledge_sources uniqueness
-- ─────────────────────────────────────────────────────────────────────────
-- To support `unravel kb capture --force` (Phase 32), we must allow
-- multiple epochs to share the same source_sha256 for a given app slug.
--
-- The application-level idempotency check in `ingest.Run` (Step 1) remains
-- the default gate; `--force` explicitly bypasses it.
-- ─────────────────────────────────────────────────────────────────────────

ALTER TABLE knowledge_sources
  DROP CONSTRAINT IF EXISTS knowledge_sources_app_source_sha256_key;
