-- Re-apply the uniqueness constraint on knowledge_sources (app, source_sha256).
-- This may fail if duplicate rows were inserted while the constraint was dropped.
ALTER TABLE knowledge_sources
  ADD CONSTRAINT knowledge_sources_app_source_sha256_key UNIQUE (app, source_sha256);
