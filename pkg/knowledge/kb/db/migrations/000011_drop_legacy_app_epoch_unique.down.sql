-- Re-apply the legacy uniqueness constraint on knowledge_sources (app, epoch).
-- This may fail if identity-fork rows (same app slug, distinct kb_id,
-- overlapping epoch) were inserted while the constraint was dropped — which is
-- precisely the scenario 000011 exists to permit.
ALTER TABLE knowledge_sources
  ADD CONSTRAINT knowledge_sources_app_epoch_key UNIQUE (app, epoch);
