-- ─────────────────────────────────────────────────────────────────────────
-- Migration 000011: drop legacy knowledge_sources (app, epoch) uniqueness
-- ─────────────────────────────────────────────────────────────────────────
-- Migration 000002 created UNIQUE(app, epoch) back when an epoch sequence was
-- keyed by the app display-name slug. The identity model (000004,
-- D-29-EPOCH-CONSTRAINT / IDEN-02) re-keyed epoch uniqueness to (kb_id, epoch)
-- via the partial index knowledge_sources_kb_epoch_uq, with per-kb_id epoch
-- allocation serialized under pg_advisory_xact_lock(hashtext('kb_epoch:'||
-- kb_id)) in identity.AllocateEpoch.
--
-- Migration 000006 already relaxed the sibling UNIQUE(app, source_sha256) for
-- exactly this reason but left UNIQUE(app, epoch) in place.
--
-- On an identity fork (app updated -> new content fingerprint -> new kb_id,
-- same display-name slug) AllocateEpoch correctly returns epoch=1 for the new
-- kb_id, but inserting (app='Foo', epoch=1) collides with the *old* kb_id's
-- historical (app='Foo', epoch=1) row under the stale constraint, raising
-- SQLSTATE 23505 (knowledge_sources_app_epoch_key) and making `kb capture` of
-- any updated app impossible. Epoch uniqueness remains correctly and
-- sufficiently enforced per-kb_id by knowledge_sources_kb_epoch_uq.
-- ─────────────────────────────────────────────────────────────────────────

ALTER TABLE knowledge_sources
  DROP CONSTRAINT IF EXISTS knowledge_sources_app_epoch_key;
