-- ─────────────────────────────────────────────────────────────────────────
-- Migration 000004: kb_apps (stable identity) + knowledge_sources metadata
-- ─────────────────────────────────────────────────────────────────────────
-- Today's `app` column on knowledge_sources is free-form TEXT — same app
-- repackaged with a different display name produces a fresh per-app
-- timeline. This migration adds:
--
--   kb_apps                  — stable app identity keyed by sha256 hash
--                              of (package_id|platform) where available,
--                              else (canonical_name|platform). publisher_cn
--                              is stored for filtering only, NEVER hashed
--                              (mitigates PITFALLS-CRIT-1: cert rotation
--                              forking identity).
--   kb_aliases               — merge mapping; survives kb_apps row delete
--                              so `unravel kb merge` (Phase 29 Day-1) is
--                              non-destructive for read paths.
--   knowledge_sources.kb_id  — FK back to kb_apps (NOT VALID; validation
--                              deferred to Phase 34 backfill).
--   knowledge_sources.ks_id  — human-readable per-snapshot ID.
--   knowledge_sources.{framework,risk_score,risk_level,depth_score,
--                       depth_covered,depth_missing,binary_sha256}
--                            — snapshot-level scoring + provenance.
--
-- This migration is DDL-only (D-29-MIGRATION-DDL-ONLY, PITFALLS-CRIT-2):
-- no INSERT/UPDATE statements. Backfill of legacy `app`-only rows is
-- performed by `unravel kb backfill` in Phase 34, in a controlled tx
-- with rate limiting and audit logging. Inline backfill here would take
-- a long ACCESS EXCLUSIVE lock on knowledge_sources during deploy and
-- conflicts with managed-Postgres lock-budget constraints.
--
-- pgcrypto stays installed for Phase 34's backfill (which uses digest()
-- to hash legacy rows), but the live ingest writer (Phase 30) computes
-- sha256 Go-side via crypto/sha256 — keeps managed-Postgres deployments
-- without pgcrypto privileges working (D-29-PGCRYPTO-REMOVAL-FROM-LIVE-PATH,
-- PITFALLS-MOD-7).
-- ─────────────────────────────────────────────────────────────────────────

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ─────────────────────────────── kb_apps ─────────────────────────────────
CREATE TABLE kb_apps (
  kb_id           TEXT PRIMARY KEY,
  canonical_name  TEXT NOT NULL,
  display_name    TEXT NOT NULL,
  platform        TEXT NOT NULL,
  publisher       TEXT,
  publisher_cn    TEXT,
  framework       TEXT,
  package_id      TEXT,
  first_seen_at   BIGINT NOT NULL,
  last_seen_at    BIGINT NOT NULL,
  tags            TEXT[],
  metadata        JSONB
);
CREATE INDEX kb_apps_canon_trgm   ON kb_apps USING GIN (canonical_name gin_trgm_ops);
CREATE INDEX kb_apps_display_trgm ON kb_apps USING GIN (display_name   gin_trgm_ops);
CREATE INDEX kb_apps_meta_idx     ON kb_apps USING GIN (metadata jsonb_path_ops);
CREATE INDEX kb_apps_tags_idx     ON kb_apps USING GIN (tags);
CREATE INDEX kb_apps_framework_idx ON kb_apps (framework) WHERE framework IS NOT NULL;
CREATE INDEX kb_apps_platform_idx  ON kb_apps (platform);
CREATE INDEX kb_apps_package_idx   ON kb_apps (package_id) WHERE package_id IS NOT NULL;

-- ─────────────────────────────── kb_aliases ──────────────────────────────
-- Merge mapping for `unravel kb merge` (D-29-MERGE-NEW-TABLE, IDEN-03).
-- An alias row maps a loser kb_id → canonical winner kb_id. Kept in its
-- own narrow table so kb_apps queries never need a `WHERE merged_into IS
-- NULL` predicate. Read path uses `coalesce(kb_aliases.canonical_kb_id,
-- $input)` so analysts can pass either form to `kb show`.
CREATE TABLE kb_aliases (
  alias_kb_id      TEXT PRIMARY KEY,
  canonical_kb_id  TEXT NOT NULL REFERENCES kb_apps(kb_id) ON DELETE CASCADE,
  merged_at        BIGINT NOT NULL,
  merged_by        TEXT,
  reason           TEXT
);
CREATE INDEX kb_aliases_canonical_idx ON kb_aliases (canonical_kb_id);

-- ─────────────────────── knowledge_sources extension ─────────────────────
-- FK on kb_id is added separately as NOT VALID to avoid a long
-- ACCESS EXCLUSIVE lock during deploy when knowledge_sources already
-- has rows with NULL kb_id (PITFALLS-CRIT-2). Phase 34's backfill
-- runs `ALTER TABLE ... VALIDATE CONSTRAINT` after backfilling kb_id.
ALTER TABLE knowledge_sources
  ADD COLUMN kb_id          TEXT,
  ADD COLUMN ks_id          TEXT,
  ADD COLUMN framework      TEXT,
  ADD COLUMN risk_score     INTEGER,
  ADD COLUMN risk_level     TEXT,
  ADD COLUMN depth_score    INTEGER,
  ADD COLUMN depth_covered  TEXT[],
  ADD COLUMN depth_missing  TEXT[],
  ADD COLUMN binary_sha256  TEXT;

ALTER TABLE knowledge_sources
  ADD CONSTRAINT knowledge_sources_kb_id_fkey
  FOREIGN KEY (kb_id) REFERENCES kb_apps(kb_id) ON DELETE CASCADE NOT VALID;

CREATE UNIQUE INDEX knowledge_sources_ks_id_uq
  ON knowledge_sources (ks_id) WHERE ks_id IS NOT NULL;
-- Partial UNIQUE (kb_id, epoch) per D-29-EPOCH-CONSTRAINT / IDEN-02 / INGE-04.
-- Partial on `kb_id IS NOT NULL` so legacy rows (pre-Phase-34-backfill)
-- with NULL kb_id don't collide; the live ingest writer (Phase 30) always
-- sets kb_id on new rows under pg_advisory_xact_lock(hashtext('kb_epoch:'
-- || kb_id)) to serialize epoch allocation per-app (PITFALLS-CRIT-4).
CREATE UNIQUE INDEX knowledge_sources_kb_epoch_uq
  ON knowledge_sources (kb_id, epoch) WHERE kb_id IS NOT NULL;
CREATE INDEX knowledge_sources_kb_id_idx
  ON knowledge_sources (kb_id, captured_at DESC) WHERE kb_id IS NOT NULL;
CREATE INDEX knowledge_sources_risk_idx
  ON knowledge_sources (risk_level) WHERE risk_level IS NOT NULL;
CREATE INDEX knowledge_sources_framework_idx
  ON knowledge_sources (framework) WHERE framework IS NOT NULL;
CREATE INDEX knowledge_sources_depth_idx
  ON knowledge_sources (depth_score) WHERE depth_score IS NOT NULL;
