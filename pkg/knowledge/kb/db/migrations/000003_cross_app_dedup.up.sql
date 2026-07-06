-- ─────────────────────────────────────────────────────────────────────────
-- Migration 000003: cross-app body sharing + physical-file dedup
-- ─────────────────────────────────────────────────────────────────────────
-- Today's schema dedups body content globally (module_bodies.body_sha256)
-- but the modules table still has UNIQUE (app, body_sha256), so the same
-- body shipped by 5 apps creates 5 modules rows and 5 sets of metadata.
-- This migration adds three additive tables that surface cross-app sharing
-- without touching the existing modules table — the old upsert path keeps
-- working during the transition. A future migration may drop modules's
-- per-app shape once all callers are reading from module_app_refs.
--
-- New tables:
--   files          — physical-file dedup (file_sha256). One file shipped
--                    by N apps = 1 file row, N file_app_refs rows.
--   file_app_refs  — (file_sha256, source_id, rel_path) → which capture
--                    of which app contains a given file. Normalises
--                    module_sightings.source_file (free-form TEXT) into
--                    a stable cross-machine reference.
--   module_app_refs — (body_sha256, app, source_id) → cross-app body
--                    sharing. Lets a single body row participate in many
--                    apps without duplicating name/summary/enrichment
--                    metadata (those stay keyed by body_sha256).
--
-- Backfill: opportunistic only. New captures populate the new tables;
-- legacy SQLite-migrated rows whose modules.last_source_id IS NULL stay
-- untouched. Down migration drops the three tables; legacy modules data
-- is preserved.
-- ─────────────────────────────────────────────────────────────────────────

-- ────────────────────────────── files ────────────────────────────────────
-- file_sha256 is the dedup key. Distinct from body_sha256: a file CONTAINS
-- many module bodies (one .js bundle holds many module factories).
CREATE TABLE files (
  file_sha256   TEXT PRIMARY KEY,
  file_size     BIGINT NOT NULL,
  first_seen_at BIGINT NOT NULL,
  detected_kind TEXT             -- "webpack-bundle", "asar", "metro-bundle", "appx-manifest", ...
);
CREATE INDEX files_kind_idx ON files (detected_kind) WHERE detected_kind IS NOT NULL;

-- ─────────────────────────── file_app_refs ──────────────────────────────
-- Each capture pass produces one row per file actually present at that
-- capture's source root. rel_path is the path RELATIVE to the source root
-- so it survives across machines (e.g. "resources/app.asar" not the
-- absolute install path).
CREATE TABLE file_app_refs (
  file_sha256 TEXT   NOT NULL REFERENCES files(file_sha256) ON DELETE CASCADE,
  source_id   BIGINT NOT NULL REFERENCES knowledge_sources(id) ON DELETE CASCADE,
  rel_path    TEXT   NOT NULL,
  observed_at BIGINT NOT NULL,
  PRIMARY KEY (file_sha256, source_id, rel_path)
);
CREATE INDEX file_app_refs_source_idx ON file_app_refs (source_id);
CREATE INDEX file_app_refs_path_idx   ON file_app_refs (rel_path);

-- ───────────────────────── module_app_refs ──────────────────────────────
-- Cross-app body-sharing reference. Same body_sha256 appearing in N apps
-- produces N rows here. Use this in preference to modules's per-app shape
-- for any new analysis that needs cross-app reuse stats.
--
-- The body row in module_bodies is the canonical content; metadata that
-- belongs to the body (name, summary, enrichment) stays keyed by
-- body_sha256 in modules / module_enrichment. The module_app_refs row
-- only adds: which app saw it, in which capture, when.
CREATE TABLE module_app_refs (
  body_sha256 TEXT   NOT NULL REFERENCES module_bodies(body_sha256) ON DELETE CASCADE,
  app         TEXT   NOT NULL,
  source_id   BIGINT NOT NULL REFERENCES knowledge_sources(id) ON DELETE CASCADE,
  observed_at BIGINT NOT NULL,
  PRIMARY KEY (body_sha256, app, source_id)
);
CREATE INDEX module_app_refs_app_idx        ON module_app_refs (app);
CREATE INDEX module_app_refs_source_idx     ON module_app_refs (source_id);
CREATE INDEX module_app_refs_body_sha_idx   ON module_app_refs (body_sha256);

-- ─────────────────────────── Backfill (opt-in) ──────────────────────────
-- Synthesise module_app_refs rows for every existing modules row whose
-- last_source_id is known. Legacy rows (SQLite-migrated, source_id NULL)
-- are skipped — they will be backfilled organically next time the body
-- is observed.
INSERT INTO module_app_refs (body_sha256, app, source_id, observed_at)
SELECT m.body_sha256, m.app, m.last_source_id, m.last_seen_at
  FROM modules m
 WHERE m.last_source_id IS NOT NULL
   AND m.last_seen_at IS NOT NULL
ON CONFLICT (body_sha256, app, source_id) DO NOTHING;

-- ─────────────────────────────── Helper view ─────────────────────────────
-- "How many distinct apps share this body, and which captures saw it?"
-- Cheap to query via a left join from module_bodies.
CREATE VIEW module_body_reuse AS
SELECT
  mb.body_sha256,
  mb.body_size,
  COUNT(DISTINCT r.app)        AS app_count,
  COUNT(DISTINCT r.source_id)  AS capture_count,
  MIN(r.observed_at)           AS first_observed_at,
  MAX(r.observed_at)           AS last_observed_at
FROM module_bodies mb
LEFT JOIN module_app_refs r ON r.body_sha256 = mb.body_sha256
GROUP BY mb.body_sha256, mb.body_size;

-- "Per-app capture summary: version, file count, body count, share
--  with other apps." Single-query answer to "what changed between
--  v6.7.4 and v6.7.5" + "which of those bodies are unique to this app
--  vs shared with other apps."
CREATE VIEW knowledge_capture_summary AS
SELECT
  ks.app,
  ks.epoch,
  ks.app_version,
  ks.captured_at,
  ks.source_kind,
  ks.source_path,
  COALESCE(f.files_count, 0)             AS files_count,
  COALESCE(b.bodies_count, 0)            AS bodies_count,
  COALESCE(b.shared_count, 0)            AS bodies_shared_with_other_apps
FROM knowledge_sources ks
LEFT JOIN (
  SELECT source_id, COUNT(DISTINCT file_sha256) AS files_count
    FROM file_app_refs
   GROUP BY source_id
) f ON f.source_id = ks.id
LEFT JOIN (
  SELECT
    r.source_id,
    COUNT(DISTINCT r.body_sha256) AS bodies_count,
    SUM(CASE WHEN x.other_apps > 0 THEN 1 ELSE 0 END) AS shared_count
  FROM module_app_refs r
  LEFT JOIN LATERAL (
    SELECT COUNT(DISTINCT r2.app) - 1 AS other_apps
      FROM module_app_refs r2
     WHERE r2.body_sha256 = r.body_sha256
  ) x ON true
  GROUP BY r.source_id
) b ON b.source_id = ks.id;
