-- knowledge_sources tracks every capture/scan event so the catalog can
-- show app evolution over time. One row per (app, capture). The epoch
-- column is a per-app monotonically-increasing integer that doubles as a
-- human-readable "capture #N" identifier.

CREATE TABLE knowledge_sources (
  id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  app             TEXT NOT NULL,
  epoch           INTEGER NOT NULL,                          -- 1,2,3,... per app
  source_path     TEXT NOT NULL,                             -- absolute path of the captured asset
  source_kind     TEXT NOT NULL,                             -- msix|squirrel|asar|cache|repo|other
  app_version     TEXT,                                      -- parsed from manifest / path (best-effort)
  source_sha256   TEXT,                                      -- sha256 of the asset (NULL for directory captures)
  captured_at     BIGINT NOT NULL,                           -- ms epoch
  modules_indexed BIGINT DEFAULT 0,                          -- backfilled by the indexer at end of pass
  bodies_indexed  BIGINT DEFAULT 0,
  notes           TEXT,
  UNIQUE (app, epoch),
  UNIQUE (app, source_sha256)
);
CREATE INDEX knowledge_sources_app_idx        ON knowledge_sources (app);
CREATE INDEX knowledge_sources_captured_idx   ON knowledge_sources (captured_at DESC);

-- Add a back-reference column on modules so we can answer "which capture
-- introduced this body?" without joining through module_sightings.
ALTER TABLE modules
  ADD COLUMN first_source_id BIGINT REFERENCES knowledge_sources(id) ON DELETE SET NULL,
  ADD COLUMN last_source_id  BIGINT REFERENCES knowledge_sources(id) ON DELETE SET NULL;
CREATE INDEX modules_first_source_idx ON modules (first_source_id) WHERE first_source_id IS NOT NULL;
CREATE INDEX modules_last_source_idx  ON modules (last_source_id)  WHERE last_source_id  IS NOT NULL;

-- module_sightings already records the raw source_file string per row;
-- linking it to knowledge_sources is opt-in so historical sightings (from
-- the SQLite migrator) keep the NULL.
ALTER TABLE module_sightings
  ADD COLUMN source_id BIGINT REFERENCES knowledge_sources(id) ON DELETE SET NULL;
CREATE INDEX module_sightings_source_idx ON module_sightings (source_id) WHERE source_id IS NOT NULL;

-- Helper view: per-app evolution timeline. One row per (app, epoch),
-- exposing module-count delta between consecutive captures so callers
-- can answer "what changed between v6.7.4 and v6.7.5".
CREATE VIEW knowledge_source_evolution AS
SELECT
  ks.app,
  ks.epoch,
  ks.app_version,
  ks.captured_at,
  ks.source_kind,
  ks.modules_indexed,
  ks.modules_indexed
    - LAG(ks.modules_indexed) OVER (PARTITION BY ks.app ORDER BY ks.epoch)
    AS modules_delta,
  ks.bodies_indexed,
  ks.bodies_indexed
    - LAG(ks.bodies_indexed) OVER (PARTITION BY ks.app ORDER BY ks.epoch)
    AS bodies_delta,
  ks.source_path,
  ks.notes
FROM knowledge_sources ks
ORDER BY ks.app, ks.epoch;
