-- Postgres port of the unravel knowledge catalog (formerly SQLite).
-- See docs/MIGRATION-postgres.md for the SQLite↔PG mapping.

CREATE EXTENSION IF NOT EXISTS pg_trgm;
-- pgvector is optional for now (BYTEA-backed embeddings); we install the
-- extension so a future per-dim materialized vector column can be added
-- without DDL freeze.
CREATE EXTENSION IF NOT EXISTS vector;

-- ─────────────────────────────── modules ─────────────────────────────────
CREATE TABLE modules (
  id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  app             TEXT NOT NULL,
  name            TEXT NOT NULL,
  synthetic_name  TEXT,
  prefix          TEXT,
  body_size       BIGINT,
  body_excerpt    TEXT,
  body_sha256     TEXT NOT NULL,
  symbols_json    TEXT,
  summary         TEXT,
  tags            TEXT,
  first_seen_at   BIGINT,
  last_seen_at    BIGINT,
  lang            TEXT,
  repo_root       TEXT,
  search_text     TEXT GENERATED ALWAYS AS (
    coalesce(name,'') || ' ' ||
    coalesce(synthetic_name,'') || ' ' ||
    coalesce(body_excerpt,'') || ' ' ||
    coalesce(symbols_json,'') || ' ' ||
    coalesce(summary,'') || ' ' ||
    coalesce(tags,'')
  ) STORED,
  UNIQUE (app, body_sha256)
);
CREATE INDEX modules_app_name_idx     ON modules (app, name);
CREATE INDEX modules_summary_null_idx ON modules (app) WHERE summary IS NULL;
CREATE INDEX modules_synth_idx        ON modules (synthetic_name);
CREATE INDEX modules_lang_idx         ON modules (lang)      WHERE lang IS NOT NULL;
CREATE INDEX modules_repo_root_idx    ON modules (repo_root) WHERE repo_root IS NOT NULL;
CREATE INDEX modules_search_trgm_idx  ON modules USING GIN (search_text gin_trgm_ops);

-- ─────────────────────────── module_sightings ────────────────────────────
CREATE TABLE module_sightings (
  id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  module_id    BIGINT NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
  source_file  TEXT NOT NULL,
  byte_offset  BIGINT,
  observed_at  BIGINT NOT NULL,
  UNIQUE (module_id, source_file, byte_offset)
);
CREATE INDEX module_sightings_mid_idx ON module_sightings (module_id);
CREATE INDEX module_sightings_at_idx  ON module_sightings (observed_at);

-- ───────────────────────────── module_bodies ─────────────────────────────
CREATE TABLE module_bodies (
  body_sha256 TEXT PRIMARY KEY,
  body        BYTEA NOT NULL,
  body_size   BIGINT,
  stored_at   BIGINT
);

-- ─────────────────────────── module_enrichment ───────────────────────────
CREATE TABLE module_enrichment (
  module_id     BIGINT PRIMARY KEY REFERENCES modules(id) ON DELETE CASCADE,
  long_summary  TEXT,
  role          TEXT,
  inputs_json   TEXT,
  outputs_json  TEXT,
  side_effects  TEXT,
  deps_json     TEXT,
  raw_response  TEXT,
  model         TEXT,
  body_sha256   TEXT,
  created_at    BIGINT
);

-- ────────────────────────────── module_deps ──────────────────────────────
CREATE TABLE module_deps (
  from_id  BIGINT NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
  to_name  TEXT NOT NULL,
  to_id    BIGINT,
  PRIMARY KEY (from_id, to_name)
);
CREATE INDEX module_deps_to_idx    ON module_deps (to_name);
CREATE INDEX module_deps_to_id_idx ON module_deps (to_id) WHERE to_id IS NOT NULL;

-- ───────────────────────────── module_topics ─────────────────────────────
CREATE TABLE module_topics (
  module_id BIGINT NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
  topic     TEXT NOT NULL,
  score     REAL DEFAULT 1.0,
  PRIMARY KEY (module_id, topic)
);
CREATE INDEX module_topics_topic_idx ON module_topics (topic);

-- ─────────────────────────────── app_facts ───────────────────────────────
CREATE TABLE app_facts (
  id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  app           TEXT NOT NULL,
  category      TEXT NOT NULL,
  key           TEXT NOT NULL,
  value         TEXT,
  evidence_ids  TEXT,
  source_step   TEXT,
  confidence    REAL,
  gap_prompt    TEXT,
  candidates_q  TEXT,
  value_format  TEXT,
  filled_at     BIGINT,
  updated_at    BIGINT,
  UNIQUE (app, category, key)
);
CREATE INDEX app_facts_open_idx ON app_facts (app, category) WHERE value IS NULL;

-- ────────────────────────────── fact_history ─────────────────────────────
CREATE TABLE fact_history (
  fact_id       BIGINT NOT NULL REFERENCES app_facts(id) ON DELETE CASCADE,
  value         TEXT,
  evidence_ids  TEXT,
  source_step   TEXT,
  confidence    REAL,
  observed_at   BIGINT NOT NULL,
  PRIMARY KEY (fact_id, observed_at)
);

-- ─────────────────────────── module_embeddings ───────────────────────────
-- BYTEA layout: f32 (len = dim*4) or f16 (len = dim*2). Per-dim materialized
-- vector columns can be added in a later migration when search needs them.
CREATE TABLE module_embeddings (
  module_id   BIGINT PRIMARY KEY REFERENCES modules(id) ON DELETE CASCADE,
  model       TEXT NOT NULL,
  dim         INTEGER NOT NULL,
  vector      BYTEA NOT NULL,
  created_at  BIGINT,
  CONSTRAINT module_embeddings_layout_chk
    CHECK (octet_length(vector) = dim * 4 OR octet_length(vector) = dim * 2)
);

-- ────────────────────────────────── repos ────────────────────────────────
CREATE TABLE repos (
  slug         TEXT PRIMARY KEY,
  root         TEXT NOT NULL,
  vcs          TEXT,
  vcs_head     TEXT,
  indexed_at   BIGINT,
  module_count BIGINT DEFAULT 0,
  total_bytes  BIGINT DEFAULT 0
);
CREATE INDEX repos_root_idx ON repos (root);
