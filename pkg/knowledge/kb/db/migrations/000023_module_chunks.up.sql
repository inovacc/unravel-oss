-- module_chunks stores semantic slices of code/prose for high-precision search.
-- Derived from context-mode (D-40-SEMANTIC-CHUNKING).
CREATE TABLE module_chunks (
  id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  module_id       BIGINT NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
  title           TEXT NOT NULL, -- e.g. "Auth > Login Flow" or "config.database.host"
  content         TEXT NOT NULL,
  has_code        BOOLEAN DEFAULT FALSE,
  chunk_index     INTEGER NOT NULL,
  created_at      BIGINT NOT NULL
);

CREATE INDEX module_chunks_mid_idx ON module_chunks (module_id);
-- Trigram index for ultra-fast, similarity-ranked search over semantic chunks.
CREATE INDEX module_chunks_search_idx ON module_chunks USING GIN (content gin_trgm_ops);
