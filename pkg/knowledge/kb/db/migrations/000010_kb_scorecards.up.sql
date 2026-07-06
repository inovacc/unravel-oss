-- v2.10 P59-02: kb_scorecards sidecar (RESEARCH Path B).
--
-- Notes:
--   * kb_apps.kb_id is TEXT (not BYTEA) in the shipped schema (000004); we
--     mirror that here. Plan PR text said BYTEA — adapted to reality.
--   * knowledge_sources.id is BIGINT GENERATED ALWAYS AS IDENTITY (000002).
--   * mean_score holds mean10 (e.g. 858 == 85.8%) per B2 integer-only.
--   * UNIQUE(source_id) enforces RESEARCH Q4: one scorecard per snapshot.
--   * iterations_jsonl is a single JSONB blob of the IterationLog (NOT
--     line-separated JSONL on disk — name preserved for symmetry with the
--     iterations.jsonl sidecar file).
CREATE TABLE IF NOT EXISTS kb_scorecards (
    id               BIGSERIAL PRIMARY KEY,
    kb_id            TEXT     NOT NULL REFERENCES kb_apps(kb_id),
    source_id        BIGINT   NOT NULL REFERENCES knowledge_sources(id),
    mean_score       INTEGER  NOT NULL,
    dims_at_80       INTEGER  NOT NULL,
    dims_at_50       INTEGER  NOT NULL,
    dims_at_20       INTEGER  NOT NULL,
    loop_exit        BOOLEAN  NOT NULL,
    citations_ok     BOOLEAN  NOT NULL,
    iterations       INTEGER  NOT NULL,
    iterations_jsonl JSONB,
    scorecard_json   JSONB    NOT NULL,
    generated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (source_id)
);

CREATE INDEX IF NOT EXISTS idx_kb_scorecards_kb_id_generated_at
    ON kb_scorecards (kb_id, generated_at DESC);

CREATE INDEX IF NOT EXISTS idx_kb_scorecards_mean
    ON kb_scorecards (mean_score);

CREATE INDEX IF NOT EXISTS idx_kb_scorecards_loop_exit_partial
    ON kb_scorecards (loop_exit) WHERE loop_exit = true;
