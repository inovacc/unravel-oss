-- ─────────────────────────────────────────────────────────────────────────
-- Migration 000005: explicit diffs + component classification
-- ─────────────────────────────────────────────────────────────────────────
-- knowledge_source_evolution view in 000002 only deltas module/body
-- counts. Callers can't ask "which deps were added", "which capabilities
-- changed", "which URLs disappeared" without ad-hoc joins.
--
-- This migration adds:
--   kb_diffs           — typed change log between consecutive snapshots.
--   module_components  — fixed-taxonomy component bucket per module
--                        (communication|auth|ui|ipc|security|stealth|
--                         telemetry|storage|crypto|protocol|other).
--                        Coexists with module_topics (free-form) for
--                        legacy data; new ingestion writes both.
-- ─────────────────────────────────────────────────────────────────────────

-- ─────────────────────────────── kb_diffs ────────────────────────────────
CREATE TABLE kb_diffs (
  from_source_id BIGINT NOT NULL REFERENCES knowledge_sources(id) ON DELETE CASCADE,
  to_source_id   BIGINT NOT NULL REFERENCES knowledge_sources(id) ON DELETE CASCADE,
  category       TEXT   NOT NULL,
  change_type    TEXT   NOT NULL,
  identifier     TEXT   NOT NULL,
  payload        JSONB  NOT NULL,
  computed_at    BIGINT NOT NULL,
  PRIMARY KEY (from_source_id, to_source_id, category, change_type, identifier),
  CONSTRAINT kb_diffs_category_chk CHECK (category IN
    ('file','dep','capability','url','risk','cert','fact','module','component')),
  CONSTRAINT kb_diffs_change_chk CHECK (change_type IN
    ('added','removed','modified'))
);
CREATE INDEX kb_diffs_to_idx       ON kb_diffs (to_source_id);
CREATE INDEX kb_diffs_category_idx ON kb_diffs (category, change_type);
CREATE INDEX kb_diffs_payload_idx  ON kb_diffs USING GIN (payload jsonb_path_ops);

-- ───────────────────────── module_components ────────────────────────────
CREATE TABLE module_components (
  module_id     BIGINT PRIMARY KEY REFERENCES modules(id) ON DELETE CASCADE,
  component     TEXT NOT NULL,
  confidence    REAL NOT NULL DEFAULT 1.0,
  classifier    TEXT NOT NULL,
  classified_at BIGINT NOT NULL,
  CONSTRAINT module_components_component_chk CHECK (component IN
    ('communication','auth','ui','ipc','security','stealth',
     'telemetry','storage','crypto','protocol','other')),
  CONSTRAINT module_components_classifier_chk CHECK (classifier IN
    ('rule','llm','manual','heuristic'))
);
CREATE INDEX module_components_comp_idx ON module_components (component);
CREATE INDEX module_components_conf_idx ON module_components (confidence);
