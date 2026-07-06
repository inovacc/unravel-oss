-- 000009_drop_module_topics.down.sql
-- Best-effort restore: recreates the table shell from 000001_init_schema.
-- Data is NOT restored (it was migrated to module_components in 000007).

CREATE TABLE IF NOT EXISTS module_topics (
  module_id  BIGINT  NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
  topic      TEXT    NOT NULL,
  score      REAL    NOT NULL DEFAULT 1.0,
  PRIMARY KEY (module_id, topic)
);
CREATE INDEX IF NOT EXISTS module_topics_topic_idx ON module_topics (topic);
