-- 000007_module_topics_deprecate.down.sql
COMMENT ON TABLE  module_topics       IS NULL;
COMMENT ON COLUMN module_topics.topic IS NULL;
-- Synthesised rows in module_components remain on down — they are now the
-- canonical source. Re-orphaning modules would lose data.
