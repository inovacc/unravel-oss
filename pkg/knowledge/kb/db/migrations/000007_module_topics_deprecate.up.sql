-- 000007_module_topics_deprecate.up.sql
-- Deprecates the module_topics table per MTOP-01..03 (v2.7 phase 44).
-- Removal target: on/after 2026-06-05 (>= 30 days from this commit per CLAUDE.md).

COMMENT ON TABLE  module_topics       IS 'DEPRECATED 2026-05-05; removal on/after 2026-06-05. Use module_components.';
COMMENT ON COLUMN module_topics.topic IS 'DEPRECATED — see module_components.component (fixed taxonomy).';

-- Idempotent backfill: synthesise module_components rows for modules that
-- have a module_topics row but no module_components row.
INSERT INTO module_components (module_id, component, confidence, classifier, classified_at)
SELECT
  mt.module_id,
  CASE
    WHEN mt.topic IN ('crypto','crypto-at-rest','crypto-in-transit') THEN 'crypto'
    WHEN mt.topic IN ('auth','authentication','authn','authz')        THEN 'auth'
    WHEN mt.topic IN ('messages','send','communication','comm')       THEN 'communication'
    WHEN mt.topic IN ('ui','frontend','render')                       THEN 'ui'
    WHEN mt.topic IN ('ipc','rpc','channel')                          THEN 'ipc'
    WHEN mt.topic IN ('telemetry','analytics','metrics')              THEN 'telemetry'
    WHEN mt.topic IN ('stealth','content-protection','hide')          THEN 'stealth'
    WHEN mt.topic IN ('storage','db','persistence')                   THEN 'storage'
    WHEN mt.topic IN ('protocol','wire','transport')                  THEN 'protocol'
    WHEN mt.topic IN ('security','sandbox','permission')              THEN 'security'
    ELSE 'other'
  END                                       AS component,
  LEAST(mt.score, 0.79)                     AS confidence,
  'rule'                                    AS classifier,
  (EXTRACT(EPOCH FROM NOW())::BIGINT) * 1000 AS classified_at
FROM (
  SELECT DISTINCT ON (module_id) module_id, topic, score
  FROM module_topics
  ORDER BY module_id, score DESC, topic ASC
) mt
WHERE NOT EXISTS (
  SELECT 1 FROM module_components mc WHERE mc.module_id = mt.module_id
)
ON CONFLICT (module_id) DO NOTHING;
