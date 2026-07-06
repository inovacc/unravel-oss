-- KBC-ENRICH-SESSION-MONITOR — audit + heartbeat tables.
-- Additive: existing kbenrich code paths continue to work unchanged.

CREATE TABLE IF NOT EXISTS enrich_runs (
    run_id             uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    app                text         NOT NULL,
    model              text         NOT NULL,
    concurrency        int          NOT NULL,
    prompt_batch       int          NOT NULL,
    started_at         timestamptz  NOT NULL DEFAULT now(),
    ended_at           timestamptz  NULL,
    status             text         NOT NULL,
    total_target       int          NOT NULL,
    completed          int          NOT NULL DEFAULT 0,
    failed             int          NOT NULL DEFAULT 0,
    last_heartbeat_at  timestamptz  NOT NULL DEFAULT now(),
    host               text         NOT NULL,
    pid                int          NOT NULL,
    parent_run_id      uuid         NULL REFERENCES enrich_runs(run_id) ON DELETE SET NULL,
    CONSTRAINT enrich_runs_status_chk CHECK (status IN ('in_progress','completed','failed','interrupted','legacy'))
);

CREATE INDEX IF NOT EXISTS idx_enrich_runs_app_started_at
    ON enrich_runs (app, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_enrich_runs_in_progress
    ON enrich_runs (last_heartbeat_at)
    WHERE status = 'in_progress';

CREATE TABLE IF NOT EXISTS enrich_attempts (
    attempt_id              bigserial    PRIMARY KEY,
    run_id                  uuid         NOT NULL REFERENCES enrich_runs(run_id) ON DELETE CASCADE,
    module_id               bigint       NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
    started_at              timestamptz  NOT NULL DEFAULT now(),
    ended_at                timestamptz  NULL,
    status                  text         NOT NULL,
    error_class             text         NULL,
    error_message_redacted  text         NULL,
    model_used              text         NOT NULL,
    prompt_tokens_est       int          NULL,
    attempt_no              int          NOT NULL,
    CONSTRAINT enrich_attempts_status_chk CHECK (status IN ('success','failure','timeout'))
);

CREATE INDEX IF NOT EXISTS idx_enrich_attempts_run_status
    ON enrich_attempts (run_id, status);

CREATE INDEX IF NOT EXISTS idx_enrich_attempts_module_started
    ON enrich_attempts (module_id, started_at DESC);

-- One-shot backfill: synthetic 'legacy' run per app with already-summarised modules,
-- guarded so re-running the migration is idempotent.
INSERT INTO enrich_runs (run_id, app, model, concurrency, prompt_batch,
                         started_at, ended_at, status, total_target,
                         completed, failed, last_heartbeat_at, host, pid)
SELECT gen_random_uuid(), COALESCE(app,''), 'legacy', 0, 0,
       now(), now(), 'legacy', COUNT(*), COUNT(*), 0, now(), 'migration', 0
  FROM modules
 WHERE summary IS NOT NULL AND summary <> ''
   AND NOT EXISTS (SELECT 1 FROM enrich_runs)
 GROUP BY app;
