-- pkg/knowledge/kb/db/migrations/000021_kb_ai_findings.up.sql
-- KB AI Findings adjudication layer (Phase A).
-- Stores structured AI verdicts (affirm/contradict/augment/uncertain) over KB claims,
-- plus a per-pass iteration trail. run_id mirrors enrich_runs.run_id (UUID).

CREATE TABLE IF NOT EXISTS kb_ai_findings (
    id            BIGSERIAL PRIMARY KEY,
    app           TEXT    NOT NULL,                  -- KB app slug
    module_id     BIGINT  REFERENCES modules(id) ON DELETE CASCADE,  -- NULL = app-level finding
    scope         TEXT    NOT NULL DEFAULT 'module', -- module | app | cross-module
    target_kind   TEXT    NOT NULL,                  -- summary|role|side_effect|dep|input|output|security|vendored|app_fact|other
    target_ref    TEXT,                              -- specific claim: field name / app_fact key / quoted snippet
    claim         TEXT    NOT NULL,                  -- the KB assertion under scrutiny (quoted verbatim)
    stance        TEXT    NOT NULL,                  -- affirm | contradict | augment | uncertain
    finding       TEXT    NOT NULL,                  -- the verdict + reasoning
    evidence      TEXT,                              -- citations: module ids, body offsets, external URLs
    confidence    REAL,                              -- 0..1 final confidence
    severity      TEXT,                              -- info | low | medium | high (mainly for contradict)
    iterations    INT     NOT NULL DEFAULT 1,        -- passes to converge
    converged     BOOLEAN NOT NULL DEFAULT TRUE,     -- reached stability vs hit max-iter cap
    model_used    TEXT,
    run_id        UUID,                              -- groups one audit run
    status        TEXT    NOT NULL DEFAULT 'open',   -- open | accepted | rejected | applied | superseded
    created_at    BIGINT  NOT NULL,                  -- epoch ms
    resolved_at   BIGINT,
    resolved_by   TEXT
);
CREATE INDEX IF NOT EXISTS idx_kb_ai_findings_app    ON kb_ai_findings(app);
CREATE INDEX IF NOT EXISTS idx_kb_ai_findings_module ON kb_ai_findings(module_id);
CREATE INDEX IF NOT EXISTS idx_kb_ai_findings_stance ON kb_ai_findings(stance);
CREATE INDEX IF NOT EXISTS idx_kb_ai_findings_status ON kb_ai_findings(status);
CREATE INDEX IF NOT EXISTS idx_kb_ai_findings_run    ON kb_ai_findings(run_id);

-- per-pass audit trail
CREATE TABLE IF NOT EXISTS kb_ai_finding_iterations (
    finding_id     BIGINT  NOT NULL REFERENCES kb_ai_findings(id) ON DELETE CASCADE,
    iter           INT     NOT NULL,                 -- 1..N
    interim_stance TEXT,                             -- verdict at this pass
    interim_conf   REAL,
    challenger     TEXT,                             -- which lens/adversary ran this pass
    changed        BOOLEAN NOT NULL DEFAULT FALSE,   -- did the verdict flip vs the prior pass
    note           TEXT,                             -- what the challenge / re-examination found
    created_at     BIGINT  NOT NULL,
    PRIMARY KEY (finding_id, iter)
);
