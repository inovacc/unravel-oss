-- KBC-ENRICH-MODEL-ESCALATION — opus retry + human-verification flag.
-- Additive: existing kbenrich code paths continue to work unchanged until
-- the orchestration layer (EnrichCore + new _human_review MCP tool) is
-- wired in a follow-up.

-- needs_human_verification: set when both sonnet and opus failed on this
-- module. Modules with this flag set MUST NOT be re-enqueued by normal
-- enrichment runs (filter in PendingModules). Cleared only by human
-- review via the new _human_review MCP tool.
ALTER TABLE modules
    ADD COLUMN IF NOT EXISTS needs_human_verification boolean NOT NULL DEFAULT false;

-- escalated_to: NULL when normal sonnet enrichment succeeded; 'opus' when
-- the escalation path produced the surviving summary. Audit trail for the
-- per-module model used; complements enrich_attempts.attempt_no history.
ALTER TABLE modules
    ADD COLUMN IF NOT EXISTS escalated_to text NULL
    CHECK (escalated_to IS NULL OR escalated_to IN ('opus'));

-- Partial index for the new MCP _human_review tool: fast scan of the
-- (small, expected) set of modules awaiting human verification.
CREATE INDEX IF NOT EXISTS idx_modules_needs_human_verification
    ON modules (app, id)
    WHERE needs_human_verification;
