-- KB-OVERSEG P3 — vendored ingest gate (MARK and exclude, zero data loss).
-- Additive; existing rows default to is_vendored = false (first-party).
-- Picked up by the //go:embed in db.go.

-- 1. Mark column. Set at ingest time by scanner.IsVendoredBody; never used to
--    skip persisting a row, only to exclude rows from enrichment selection.
ALTER TABLE modules ADD COLUMN IF NOT EXISTS is_vendored boolean NOT NULL DEFAULT false;

-- 2. Partial index over first-party rows only — keeps pending-enrichment and
--    coverage scans cheap once the vendored rows are filtered out.
CREATE INDEX IF NOT EXISTS idx_modules_app_firstparty ON modules (app) WHERE is_vendored = false;
