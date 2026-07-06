-- KB-OVERSEG P3 — revert vendored ingest gate.
DROP INDEX IF EXISTS idx_modules_app_firstparty;
ALTER TABLE modules DROP COLUMN IF EXISTS is_vendored;
