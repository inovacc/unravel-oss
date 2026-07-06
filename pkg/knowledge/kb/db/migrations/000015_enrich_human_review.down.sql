DROP INDEX IF EXISTS idx_modules_needs_human_verification;
ALTER TABLE modules DROP COLUMN IF EXISTS escalated_to;
ALTER TABLE modules DROP COLUMN IF EXISTS needs_human_verification;
