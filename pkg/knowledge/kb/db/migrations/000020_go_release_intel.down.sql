-- pkg/knowledge/kb/db/migrations/000020_go_release_intel.down.sql
-- Revert Go Release Intelligence (Sub-project A).
DROP TABLE IF EXISTS go_sync_state;
DROP TABLE IF EXISTS go_vuln_affected;
DROP TABLE IF EXISTS go_vulns;
DROP INDEX IF EXISTS idx_go_release_files_sha256;
DROP TABLE IF EXISTS go_release_files;
DROP TABLE IF EXISTS go_releases;
