-- pkg/knowledge/kb/db/migrations/000021_kb_ai_findings.down.sql
-- Revert KB AI Findings adjudication layer.
DROP TABLE IF EXISTS kb_ai_finding_iterations;
DROP TABLE IF EXISTS kb_ai_findings;
