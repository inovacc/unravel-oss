-- knowledge_sources_git adds commit tracking for Git-managed repositories.
ALTER TABLE knowledge_sources
  ADD COLUMN commit_hash TEXT;

COMMENT ON COLUMN knowledge_sources.commit_hash IS 'Git commit hash for repo-managed knowledge sources (D-39-SOKS).';
