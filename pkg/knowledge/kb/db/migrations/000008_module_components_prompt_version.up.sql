-- Phase 45 / Plan 45-02 / D-45-PROMPT-VERSIONING.
--
-- Adds module_components.prompt_version so the MCP classifier path
-- (classifier='llm') can record which embedded prompt revision produced
-- a verdict. NULL on rule/heuristic/manual rows. Used by future precision
-- gate analyses to scope metrics by prompt version.
ALTER TABLE module_components ADD COLUMN prompt_version TEXT NULL;
