ALTER TABLE modules ADD COLUMN IF NOT EXISTS topic TEXT;
CREATE INDEX IF NOT EXISTS modules_topic_idx ON modules (topic);
