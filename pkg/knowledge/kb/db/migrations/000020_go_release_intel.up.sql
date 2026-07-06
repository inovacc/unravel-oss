-- pkg/knowledge/kb/db/migrations/000020_go_release_intel.up.sql
-- Go Release Intelligence (Sub-project A): release catalog + CVE posture.
-- Additive; picked up by the //go:embed in db.go.

CREATE TABLE IF NOT EXISTS go_releases (
    version          TEXT PRIMARY KEY,
    stable           BOOLEAN NOT NULL,
    release_date     DATE,
    notes_url        TEXT,
    security_summary TEXT,
    first_seen_at    BIGINT NOT NULL,
    last_seen_at     BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS go_release_files (
    version  TEXT NOT NULL REFERENCES go_releases(version) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    os       TEXT NOT NULL DEFAULT '',
    arch     TEXT NOT NULL DEFAULT '',
    kind     TEXT NOT NULL,
    sha256   TEXT NOT NULL,
    size     BIGINT NOT NULL,
    PRIMARY KEY (version, filename)
);
CREATE INDEX IF NOT EXISTS idx_go_release_files_sha256 ON go_release_files (sha256);

CREATE TABLE IF NOT EXISTS go_vulns (
    id        TEXT PRIMARY KEY,
    aliases   TEXT,
    summary   TEXT,
    url       TEXT,
    published DATE,
    modified  DATE
);

CREATE TABLE IF NOT EXISTS go_vuln_affected (
    vuln_id    TEXT NOT NULL REFERENCES go_vulns(id) ON DELETE CASCADE,
    component  TEXT NOT NULL,
    introduced TEXT NOT NULL DEFAULT '0',
    fixed      TEXT
);
CREATE INDEX IF NOT EXISTS idx_go_vuln_affected_vuln ON go_vuln_affected (vuln_id);

CREATE TABLE IF NOT EXISTS go_sync_state (
    source       TEXT PRIMARY KEY,
    last_sync_at BIGINT NOT NULL,
    item_count   INTEGER NOT NULL DEFAULT 0,
    note         TEXT
);
