-- One-way, API-fed sources. The connector never opens this database.
CREATE TABLE sources (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id),
    connector_id TEXT NOT NULL REFERENCES principals(id),
    endpoint TEXT NOT NULL,
    aic_project TEXT NOT NULL,
    cursor INTEGER NOT NULL DEFAULT 0 CHECK (cursor >= 0),
    last_sync_us INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled', 'error')),
    created_us INTEGER NOT NULL
) STRICT;

CREATE TABLE source_events (
    source_id TEXT NOT NULL REFERENCES sources(id),
    seq INTEGER NOT NULL,
    digest TEXT NOT NULL CHECK (length(digest) = 64),
    PRIMARY KEY (source_id, seq)
) STRICT, WITHOUT ROWID;

CREATE TABLE source_rows (
    source_id TEXT NOT NULL REFERENCES sources(id),
    external_kind TEXT NOT NULL,
    external_id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id),
    record_id TEXT NOT NULL,
    digest TEXT NOT NULL CHECK (length(digest) = 64),
    source_seq INTEGER NOT NULL,
    superseded_by TEXT,
    PRIMARY KEY (source_id, external_kind, external_id),
    UNIQUE (project_id, record_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX source_rows_record ON source_rows(project_id, record_id);
