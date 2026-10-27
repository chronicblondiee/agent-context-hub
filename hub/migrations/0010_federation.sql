-- Explicit hub-to-hub peers and application receipts. Transport has API access only.
CREATE TABLE federation_peers (
    project_id TEXT NOT NULL REFERENCES projects(id),
    remote_project TEXT NOT NULL,
    transport_id TEXT NOT NULL REFERENCES principals(id),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
    PRIMARY KEY (project_id, remote_project)
) STRICT, WITHOUT ROWID;

CREATE TABLE federation_shares (
    project_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    remote_project TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    PRIMARY KEY (project_id, record_id, remote_project),
    FOREIGN KEY (project_id, record_id) REFERENCES memory_records(project_id, id),
    FOREIGN KEY (project_id, remote_project) REFERENCES federation_peers(project_id, remote_project)
) STRICT, WITHOUT ROWID;

CREATE TABLE federation_outbox (
    project_id TEXT NOT NULL REFERENCES projects(id),
    id TEXT NOT NULL,
    remote_project TEXT NOT NULL,
    payload TEXT NOT NULL CHECK (json_valid(payload)),
    digest TEXT NOT NULL CHECK (length(digest)=64),
    applied INTEGER NOT NULL DEFAULT 0 CHECK (applied IN (0,1)),
    created_us INTEGER NOT NULL,
    PRIMARY KEY (project_id, id),
    FOREIGN KEY (project_id, remote_project) REFERENCES federation_peers(project_id, remote_project)
) STRICT, WITHOUT ROWID;
CREATE INDEX federation_outbox_pending ON federation_outbox(project_id, applied, created_us);

CREATE TABLE federation_inbox (
    project_id TEXT NOT NULL REFERENCES projects(id),
    origin_project TEXT NOT NULL,
    id TEXT NOT NULL,
    digest TEXT NOT NULL CHECK (length(digest)=64),
    applied_us INTEGER NOT NULL,
    PRIMARY KEY (project_id, origin_project, id)
) STRICT, WITHOUT ROWID;

CREATE TABLE federation_records (
    project_id TEXT NOT NULL REFERENCES projects(id),
    origin_project TEXT NOT NULL,
    origin_record TEXT NOT NULL,
    record_id TEXT NOT NULL,
    superseded_by TEXT,
    revision INTEGER NOT NULL CHECK (revision > 0),
    digest TEXT NOT NULL CHECK (length(digest)=64),
    PRIMARY KEY (project_id, origin_project, origin_record),
    UNIQUE (project_id, record_id)
) STRICT, WITHOUT ROWID;
