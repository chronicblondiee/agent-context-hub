-- Large artifacts live under <data>/artifacts/<project>/<owner>/<id>; SQLite owns their
-- metadata and hashes (architecture.md). The AIC import fills it; no API serves it yet.
CREATE TABLE artifacts (
    project_id TEXT NOT NULL REFERENCES projects(id),
    owner TEXT NOT NULL,
    id TEXT NOT NULL,
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    size INTEGER NOT NULL CHECK (size >= 0),
    created_us INTEGER NOT NULL,
    PRIMARY KEY (project_id, owner, id)
) STRICT, WITHOUT ROWID;

-- AIC memory replicas: a record one stack received from a peer, compared by content hash with
-- its origin record once the origin stack is imported too. Similar text never matches. A
-- conflict is quarantined: kept and auditable, but removed from retrieval until reviewed.
CREATE TABLE import_replicas (
    project_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    origin_aic TEXT NOT NULL,
    origin_record TEXT NOT NULL,
    replica_sha256 TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'match', 'conflict')),
    origin_project TEXT REFERENCES projects(id),
    origin_sha256 TEXT,
    reason TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (project_id, record_id),
    FOREIGN KEY (project_id, record_id) REFERENCES memory_records(project_id, id)
) STRICT, WITHOUT ROWID;

CREATE INDEX import_replicas_pending ON import_replicas (status, origin_aic);
