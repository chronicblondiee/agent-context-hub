-- Every project-owned row carries project_id in its key; sequences count per project so
-- one project's cursor never reveals another project's activity.
CREATE TABLE projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_us INTEGER NOT NULL
) STRICT;

-- Durable work state (tasks, sessions, checkpoints, actions) as JSON documents.
CREATE TABLE objects (
    project_id TEXT NOT NULL REFERENCES projects(id),
    kind TEXT NOT NULL,
    id TEXT NOT NULL,
    body TEXT NOT NULL CHECK (json_valid(body)),
    PRIMARY KEY (project_id, kind, id)
) STRICT, WITHOUT ROWID;

CREATE TABLE audit (
    project_id TEXT NOT NULL REFERENCES projects(id),
    seq INTEGER NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    object_id TEXT NOT NULL,
    detail TEXT NOT NULL CHECK (json_valid(detail)),
    created_us INTEGER NOT NULL,
    PRIMARY KEY (project_id, seq)
) STRICT, WITHOUT ROWID;

CREATE TABLE changes (
    project_id TEXT NOT NULL REFERENCES projects(id),
    seq INTEGER NOT NULL,
    actor TEXT NOT NULL,
    operation TEXT NOT NULL,
    object_id TEXT NOT NULL,
    detail TEXT NOT NULL CHECK (json_valid(detail)),
    created_us INTEGER NOT NULL,
    PRIMARY KEY (project_id, seq)
) STRICT, WITHOUT ROWID;

-- Keyed by actor too: one actor can never replay another actor's stored response.
CREATE TABLE idempotency (
    project_id TEXT NOT NULL REFERENCES projects(id),
    actor TEXT NOT NULL,
    key TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    response TEXT NOT NULL CHECK (json_valid(response)),
    created_us INTEGER NOT NULL,
    PRIMARY KEY (project_id, actor, key)
) STRICT, WITHOUT ROWID;
