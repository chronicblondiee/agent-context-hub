-- Shared and agent-private memory. Records are immutable: a revision supersedes, revocation flags.
CREATE TABLE memory_records (
    project_id TEXT NOT NULL REFERENCES projects(id),
    id TEXT NOT NULL,
    task_id TEXT,
    namespace TEXT NOT NULL,
    kind TEXT NOT NULL,
    body TEXT NOT NULL,
    hook TEXT NOT NULL,
    provenance TEXT NOT NULL CHECK (provenance IN ('stated', 'tested', 'assumed', 'inferred')),
    confidence REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    author TEXT NOT NULL,
    evidence TEXT NOT NULL CHECK (json_valid(evidence) AND json_array_length(evidence) > 0),
    visibility TEXT NOT NULL CHECK (visibility IN ('private', 'project')),
    revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
    superseded_by TEXT,
    created_us INTEGER NOT NULL,
    PRIMARY KEY (project_id, id),
    FOREIGN KEY (project_id, superseded_by) REFERENCES memory_records(project_id, id)
) STRICT, WITHOUT ROWID;

CREATE INDEX memory_author ON memory_records (project_id, author, created_us);
