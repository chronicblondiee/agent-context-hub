-- Project-scoped knowledge and durable derived indexes. FTS5 is necessarily a virtual table.
CREATE TABLE solutions (
    project_id TEXT NOT NULL REFERENCES projects(id),
    id TEXT NOT NULL,
    author TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('unverified','verified','review','revoked','superseded')),
    current_revision INTEGER NOT NULL CHECK (current_revision > 0),
    superseded_by TEXT,
    problem_key TEXT NOT NULL,
    created_us INTEGER NOT NULL,
    PRIMARY KEY (project_id, id),
    FOREIGN KEY (project_id, superseded_by) REFERENCES solutions(project_id, id)
) STRICT, WITHOUT ROWID;

CREATE TABLE solution_revisions (
    project_id TEXT NOT NULL,
    solution_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    body TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    author TEXT NOT NULL,
    repository_commit TEXT NOT NULL,
    image_digest TEXT NOT NULL,
    checks_sha256 TEXT NOT NULL,
    applicability TEXT NOT NULL CHECK (json_valid(applicability)),
    conflicts_with TEXT NOT NULL CHECK (json_valid(conflicts_with)),
    created_us INTEGER NOT NULL,
    PRIMARY KEY (project_id, solution_id, revision),
    FOREIGN KEY (project_id, solution_id) REFERENCES solutions(project_id, id)
) STRICT, WITHOUT ROWID;

CREATE TABLE attempts (
    project_id TEXT NOT NULL REFERENCES projects(id),
    id TEXT NOT NULL,
    task_id TEXT,
    author TEXT NOT NULL,
    approach TEXT NOT NULL,
    outcome TEXT NOT NULL,
    evidence TEXT NOT NULL CHECK (json_valid(evidence)),
    created_us INTEGER NOT NULL,
    PRIMARY KEY (project_id, id)
) STRICT, WITHOUT ROWID;

CREATE TABLE outcomes (
    project_id TEXT NOT NULL,
    id TEXT NOT NULL,
    solution_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    author TEXT NOT NULL,
    result TEXT NOT NULL CHECK (result IN ('success','failure')),
    evidence TEXT NOT NULL CHECK (json_valid(evidence)),
    created_us INTEGER NOT NULL,
    PRIMARY KEY (project_id, id),
    FOREIGN KEY (project_id, solution_id, revision)
        REFERENCES solution_revisions(project_id, solution_id, revision)
) STRICT, WITHOUT ROWID;

CREATE TABLE evidence (
    project_id TEXT NOT NULL,
    id TEXT NOT NULL,
    solution_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    verifier TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    checks_sha256 TEXT NOT NULL,
    repository_commit TEXT NOT NULL,
    image_digest TEXT NOT NULL,
    result TEXT NOT NULL CHECK (result IN ('pass','fail')),
    artifacts TEXT NOT NULL CHECK (json_valid(artifacts) AND json_array_length(artifacts) > 0),
    created_us INTEGER NOT NULL,
    PRIMARY KEY (project_id, id),
    FOREIGN KEY (project_id, solution_id, revision)
        REFERENCES solution_revisions(project_id, solution_id, revision)
) STRICT, WITHOUT ROWID;

CREATE TABLE decisions (
    project_id TEXT NOT NULL,
    id TEXT NOT NULL,
    solution_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    maintainer TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('approve','review','revoke','supersede')),
    reason TEXT NOT NULL,
    target_id TEXT,
    created_us INTEGER NOT NULL,
    PRIMARY KEY (project_id, id),
    FOREIGN KEY (project_id, solution_id, revision)
        REFERENCES solution_revisions(project_id, solution_id, revision)
) STRICT, WITHOUT ROWID;

CREATE VIRTUAL TABLE search_fts USING fts5(
    project_id UNINDEXED, kind UNINDEXED, record_id UNINDEXED, revision UNINDEXED,
    text, tokenize='unicode61'
);

CREATE TABLE chunk_vectors (
    project_id TEXT NOT NULL REFERENCES projects(id),
    kind TEXT NOT NULL,
    record_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    chunk INTEGER NOT NULL,
    model TEXT NOT NULL,
    dim INTEGER NOT NULL CHECK (dim = 384),
    vector BLOB NOT NULL,
    PRIMARY KEY (project_id, kind, record_id, revision, chunk, model)
) STRICT, WITHOUT ROWID;

CREATE TABLE embedding_jobs (
    project_id TEXT NOT NULL REFERENCES projects(id),
    kind TEXT NOT NULL,
    record_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending','done','failed')),
    attempts INTEGER NOT NULL DEFAULT 0,
    error TEXT NOT NULL DEFAULT '',
    next_retry_us INTEGER NOT NULL DEFAULT 0,
    created_us INTEGER NOT NULL,
    PRIMARY KEY (project_id, kind, record_id, revision)
) STRICT, WITHOUT ROWID;

CREATE INDEX embedding_jobs_ready ON embedding_jobs(state, next_retry_us, created_us);
CREATE INDEX vectors_scoped ON chunk_vectors(project_id, model, kind, record_id);

CREATE TABLE search_generations (
    project_id TEXT PRIMARY KEY REFERENCES projects(id),
    generation INTEGER NOT NULL
) STRICT;

-- Existing M3 records become keyword-searchable immediately; the worker fills vectors.
INSERT INTO search_fts(project_id, kind, record_id, revision, text)
SELECT project_id, 'memory', id, 1, body FROM memory_records
WHERE revoked = 0 AND superseded_by IS NULL;
INSERT INTO embedding_jobs(project_id, kind, record_id, revision, state, created_us)
SELECT project_id, 'memory', id, 1, 'pending', created_us FROM memory_records
WHERE revoked = 0 AND superseded_by IS NULL;
INSERT INTO search_generations(project_id, generation)
SELECT id, 1 FROM projects;
