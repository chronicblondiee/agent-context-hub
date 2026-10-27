-- The one general troubleshooting library: a dedicated project an administrator designates.
-- A row rather than configuration, so backup and restore carry it with the data.
CREATE TABLE tshoot_library (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    project_id TEXT NOT NULL REFERENCES projects(id)
) STRICT;

-- Sanitized proposals from an originating project and their review. A published row links the
-- exact source revision to the library copy (dest); proposals themselves are never indexed.
CREATE TABLE publications (
    id TEXT PRIMARY KEY,
    source_project TEXT NOT NULL REFERENCES projects(id),
    source_kind TEXT NOT NULL CHECK (source_kind IN ('memory', 'solution')),
    source_id TEXT NOT NULL,
    source_revision INTEGER NOT NULL CHECK (source_revision > 0),
    library_project TEXT NOT NULL REFERENCES projects(id),
    dest_id TEXT,
    dest_revision INTEGER,
    body TEXT NOT NULL,
    hook TEXT NOT NULL,
    applicability TEXT NOT NULL CHECK (json_valid(applicability)),
    evidence TEXT NOT NULL CHECK (json_valid(evidence) AND json_array_length(evidence) > 0),
    seed_key TEXT,
    status TEXT NOT NULL CHECK (status IN ('proposed', 'published', 'rejected', 'withdrawn')),
    proposer TEXT NOT NULL,
    reviewer TEXT,
    reason TEXT,
    created_us INTEGER NOT NULL,
    decided_us INTEGER
) STRICT;

CREATE UNIQUE INDEX publication_dest ON publications(library_project, dest_id)
    WHERE dest_id IS NOT NULL;
CREATE INDEX publication_source ON publications(source_project, source_id, status);
CREATE INDEX publication_page ON publications(source_project, created_us, id);
CREATE INDEX publication_library_page ON publications(library_project, created_us, id);
-- A starter entry is proposed once; a withdrawn or rejected one is never recreated.
CREATE UNIQUE INDEX publication_seed ON publications(seed_key) WHERE seed_key IS NOT NULL;
