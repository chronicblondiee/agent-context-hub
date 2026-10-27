-- Identities are global; grants tie them to projects. Admin actions audit into the reserved
-- "_system" project, which the project-ID rule (no leading underscore) keeps ungrantable.
INSERT INTO projects VALUES ('_system', 'service administration', 0);

CREATE TABLE principals (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('human', 'agent', 'verifier', 'connector')),
    service_admin INTEGER NOT NULL DEFAULT 0 CHECK (service_admin IN (0, 1)),
    created_us INTEGER NOT NULL
) STRICT;

-- Roles are additive: a principal holds one row per role it has in a project.
CREATE TABLE grants (
    principal_id TEXT NOT NULL REFERENCES principals(id),
    project_id TEXT NOT NULL REFERENCES projects(id) CHECK (project_id <> '_system'),
    role TEXT NOT NULL
        CHECK (role IN ('reader', 'contributor', 'maintainer', 'verifier', 'connector')),
    created_us INTEGER NOT NULL,
    PRIMARY KEY (principal_id, project_id, role)
) STRICT, WITHOUT ROWID;

-- Only the SHA-256 digest of each 32-byte secret is stored; the secret is shown once.
CREATE TABLE keys (
    id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL REFERENCES principals(id),
    digest TEXT NOT NULL,
    created_us INTEGER NOT NULL,
    expires_us INTEGER NOT NULL,
    revoked_us INTEGER,
    last_used_us INTEGER
) STRICT;

CREATE INDEX keys_principal ON keys (principal_id);
