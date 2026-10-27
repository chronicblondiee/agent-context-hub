-- Source identity of every imported AIC row (M5): its table and ID, the hub row it became, and
-- any source columns the hub schema has no place for. Imported IDs are kept within the project.
CREATE TABLE import_aliases (
    project_id TEXT NOT NULL REFERENCES projects(id),
    source_table TEXT NOT NULL,
    source_id TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    target_id TEXT NOT NULL,
    detail TEXT NOT NULL CHECK (json_valid(detail)),
    source_sha256 TEXT NOT NULL REFERENCES import_manifest(source_sha256),
    PRIMARY KEY (project_id, source_table, source_id)
) STRICT, WITHOUT ROWID;
