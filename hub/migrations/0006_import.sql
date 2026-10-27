-- AIC import manifest (M5). A database with a row here that is not 'active' holds a partial
-- import: the core refuses to serve it, and only an import of the same source may resume it.
CREATE TABLE import_manifest (
    source_sha256 TEXT PRIMARY KEY CHECK (length(source_sha256) = 64),
    source_schema INTEGER NOT NULL,
    duckdb_version TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('importing', 'verified', 'active')),
    created_us INTEGER NOT NULL
) STRICT;
