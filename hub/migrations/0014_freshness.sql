-- Temporal assessment is independent of immutable content and solution trust.
CREATE TABLE memory_freshness (
 project_id TEXT NOT NULL,
 memory_id TEXT NOT NULL,
 revision INTEGER NOT NULL DEFAULT 1,
 temporal_kind TEXT NOT NULL DEFAULT 'unclassified'
  CHECK(temporal_kind IN ('unclassified','durable','changing','historical')),
 observed_us INTEGER,
 checked_us INTEGER,
 review_due_us INTEGER,
 reminder_us INTEGER,
 claim_key TEXT,
 owner TEXT NOT NULL,
 namespace TEXT NOT NULL,
 visibility TEXT NOT NULL,
 active INTEGER NOT NULL DEFAULT 1,
 review_reason TEXT,
 review_evidence TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(review_evidence)),
 proposed_correction TEXT,
 PRIMARY KEY(project_id,memory_id),
 FOREIGN KEY(project_id,memory_id) REFERENCES memory_records(project_id,id),
 CHECK(temporal_kind <> 'changing' OR (review_due_us IS NOT NULL AND claim_key IS NOT NULL))
) STRICT, WITHOUT ROWID;
INSERT INTO memory_freshness(project_id,memory_id,owner,namespace,visibility,active)
 SELECT project_id,id,owner,namespace,visibility,NOT revoked AND superseded_by IS NULL
 FROM memory_records;
CREATE UNIQUE INDEX active_claim ON memory_freshness(project_id,owner,namespace,visibility,claim_key)
 WHERE active=1 AND claim_key IS NOT NULL;

CREATE TABLE memory_source_checks (
 project_id TEXT NOT NULL,
 id TEXT NOT NULL,
 memory_id TEXT NOT NULL,
 source TEXT NOT NULL CHECK(json_valid(source)),
 baseline TEXT,
 observed_fingerprint TEXT,
 checked_us INTEGER,
 state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','claimed','failed','stopped')),
 due_us INTEGER NOT NULL,
 generation INTEGER NOT NULL DEFAULT 0,
 lease_until_us INTEGER,
 claimant TEXT,
 target_revision INTEGER,
 attempts INTEGER NOT NULL DEFAULT 0,
 failure TEXT,
 PRIMARY KEY(project_id,id),
 UNIQUE(project_id,memory_id,source),
 FOREIGN KEY(project_id,memory_id) REFERENCES memory_records(project_id,id)
) STRICT, WITHOUT ROWID;
CREATE INDEX due_source_checks ON memory_source_checks(project_id,state,due_us);
CREATE TABLE memory_review_previews (
 project_id TEXT NOT NULL,
 token TEXT NOT NULL,
 actor TEXT NOT NULL,
 request TEXT NOT NULL,
 expires_us INTEGER NOT NULL,
 PRIMARY KEY(project_id,token)
) STRICT, WITHOUT ROWID;
CREATE TABLE source_check_results (
 project_id TEXT NOT NULL,
 job_id TEXT NOT NULL,
 generation INTEGER NOT NULL,
 actor TEXT NOT NULL,
 request TEXT NOT NULL,
 result TEXT NOT NULL,
 PRIMARY KEY(project_id,job_id,generation),
 FOREIGN KEY(project_id,job_id) REFERENCES memory_source_checks(project_id,id)
) STRICT, WITHOUT ROWID;
-- All insertion paths (including federation and library publication) start unassessed.
CREATE TRIGGER memory_freshness_insert AFTER INSERT ON memory_records BEGIN
 INSERT INTO memory_freshness(project_id,memory_id,owner,namespace,visibility,active)
 VALUES(NEW.project_id,NEW.id,NEW.owner,NEW.namespace,NEW.visibility,
        NOT NEW.revoked AND NEW.superseded_by IS NULL);
END;
CREATE TRIGGER memory_freshness_inactive AFTER UPDATE OF revoked,superseded_by ON memory_records BEGIN
 UPDATE memory_freshness SET active=NOT NEW.revoked AND NEW.superseded_by IS NULL
 WHERE project_id=NEW.project_id AND memory_id=NEW.id;
END;
