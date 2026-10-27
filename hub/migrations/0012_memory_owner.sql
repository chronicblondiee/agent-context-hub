-- Memory belongs to the human an agent acts for; the agent principal and its client session
-- are attribution only. Existing records stay owned by their author until that agent is bound.
ALTER TABLE principals ADD COLUMN acts_for TEXT REFERENCES principals(id);

ALTER TABLE memory_records ADD COLUMN owner TEXT NOT NULL DEFAULT '';
ALTER TABLE memory_records ADD COLUMN agent_session TEXT;
UPDATE memory_records SET owner = author;

CREATE INDEX memory_owner ON memory_records (project_id, owner, created_us);
