-- Local agent messages. Acknowledgement is explicit and never resolves a disagreement.
CREATE TABLE messages (
    project_id TEXT NOT NULL REFERENCES projects(id),
    id TEXT NOT NULL,
    task_id TEXT,
    sender TEXT NOT NULL,
    recipient TEXT NOT NULL,
    message_type TEXT NOT NULL,
    content TEXT NOT NULL CHECK (json_valid(content)),
    evidence TEXT NOT NULL CHECK (json_valid(evidence)),
    in_reply_to TEXT,
    acknowledged INTEGER NOT NULL DEFAULT 0 CHECK (acknowledged IN (0, 1)),
    created_us INTEGER NOT NULL,
    PRIMARY KEY (project_id, id)
) STRICT, WITHOUT ROWID;

CREATE INDEX messages_inbox ON messages (project_id, recipient, acknowledged, created_us);
