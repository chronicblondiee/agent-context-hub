-- Shared execution history; deliberately absent from FTS, vectors and memory export.
CREATE TABLE troubleshooting_threads (
    project_id TEXT NOT NULL REFERENCES projects(id),
    id TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('open','resolved')),
    predecessor TEXT,
    created_us INTEGER NOT NULL,
    PRIMARY KEY(project_id,id),
    FOREIGN KEY(project_id,predecessor) REFERENCES troubleshooting_threads(project_id,id)
) STRICT, WITHOUT ROWID;
CREATE UNIQUE INDEX troubleshooting_open_target ON troubleshooting_threads(project_id,target)
    WHERE status='open';
CREATE INDEX troubleshooting_target_history
    ON troubleshooting_threads(project_id,target,created_us DESC);
CREATE INDEX troubleshooting_thread_page ON troubleshooting_threads(project_id,created_us,id);

CREATE TABLE troubleshooting_participants (
    project_id TEXT NOT NULL,
    thread_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    PRIMARY KEY(project_id,thread_id,actor),
    FOREIGN KEY(project_id,thread_id) REFERENCES troubleshooting_threads(project_id,id)
) STRICT, WITHOUT ROWID;

CREATE TABLE troubleshooting_events (
    project_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    thread_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    kind TEXT NOT NULL,
    body TEXT NOT NULL CHECK(json_valid(body)),
    evidence TEXT NOT NULL CHECK(json_valid(evidence)),
    corrects INTEGER,
    created_us INTEGER NOT NULL,
    PRIMARY KEY(project_id,seq),
    FOREIGN KEY(project_id,thread_id) REFERENCES troubleshooting_threads(project_id,id),
    FOREIGN KEY(project_id,corrects) REFERENCES troubleshooting_events(project_id,seq)
) STRICT, WITHOUT ROWID;
CREATE INDEX troubleshooting_event_page ON troubleshooting_events(project_id,thread_id,seq);

CREATE TABLE troubleshooting_actions (
    project_id TEXT NOT NULL,
    id TEXT NOT NULL,
    thread_id TEXT NOT NULL,
    resource TEXT NOT NULL,
    actor TEXT NOT NULL,
    task_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation>0),
    expires_us INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN
        ('reserved','started','outcome-unknown','completed','failed','released')),
    PRIMARY KEY(project_id,id),
    FOREIGN KEY(project_id,thread_id) REFERENCES troubleshooting_threads(project_id,id)
) STRICT, WITHOUT ROWID;
CREATE UNIQUE INDEX troubleshooting_resource ON troubleshooting_actions(project_id,resource)
    WHERE status IN ('reserved','started','outcome-unknown');
CREATE INDEX troubleshooting_thread_actions ON troubleshooting_actions(project_id,thread_id);
