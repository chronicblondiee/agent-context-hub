"""Derived search indexes and crash-safe embedding jobs."""

import struct

from hub.embed import MODEL, MODEL_KEY
from hub.store import now_us


def generation(tx):
    tx.execute(
        "INSERT INTO search_generations VALUES (?, 1) ON CONFLICT(project_id) "
        "DO UPDATE SET generation = generation + 1",
        [tx.project_id],
    )


def index(tx, kind, record_id, revision, value):
    tx.execute(
        "DELETE FROM search_fts WHERE project_id = ? AND kind = ? AND record_id = ?",
        [tx.project_id, kind, record_id],
    )
    tx.execute(
        "INSERT INTO search_fts(project_id, kind, record_id, revision, text) "
        "VALUES (?, ?, ?, ?, ?)",
        [tx.project_id, kind, record_id, revision, value],
    )
    tx.execute(
        "INSERT INTO embedding_jobs(project_id, kind, record_id, revision, state, created_us) "
        "VALUES (?, ?, ?, ?, 'pending', ?) ON CONFLICT(project_id, kind, record_id, revision) "
        "DO UPDATE SET state = 'pending', attempts = 0, error = '', next_retry_us = 0",
        [tx.project_id, kind, record_id, revision, now_us()],
    )
    generation(tx)


def deindex(tx, kind, record_id):
    args = [tx.project_id, kind, record_id]
    tx.execute("DELETE FROM search_fts WHERE project_id = ? AND kind = ? AND record_id = ?", args)
    tx.execute(
        "DELETE FROM chunk_vectors WHERE project_id = ? AND kind = ? AND record_id = ?", args
    )
    tx.execute(
        "DELETE FROM embedding_jobs WHERE project_id = ? AND kind = ? AND record_id = ?", args
    )
    generation(tx)


def pending_job(con):
    row = con.execute(
        "SELECT project_id, kind, record_id, revision FROM embedding_jobs "
        "WHERE state = 'pending' AND next_retry_us <= ? "
        "ORDER BY created_us, project_id, kind, record_id LIMIT 1",
        [now_us()],
    ).fetchone()
    return dict(row) if row else None


def current_text(db, job):
    p, kind, ident, revision = (
        job["project_id"],
        job["kind"],
        job["record_id"],
        job["revision"],
    )
    if kind == "memory" and revision == 1:
        row = db.execute(
            "SELECT body FROM memory_records WHERE project_id = ? AND id = ? "
            "AND revoked = 0 AND superseded_by IS NULL",
            [p, ident],
        ).fetchone()
    elif kind == "attempt" and revision == 1:
        row = db.execute(
            "SELECT approach || ' ' || outcome FROM attempts WHERE project_id = ? AND id = ?",
            [p, ident],
        ).fetchone()
    elif kind == "solution":
        row = db.execute(
            "SELECT r.body FROM solution_revisions r JOIN solutions s "
            "ON s.project_id = r.project_id AND s.id = r.solution_id "
            "WHERE r.project_id = ? AND r.solution_id = ? AND r.revision = ? "
            "AND s.current_revision = r.revision AND s.status NOT IN ('revoked','superseded')",
            [p, ident, revision],
        ).fetchone()
    else:
        return None
    return row[0] if row else None


def finish_job(store, job, vectors):
    p, kind, ident, revision = (
        job["project_id"],
        job["kind"],
        job["record_id"],
        job["revision"],
    )

    def write(tx):
        row = tx.execute(
            "SELECT state FROM embedding_jobs WHERE project_id=? AND kind=? "
            "AND record_id=? AND revision=?",
            [p, kind, ident, revision],
        ).fetchone()
        if not row or row[0] != "pending":
            return {"stored": False}
        current = current_text(tx, job) is not None
        if current:
            tx.execute(
                "DELETE FROM chunk_vectors WHERE project_id=? AND kind=? AND record_id=? "
                "AND revision=? AND model=?",
                [p, kind, ident, revision, MODEL_KEY],
            )
            for chunk, vector in enumerate(vectors):
                tx.execute(
                    "INSERT INTO chunk_vectors VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    [
                        p,
                        kind,
                        ident,
                        revision,
                        chunk,
                        MODEL_KEY,
                        MODEL["dim"],
                        struct.pack(f"<{MODEL['dim']}f", *vector),
                    ],
                )
            if vectors:
                generation(tx)
        tx.execute(
            "UPDATE embedding_jobs SET state='done' WHERE project_id=? AND kind=? "
            "AND record_id=? AND revision=?",
            [p, kind, ident, revision],
        )
        tx.audit("index.complete", ident, {"kind": kind, "revision": revision, "stored": current})
        return {"stored": current}

    return store.mutate(p, "_embed_worker", write)


def fail_job(store, job, current_us, maximum):
    p, kind, ident, revision = (job["project_id"], job["kind"], job["record_id"], job["revision"])

    def write(tx):
        row = tx.execute(
            "SELECT attempts FROM embedding_jobs WHERE project_id=? AND kind=? "
            "AND record_id=? AND revision=? AND state='pending'",
            [p, kind, ident, revision],
        ).fetchone()
        if not row:
            return {"failed": False}
        attempts = row[0] + 1
        state = "failed" if attempts >= maximum else "pending"
        next_retry = current_us + min(60, 2**attempts) * 1_000_000
        tx.execute(
            "UPDATE embedding_jobs SET state=?, attempts=?, error='inference failed', "
            "next_retry_us=? WHERE project_id=? AND kind=? AND record_id=? AND revision=?",
            [state, attempts, next_retry, p, kind, ident, revision],
        )
        tx.audit("index.fail", ident, {"kind": kind, "revision": revision, "attempts": attempts})
        return {"failed": state == "failed"}

    return store.mutate(p, "_embed_worker", write)
