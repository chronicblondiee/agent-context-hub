"""Optional hub peer outbox, deduplicated inbox and application receipts."""

import hashlib
import json
import math
import uuid

from hub import identity, index
from hub.memory import owner_of
from hub.store import Conflict, encoded, now_us


def peer(store, actor, project, remote, transport):
    identity._ident(project, "project")
    identity._ident(remote, "remote project")
    identity._ident(transport, "transport")
    if project == remote:
        raise ValueError("a project cannot peer with itself")

    def job(tx):
        principal = tx.execute("SELECT kind FROM principals WHERE id=?", [transport]).fetchone()
        grant = tx.execute(
            "SELECT 1 FROM grants WHERE principal_id=? AND project_id=? AND role='connector'",
            [transport, project],
        ).fetchone()
        if not principal or principal[0] != "connector" or not grant:
            raise ValueError("peer transport requires a connector principal and project grant")
        tx.execute("INSERT INTO federation_peers VALUES (?,?,?,1)", [project, remote, transport])
        tx.audit("federation.peer", remote, {"transport": transport})
        return {"project": project, "remote": remote, "transport": transport}

    return store.mutate(project, actor, job)


def _row(tx, record_id):
    return tx.execute(
        "SELECT * FROM memory_records WHERE project_id=? AND id=?",
        [tx.project_id, record_id],
    ).fetchone()


def _snapshot(row):
    return {
        "id": row["id"],
        "namespace": row["namespace"],
        "kind": row["kind"],
        "body": row["body"],
        "hook": row["hook"],
        "provenance": row["provenance"],
        "confidence": row["confidence"],
        "author": row["author"],
        "evidence": json.loads(row["evidence"]),
        "visibility": row["visibility"],
        "revoked": bool(row["revoked"]),
        "superseded_by": row["superseded_by"],
    }


def _enqueue(tx, remote, row, revision):
    payload = {
        "id": str(uuid.uuid4()),
        "origin_project": tx.project_id,
        "destination_project": remote,
        "kind": "memory",
        "revision": revision,
        "record": _snapshot(row),
    }
    digest = hashlib.sha256(encoded(payload).encode()).hexdigest()
    pending = tx.execute(
        "SELECT coalesce(sum(length(payload)),0) FROM federation_outbox "
        "WHERE project_id=? AND applied=0",
        [tx.project_id],
    ).fetchone()[0]
    if pending + len(encoded(payload).encode()) > 16 * 1024 * 1024:
        raise ValueError("federation outbox full")
    tx.execute(
        "INSERT INTO federation_outbox VALUES (?,?,?,?,?,0,?)",
        [tx.project_id, payload["id"], remote, encoded(payload), digest, now_us()],
    )
    return payload["id"]


def share(store, project, actor, record_id, remote, idempotency_key):
    if not idempotency_key:
        raise ValueError("Idempotency-Key required")

    def job(tx):
        peer_row = tx.execute(
            "SELECT enabled FROM federation_peers WHERE project_id=? AND remote_project=?",
            [project, remote],
        ).fetchone()
        if not peer_row or not peer_row[0]:
            raise ValueError("peer is not configured")
        row = _row(tx, record_id)
        owned = row and row["owner"] == owner_of(tx, project, actor)
        if not owned or row["visibility"] != "project":
            raise ValueError("owned project record required")
        if row["revoked"] or row["superseded_by"]:
            raise ValueError("only an active record may be shared")
        if tx.execute(
            "SELECT 1 FROM source_rows WHERE project_id=? AND record_id=? UNION ALL "
            "SELECT 1 FROM federation_records WHERE project_id=? AND record_id=? UNION ALL "
            "SELECT 1 FROM import_aliases WHERE project_id=? AND source_table='memory_records' "
            "AND target_id=?",
            [project, record_id, project, record_id, project, record_id],
        ).fetchone():
            raise ValueError("imported or received records cannot be forwarded")
        existing = tx.execute(
            "SELECT 1 FROM federation_shares "
            "WHERE project_id=? AND record_id=? AND remote_project=?",
            [project, record_id, remote],
        ).fetchone()
        if existing:
            raise Conflict("record already shared with peer")
        tx.execute("INSERT INTO federation_shares VALUES (?,?,?,1)", [project, record_id, remote])
        event_id = _enqueue(tx, remote, row, 1)
        tx.audit("federation.share", record_id, {"remote": remote, "event": event_id})
        return {"id": event_id, "remote": remote}

    return store.mutate(
        project,
        actor,
        job,
        idempotency_key,
        {"record_id": record_id, "remote": remote},
    )


def changed(tx, record_id):
    """Queue a new state for each explicit share, in the same memory transaction."""
    row = _row(tx, record_id)
    if not row:
        return
    for remote, revision in tx.execute(
        "SELECT remote_project,revision FROM federation_shares WHERE project_id=? AND record_id=?",
        [tx.project_id, record_id],
    ).fetchall():
        next_revision = revision + 1
        tx.execute(
            "UPDATE federation_shares SET revision=? WHERE project_id=? "
            "AND record_id=? AND remote_project=?",
            [next_revision, tx.project_id, record_id, remote],
        )
        _enqueue(tx, remote, row, next_revision)


def successor(tx, old_id, new_id):
    """Continue an explicit share through a new local revision."""
    peers = tx.execute(
        "SELECT remote_project FROM federation_shares WHERE project_id=? AND record_id=?",
        [tx.project_id, old_id],
    ).fetchall()
    for (remote,) in peers:
        tx.execute(
            "INSERT OR IGNORE INTO federation_shares VALUES (?,?,?,1)",
            [tx.project_id, new_id, remote],
        )
        _enqueue(tx, remote, _row(tx, new_id), 1)
    changed(tx, old_id)


def outbox(store, project, transport):
    return store.read(
        lambda db: [
            {"remote": row[0], "event": json.loads(row[1])}
            for row in db.execute(
                "SELECT o.remote_project,o.payload FROM federation_outbox o "
                "JOIN federation_peers p ON p.project_id=o.project_id "
                "AND p.remote_project=o.remote_project "
                "WHERE o.project_id=? AND o.applied=0 AND p.enabled=1 "
                "AND p.transport_id=? ORDER BY o.created_us LIMIT 100",
                [project, transport],
            )
        ]
    )


def _incoming_record_id(origin, ident):
    digest = hashlib.sha256(f"{origin}\0{ident}".encode()).hexdigest()
    return "peer-" + digest[:32]


def incoming(store, project, origin, actor, event):
    if not isinstance(event, dict) or set(event) != {
        "id",
        "origin_project",
        "destination_project",
        "kind",
        "revision",
        "record",
    }:
        raise ValueError("invalid peer event")
    if event["origin_project"] != origin or event["destination_project"] != project:
        raise ValueError("peer project mismatch")
    if event["kind"] != "memory" or not isinstance(event["record"], dict):
        raise ValueError("unsupported peer event")
    if type(event["revision"]) is not int or event["revision"] < 1:
        raise ValueError("invalid peer revision")
    record = event["record"]
    required = {
        "id",
        "namespace",
        "kind",
        "body",
        "hook",
        "provenance",
        "confidence",
        "author",
        "evidence",
        "visibility",
        "revoked",
        "superseded_by",
    }
    if not required <= record.keys() or record["visibility"] != "project":
        raise ValueError("private or incomplete peer record")
    if not isinstance(event["id"], str) or not 0 < len(event["id"]) <= 256:
        raise ValueError("peer event ID required")
    ident = record["id"]
    if not isinstance(ident, str) or not ident or len(ident) > 256 or ":" in ident:
        raise ValueError("invalid peer record ID")
    if not all(
        isinstance(record[k], str) and record[k] for k in ("namespace", "kind", "body", "author")
    ):
        raise ValueError("invalid peer memory")
    if record["provenance"] not in ("stated", "tested", "assumed", "inferred"):
        raise ValueError("invalid peer provenance")
    confidence = record["confidence"]
    if (
        not isinstance(confidence, (int, float))
        or not math.isfinite(confidence)
        or not 0 <= confidence <= 1
    ):
        raise ValueError("invalid peer confidence")
    evidence = record["evidence"]
    if (
        not isinstance(evidence, list)
        or not evidence
        or not all(isinstance(e, str) and e for e in evidence)
    ):
        raise ValueError("invalid peer evidence")
    superseded = record["superseded_by"]
    if (
        type(record["revoked"]) is not bool
        or superseded is not None
        and not isinstance(superseded, str)
    ):
        raise ValueError("invalid peer revocation or supersession")
    digest = hashlib.sha256(encoded(event).encode()).hexdigest()
    record_digest = hashlib.sha256(encoded(record).encode()).hexdigest()

    def job(tx):
        configured = tx.execute(
            "SELECT enabled,transport_id FROM federation_peers "
            "WHERE project_id=? AND remote_project=?",
            [project, origin],
        ).fetchone()
        if not configured or not configured[0] or configured[1] != actor:
            raise ValueError("unconfigured peer")
        prior = tx.execute(
            "SELECT digest FROM federation_inbox WHERE project_id=? AND origin_project=? AND id=?",
            [project, origin, event["id"]],
        ).fetchone()
        if prior:
            if prior[0] != digest:
                raise Conflict("peer event ID reused with changed payload")
            return {"applied": event["id"], "duplicate": True}
        ident = _incoming_record_id(origin, record["id"])
        exists = tx.execute(
            "SELECT revision,digest FROM federation_records "
            "WHERE project_id=? AND origin_project=? "
            "AND origin_record=?",
            [project, origin, record["id"]],
        ).fetchone()
        stale = exists and event["revision"] < exists[0]
        if exists and event["revision"] == exists[0] and record_digest != exists[1]:
            raise Conflict("peer revision reused with changed payload")
        if stale or exists and event["revision"] == exists[0]:
            tx.execute(
                "INSERT INTO federation_inbox VALUES (?,?,?,?,?)",
                [project, origin, event["id"], digest, now_us()],
            )
            tx.audit("federation.stale", ident, {"origin": origin, "event": event["id"]})
            return {"applied": event["id"], "duplicate": False}
        if not exists:
            tx.execute(
                "INSERT INTO federation_records VALUES (?,?,?,?,?,?,?)",
                [
                    project,
                    origin,
                    record["id"],
                    ident,
                    record["superseded_by"],
                    event["revision"],
                    record_digest,
                ],
            )
        else:
            tx.execute(
                "UPDATE federation_records SET superseded_by=?,revision=?,digest=? "
                "WHERE project_id=? "
                "AND origin_project=? AND origin_record=?",
                [
                    record["superseded_by"],
                    event["revision"],
                    record_digest,
                    project,
                    origin,
                    record["id"],
                ],
            )
        values = [
            project,
            ident,
            None,
            record["namespace"],
            record["kind"],
            record["body"],
            record["hook"] or record["body"][:120],
            record["provenance"],
            record["confidence"],
            origin + ":" + record["author"],
            encoded(record["evidence"]),
            "project",
            int(bool(record["revoked"])),
            None,
            now_us(),
            origin + ":" + record["author"],  # a replica: only its origin may change it
        ]
        tx.execute(
            "INSERT INTO memory_records (project_id, id, task_id, namespace, kind, body, hook, "
            "provenance, confidence, author, evidence, visibility, revoked, superseded_by, "
            "created_us, owner) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(project_id,id) DO UPDATE SET body=excluded.body,hook=excluded.hook,"
            "revoked=excluded.revoked,evidence=excluded.evidence",
            values,
        )
        if record["revoked"] or record["superseded_by"]:
            index.deindex(tx, "memory", ident)
        else:
            index.index(tx, "memory", ident, 1, record["body"])
        for old, successor in tx.execute(
            "SELECT record_id,superseded_by FROM federation_records WHERE project_id=? "
            "AND origin_project=? AND superseded_by IS NOT NULL",
            [project, origin],
        ).fetchall():
            new = tx.execute(
                "SELECT record_id FROM federation_records WHERE project_id=? "
                "AND origin_project=? AND origin_record=?",
                [project, origin, successor],
            ).fetchone()
            if new:
                tx.execute(
                    "UPDATE memory_records SET superseded_by=? WHERE project_id=? AND id=?",
                    [new[0], project, old],
                )
        tx.execute(
            "INSERT INTO federation_inbox VALUES (?,?,?,?,?)",
            [project, origin, event["id"], digest, now_us()],
        )
        tx.audit("federation.apply", ident, {"origin": origin, "event": event["id"]})
        tx.change("federation.apply", ident, {"origin": origin})
        return {"applied": event["id"], "duplicate": False}

    return store.mutate(project, actor, job)


def receipt(store, project, origin, actor, event_id):
    def job(tx):
        row = tx.execute(
            "SELECT o.applied FROM federation_outbox o JOIN federation_peers p "
            "ON p.project_id=o.project_id AND p.remote_project=o.remote_project "
            "WHERE o.project_id=? AND o.remote_project=? AND o.id=? AND p.transport_id=?",
            [project, origin, event_id, actor],
        ).fetchone()
        if not row:
            raise ValueError("unknown delivery receipt")
        if not row[0]:
            tx.execute(
                "UPDATE federation_outbox SET applied=1 WHERE project_id=? AND id=?",
                [project, event_id],
            )
            tx.audit("federation.receipt", event_id, {"remote": origin})
        return {"applied": event_id}

    return store.mutate(project, actor, job)
