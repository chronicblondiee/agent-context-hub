"""Project incident history, separate from private work; fenced resource coordination."""

import json
import unicodedata

from hub.common import NotFound, Stale, bounded, references, uid
from hub.store import encoded, now_us

KINDS = {"finding", "hypothesis", "attempt", "checkpoint", "decision", "evidence"}


class Troubleshooting:
    def _thread(self, db, thread_id, require_open=False):
        row = db.execute(
            "SELECT * FROM troubleshooting_threads WHERE project_id=? AND id=?",
            [self.project, thread_id],
        ).fetchone()
        if not row:
            raise NotFound("unknown thread")
        if require_open and row["status"] != "open":
            raise ValueError("thread is resolved")
        return dict(row)

    def _event(self, tx, actor, thread_id, kind, body, evidence, corrects=None):
        bounded(body, "event", 4096)
        bounded(evidence, "evidence", 4096)
        if not references(evidence):
            raise ValueError("evidence must be references")
        if (
            corrects is not None
            and not tx.execute(
                "SELECT 1 FROM troubleshooting_events WHERE project_id=? AND thread_id=? AND seq=?",
                [self.project, thread_id, corrects],
            ).fetchone()
        ):
            raise ValueError("correction must reference this thread")
        tx.execute(
            "INSERT INTO troubleshooting_participants VALUES (?,?,?) ON CONFLICT DO NOTHING",
            [self.project, thread_id, actor],
        )
        seq = tx.execute(
            "SELECT coalesce(max(seq),0)+1 FROM troubleshooting_events WHERE project_id=?",
            [self.project],
        ).fetchone()[0]
        tx.execute(
            "INSERT INTO troubleshooting_events "
            "(project_id,seq,thread_id,actor,kind,body,evidence,corrects,created_us) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            [
                self.project,
                seq,
                thread_id,
                actor,
                kind,
                encoded(body),
                encoded(evidence),
                corrects,
                now_us(),
            ],
        )
        tx.audit("tshoot." + kind, thread_id, {"seq": seq})
        return {"seq": seq, "thread_id": thread_id}

    def tshoot_open(self, actor, target):
        if not isinstance(target, str):
            raise ValueError("target required")
        target = " ".join(unicodedata.normalize("NFKC", target).casefold().split())
        bounded(target, "target", 512)
        if not target:
            raise ValueError("target required")

        def job(tx):
            rows = tx.execute(
                "SELECT * FROM troubleshooting_threads WHERE project_id=? AND target=? "
                "ORDER BY created_us DESC",
                [self.project, target],
            ).fetchall()
            current = next((dict(r) for r in rows if r["status"] == "open"), None)
            if not current:
                current = dict(
                    project_id=self.project,
                    id=uid(),
                    target=target,
                    status="open",
                    predecessor=rows[0]["id"] if rows else None,
                    created_us=now_us(),
                )
                tx.execute(
                    "INSERT INTO troubleshooting_threads VALUES (?,?,?,?,?,?)",
                    list(current.values()),
                )
            self._event(tx, actor, current["id"], "join", "", [])
            return current

        return self._mutate(actor, job)

    def tshoot_list(self, actor, cursor=0, limit=40):
        if type(cursor) is not int or cursor < 0 or type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("invalid pagination")
        return self.store.read(
            lambda db: [
                dict(r)
                for r in db.execute(
                    "SELECT * FROM troubleshooting_threads WHERE project_id=? "
                    "ORDER BY created_us,id LIMIT ? OFFSET ?",
                    [self.project, limit, cursor],
                )
            ]
        )

    def tshoot_read(self, actor, thread_id, cursor=0, limit=40, tail=False):
        if type(cursor) is not int or cursor < 0 or type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("invalid pagination")

        def read(db):
            thread = self._thread(db, thread_id)
            events = [
                dict(r)
                for r in db.execute(
                    "SELECT * FROM troubleshooting_events WHERE project_id=? AND thread_id=? "
                    "AND seq>? ORDER BY seq " + ("DESC" if tail else "ASC") + " LIMIT ?",
                    [self.project, thread_id, cursor, limit],
                )
            ]
            if tail:
                events.reverse()
            for event in events:
                event["body"], event["evidence"] = (
                    json.loads(event["body"]),
                    json.loads(event["evidence"]),
                )
            actions = []
            for r in db.execute(
                "SELECT * FROM troubleshooting_actions WHERE project_id=? AND thread_id=?",
                [self.project, thread_id],
            ):
                a = dict(r)
                # Do not expose task or session identifiers to other investigators.
                for key in ("task_id", "session_id", "generation"):
                    a.pop(key)
                if a["status"] == "started" and a["expires_us"] <= now_us():
                    a["status"] = "outcome-unknown"
                actions.append(a)
            checkpoint = db.execute(
                "SELECT * FROM troubleshooting_events WHERE project_id=? AND thread_id=? "
                "AND kind='checkpoint' ORDER BY seq DESC LIMIT 1",
                [self.project, thread_id],
            ).fetchone()
            checkpoint = dict(checkpoint) if checkpoint else None
            if checkpoint:
                checkpoint["body"] = json.loads(checkpoint["body"])
                checkpoint["evidence"] = json.loads(checkpoint["evidence"])
            return dict(
                checkpoint=checkpoint,
                thread=thread,
                events=events,
                actions=actions,
                cursor=events[-1]["seq"] if events else cursor,
                participants=[
                    r[0]
                    for r in db.execute(
                        "SELECT actor FROM troubleshooting_participants "
                        "WHERE project_id=? AND thread_id=? ORDER BY actor",
                        [self.project, thread_id],
                    )
                ],
            )

        return self.store.read(read)

    def tshoot_append(self, actor, thread_id, kind, body, evidence, corrects=None):
        if kind not in KINDS:
            raise ValueError("invalid event kind")

        def job(tx):
            self._thread(tx, thread_id, True)
            return self._event(tx, actor, thread_id, kind, body, evidence, corrects)

        return self._mutate(actor, job)

    def tshoot_close(self, actor, thread_id, summary, evidence):
        if not summary or not evidence or not references(evidence):
            raise ValueError("resolution requires summary and evidence")

        def job(tx):
            self._thread(tx, thread_id, True)
            self._expire_reservations(tx, actor)
            if tx.execute(
                "SELECT 1 FROM troubleshooting_actions WHERE project_id=? AND thread_id=? "
                "AND status IN ('reserved','started','outcome-unknown')",
                [self.project, thread_id],
            ).fetchone():
                raise ValueError("unfinished or uncertain actions require reconciliation")
            event = self._event(tx, actor, thread_id, "resolution", summary, evidence)
            tx.execute(
                "UPDATE troubleshooting_threads SET status='resolved' WHERE project_id=? AND id=?",
                [self.project, thread_id],
            )
            return event

        return self._mutate(actor, job)

    def _expire_reservations(self, tx, actor):
        # Started effects never release on expiry, even if the private action is resolved.
        rows = tx.execute(
            "SELECT id,thread_id,resource FROM troubleshooting_actions WHERE project_id=? "
            "AND status='reserved' AND expires_us<=?",
            [self.project, now_us()],
        ).fetchall()
        for row in rows:
            tx.execute(
                "UPDATE troubleshooting_actions SET status='released' WHERE project_id=? AND id=?",
                [self.project, row["id"]],
            )
            self._event(
                tx,
                actor,
                row["thread_id"],
                "action.release",
                {
                    "id": row["id"],
                    "resource": row["resource"],
                    "reason": "unused reservation expired before start",
                },
                [],
            )

    def tshoot_action_reserve(self, actor, thread_id, resource, session_id, generation, intent):
        if not isinstance(resource, str) or resource != resource.strip() or not resource:
            raise ValueError("explicit canonical resource required")
        resource = unicodedata.normalize("NFKC", resource).casefold()
        if any(c.isspace() or ord(c) < 32 for c in resource):
            raise ValueError("resource must have no whitespace or control characters")
        bounded(resource, "resource", 512)
        bounded(intent, "intent")

        def job(tx):
            self._thread(tx, thread_id, True)
            s = self._lease(tx, actor, session_id, generation)
            self._expire_reservations(tx, actor)
            action = dict(id=uid(), task_id=s["task_id"], intent=intent, status="planned")
            self._put(tx, "action", action)
            tx.execute(
                "INSERT INTO troubleshooting_actions VALUES (?,?,?,?,?,?,?,?,?,?)",
                [
                    self.project,
                    action["id"],
                    thread_id,
                    resource,
                    actor,
                    s["task_id"],
                    session_id,
                    generation,
                    s["expires_us"],
                    "reserved",
                ],
            )
            self._event(
                tx, actor, thread_id, "reservation", {"id": action["id"], "resource": resource}, []
            )
            return {"id": action["id"], "status": "reserved"}

        return self._mutate(actor, job)

    def _tshoot_action(
        self, actor, action_id, session_id, generation, operation, status=None, evidence=None
    ):
        def job(tx):
            s = self._lease(tx, actor, session_id, generation)
            row = tx.execute(
                "SELECT * FROM troubleshooting_actions WHERE project_id=? AND id=?",
                [self.project, action_id],
            ).fetchone()
            if not row or row["actor"] != actor or row["task_id"] != s["task_id"]:
                raise ValueError("owned action and task required")
            a = self._object(tx, "action", action_id)
            if operation != "reconcile" and (
                row["session_id"] != session_id
                or row["generation"] != generation
                or row["expires_us"] <= now_us()
            ):
                raise Stale("reservation lease expired or fenced; reconcile explicitly")
            new = row["status"]
            if operation == "start":
                if new != "reserved" or a["status"] != "planned":
                    raise ValueError("action already started; never replay")
                new = a["status"] = "started"
            elif operation == "heartbeat":
                if new not in ("reserved", "started"):
                    raise ValueError("action is stopped")
                s["expires_us"] = now_us() + 60_000_000
                self._put(tx, "session", s)
            else:
                if new not in ("started", "outcome-unknown") or status not in (
                    "completed",
                    "failed",
                    "outcome-unknown",
                ):
                    raise ValueError("invalid action outcome")
                if not evidence or not references(evidence):
                    raise ValueError("outcome requires evidence references")
                bounded(evidence, "evidence")
                new = a["status"] = status
                a["evidence"] = evidence
            self._put(tx, "action", a)
            tx.execute(
                "UPDATE troubleshooting_actions SET status=?, expires_us=? "
                "WHERE project_id=? AND id=?",
                [new, s["expires_us"], self.project, action_id],
            )
            self._event(
                tx,
                actor,
                row["thread_id"],
                "action." + operation,
                {"id": action_id, "resource": row["resource"], "status": new},
                evidence or [],
            )
            return {"id": action_id, "status": new}

        return self._mutate(actor, job)

    def tshoot_action_start(self, actor, action_id, session_id, generation):
        return self._tshoot_action(actor, action_id, session_id, generation, "start")

    def tshoot_action_heartbeat(self, actor, action_id, session_id, generation):
        return self._tshoot_action(actor, action_id, session_id, generation, "heartbeat")

    def tshoot_action_outcome(self, actor, action_id, session_id, generation, status, evidence):
        return self._tshoot_action(
            actor, action_id, session_id, generation, "outcome", status, evidence
        )

    def tshoot_action_reconcile(self, actor, action_id, session_id, generation, status, evidence):
        if status not in ("completed", "failed"):
            raise ValueError("reconciliation must resolve the effect")
        return self._tshoot_action(
            actor, action_id, session_id, generation, "reconcile", status, evidence
        )
