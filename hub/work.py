"""Durable work state ported from aic/durable.py: tasks, leases, checkpoints, actions, messages.

Every operation is scoped to one project; each mutation is one Store.mutate transaction.
"""

import json

from hub.common import Stale, bounded, references, uid
from hub.knowledge import Knowledge
from hub.memory import Memory
from hub.store import encoded, now_us
from hub.troubleshooting import Troubleshooting

TYPES = {"plan_update", "decision_request", "disagreement", "response", "memory_update", "stop"}
WORK_KINDS = ("task", "session", "session_history", "checkpoint", "action", "human_decision")
LEASE_US = 60_000_000
RETRY_LIMIT = 3
PACKET_BYTES = 8192


class Work(Troubleshooting, Knowledge, Memory):
    """One project's work and memory. Build one per request: an idempotency key covers the
    single mutation that request performs."""

    def __init__(self, store, project_id, idempotency_key=None, request=None, agent_session=None):
        self.store, self.project = store, project_id
        self.idempotency_key, self.request = idempotency_key, request
        self.agent_session = agent_session

    def context_get(self, actor, query, task_id=None, environment=None, limit=5, max_chars=8000):
        from hub.retrieval import context

        return context(self, actor, query, task_id, environment, limit, max_chars)

    def _mutate(self, actor, fn):
        return self.store.mutate(self.project, actor, fn, self.idempotency_key, self.request)

    # db is a Tx inside a mutation or a reader connection; both have execute().
    def _object(self, db, kind, ident):
        row = db.execute(
            "SELECT body FROM objects WHERE project_id = ? AND kind = ? AND id = ?",
            [self.project, kind, ident],
        ).fetchone()
        return json.loads(row[0]) if row else None

    def _objects(self, db, kind):
        rows = db.execute(
            "SELECT body FROM objects WHERE project_id = ? AND kind = ? ORDER BY id",
            [self.project, kind],
        )
        return [json.loads(r[0]) for r in rows]

    def _put(self, tx, kind, obj):
        tx.execute(
            "INSERT INTO objects VALUES (?, ?, ?, ?) "
            "ON CONFLICT (project_id, kind, id) DO UPDATE SET body = excluded.body",
            [self.project, kind, obj["id"], encoded(obj)],
        )
        tx.audit(kind, obj["id"], {"state": obj.get("status")})
        tx.change(kind, obj["id"], {"status": obj.get("status")})
        return obj

    def _task(self, db, ident):
        obj = self._object(db, "task", ident)
        if not obj:
            raise ValueError("unknown durable task")
        return obj

    @staticmethod
    def _owned(task, actor):
        if actor not in (task["owner"], task["agent"]):
            raise ValueError("task ownership required")

    @staticmethod
    def _runnable(task):
        if task["status"] not in ("open", "running"):
            raise ValueError("task is stopped: " + task.get("stop_reason", task["status"]))
        if task["turns"] >= task["turn_limit"] or now_us() >= task["deadline_us"]:
            raise ValueError("task budget exhausted")

    def _lease(self, db, actor, session_id, generation, allow_exhausted=False):
        s = self._object(db, "session", actor)
        if (
            not s
            or s["session_id"] != session_id
            or s["generation"] != generation
            or s["status"] != "active"
            or s["expires_us"] <= now_us()
        ):
            raise Stale("stale or expired session")
        if not allow_exhausted:
            self._runnable(self._task(db, s["task_id"]))
        return s

    def _inbox(self, db, recipient):
        rows = db.execute(
            "SELECT id, sender, message_type, content, evidence, in_reply_to FROM messages "
            "WHERE project_id = ? AND recipient = ? AND NOT acknowledged ORDER BY created_us, id",
            [self.project, recipient],
        )
        return [
            dict(
                id=r[0],
                sender=r[1],
                message_type=r[2],
                content=json.loads(r[3]),
                evidence=json.loads(r[4]),
                in_reply_to=r[5],
            )
            for r in rows
        ]

    def _disagreement_ids(self, db, task_id, recipient):
        rows = db.execute(
            "SELECT id FROM messages WHERE project_id = ? AND task_id = ? AND recipient = ? "
            "AND message_type = 'disagreement' ORDER BY created_us, id",
            [self.project, task_id, recipient],
        )
        return [r[0] for r in rows]

    def _disagreements(self, db, actor, task_id):
        task = self._task(db, task_id)
        if actor not in (task["owner"], task["agent"]):
            return []
        rows = db.execute(
            "SELECT id, sender, content, evidence FROM messages WHERE project_id = ? "
            "AND task_id = ? AND recipient = ? AND message_type = 'disagreement' "
            "ORDER BY created_us, id",
            [self.project, task_id, actor],
        )
        return [
            dict(
                id=r[0],
                sender=r[1],
                message_type="disagreement",
                content=json.loads(r[2]),
                evidence=json.loads(r[3]),
            )
            for r in rows
            if r[0] not in task.get("resolved_disagreements", [])
        ]

    def _visible(self, db, ident, actor):
        """Default deny: the project row, the actor's own work, messages and visible memory."""
        if ident == self.project:
            return True
        for kind in WORK_KINDS:
            obj = self._object(db, kind, ident)
            if obj:
                if kind in ("session", "session_history"):
                    return obj["agent"] == actor
                task = obj if kind == "task" else self._task(db, obj["task_id"])
                return actor in (task["owner"], task["agent"])
        row = db.execute(
            "SELECT sender, recipient FROM messages WHERE project_id = ? AND id = ?",
            [self.project, ident],
        ).fetchone()
        if row:
            return actor in tuple(row)
        record = self._memory_row(db, ident)
        if record:
            return self._memory_visible(record, self._owner(db, actor))
        if self._solution(db, ident):
            return True
        return bool(
            db.execute(
                "SELECT 1 FROM attempts WHERE project_id=? AND id=?", [self.project, ident]
            ).fetchone()
        )

    def _mine(self, db, actor, kind):
        rows = self._objects(db, kind)
        if kind in ("session", "session_history"):
            return [r for r in rows if r["agent"] == actor]
        tasks = {t["id"] for t in self._objects(db, "task") if actor in (t["owner"], t["agent"])}
        return [r for r in rows if (r["id"] if kind == "task" else r["task_id"]) in tasks]

    def _packet(self, db, actor, task, session):
        packet = {
            "protocol": 1,
            "agent": actor,
            "session": session,
            "task": {
                k: v for k, v in task.items() if k not in ("last_session", "resolved_disagreements")
            },
            "checkpoint": self._object(db, "checkpoint", task.get("checkpoint", "")),
            "references": {
                "actions": task["id"],
                "messages": actor,
                "memory": actor,
                "disagreements": task["id"],
            },
        }
        # Mandatory fields never truncate silently.
        if len(encoded(packet).encode()) > PACKET_BYTES:
            raise ValueError(f"mandatory recovery configuration exceeds {PACKET_BYTES} bytes")
        candidates = [
            ("actions", a)
            for a in self._objects(db, "action")
            if a["task_id"] == task["id"] and a["status"] not in ("completed", "failed")
        ]
        candidates += [("disagreements", d) for d in self._disagreements(db, actor, task["id"])]
        candidates += [
            ("messages", m) for m in self._inbox(db, actor) if m["message_type"] != "disagreement"
        ]
        if not task["no_memory"]:
            candidates += [("memory", line) for line in self._boot_card(db, actor)]
        for key, value in candidates:
            packet.setdefault(key, []).append(value)
            if len(encoded(packet).encode()) > PACKET_BYTES:
                packet[key].pop()
        return packet

    def create_task(
        self,
        actor,
        goal,
        acceptance,
        instructions="",
        turn_limit=100,
        seconds=3600,
        no_memory=False,
    ):
        if not isinstance(goal, str) or not goal.strip():
            raise ValueError("goal required")
        if (
            not isinstance(turn_limit, int)
            or not 1 <= turn_limit <= 100000
            or not 1 <= seconds <= 604800
        ):
            raise ValueError("invalid budget")
        bounded(instructions, "mandatory instructions", 2048)
        bounded(goal, "goal", 1024)
        bounded(acceptance, "acceptance criteria", 1024)
        obj = dict(
            id=uid(),
            owner=actor,
            goal=goal,
            acceptance=acceptance,
            instructions=instructions,
            turn_limit=turn_limit,
            turns=0,
            deadline_us=now_us() + seconds * 1_000_000,
            retries=0,
            status="open",
            agent=None,
            no_memory=bool(no_memory),
        )
        return self._mutate(actor, lambda tx: self._put(tx, "task", obj))

    def resume(self, actor, task_id):
        def job(tx):
            task = self._task(tx, task_id)
            self._owned(task, actor)
            now = now_us()
            current = self._object(tx, "session", actor)
            live = current and current["status"] == "active" and current["expires_us"] > now
            previous = task.get("last_session")
            restart = previous and previous["status"] in ("active", "failed")
            # An exhausted task escalates, and that commits even though the caller gets an error.
            if task["status"] in ("open", "running"):
                reason = None
                if task["turns"] >= task["turn_limit"] or now >= task["deadline_us"]:
                    reason = "task budget exhausted"
                elif restart and task["retries"] >= RETRY_LIMIT and not live:
                    reason = "restart limit reached; intervention required"
                if reason:
                    task.update(status="escalated", stop_reason=reason)
                    self._put(tx, "task", task)
                    return reason, None
            self._runnable(task)
            if live:
                raise ValueError("agent already has an active session")
            if task["agent"] and task["agent"] != actor:
                raise ValueError("task belongs to another agent")
            if restart:
                if task["retries"] >= RETRY_LIMIT:
                    raise ValueError("restart limit reached; intervention required")
                task["retries"] += 1
            task["agent"], task["status"] = actor, "running"
            session = dict(
                id=actor,
                session_id=uid(),
                task_id=task_id,
                generation=current["generation"] + 1 if current else 1,
                expires_us=now + LEASE_US,
                status="active",
                agent=actor,
            )
            if current:
                self._put(tx, "session_history", {**current, "id": current["session_id"]})
            task["last_session"] = session.copy()
            # A started effect may already have happened. Never automatically replay it.
            for action in self._objects(tx, "action"):
                if action["task_id"] == task_id and action["status"] == "started":
                    action["status"] = "outcome-unknown"
                    self._put(tx, "action", action)
            self._put(tx, "task", task)
            self._put(tx, "session", session)
            return None, self._packet(tx, actor, task, session)

        reason, packet = self._mutate(actor, job)
        if reason:
            raise ValueError(reason)
        return packet

    def heartbeat(self, actor, session_id, generation):
        def job(tx):
            s = self._lease(tx, actor, session_id, generation)
            s["expires_us"] = now_us() + LEASE_US
            return self._put(tx, "session", s)

        return self._mutate(actor, job)

    def checkpoint(
        self,
        actor,
        session_id,
        generation,
        completed,
        evidence,
        open_questions,
        workspace_revision,
        pending_actions,
        next_step,
    ):
        content = dict(
            completed=completed,
            evidence=evidence,
            open_questions=open_questions,
            workspace_revision=workspace_revision,
            pending_actions=pending_actions,
            next_step=next_step,
        )
        bounded(content, "checkpoint", 2048)
        for key in ("evidence", "open_questions", "pending_actions"):
            if not isinstance(content[key], list):
                raise ValueError(f"{key} must be a list")

        def job(tx):
            s = self._lease(tx, actor, session_id, generation)
            for ident in pending_actions:
                action = self._object(tx, "action", ident)
                if not action or action["task_id"] != s["task_id"]:
                    raise ValueError("pending action belongs to another task")
            task = self._task(tx, s["task_id"])
            task["turns"] += 1
            checkpoint = dict(id=uid(), task_id=s["task_id"], session_id=session_id, **content)
            self._put(tx, "checkpoint", checkpoint)
            task["checkpoint"] = checkpoint["id"]
            self._put(tx, "task", task)
            return checkpoint

        return self._mutate(actor, job)

    def finish(self, actor, session_id, generation, outcome, evidence):
        if outcome not in ("completed", "failed", "stopped", "yielded", "escalated"):
            raise ValueError("invalid outcome")
        bounded(evidence, "evidence")

        def job(tx):
            previous = self._object(tx, "session", actor)
            if (
                previous
                and previous["session_id"] == session_id
                and previous["generation"] == generation
                and previous["status"] == outcome
                and previous.get("evidence") == evidence
            ):
                return self._task(tx, previous["task_id"])  # a retried report, already applied
            s = self._lease(tx, actor, session_id, generation, allow_exhausted=True)
            task = self._task(tx, s["task_id"])
            if task["status"] == "cancelled":
                raise ValueError("task is stopped")
            if outcome == "completed":
                if any(
                    a["task_id"] == s["task_id"] and a["status"] not in ("completed", "failed")
                    for a in self._objects(tx, "action")
                ):
                    raise ValueError("unfinished or uncertain actions require reconciliation")
                resolved = task.get("resolved_disagreements", [])
                if any(i not in resolved for i in self._disagreement_ids(tx, s["task_id"], actor)):
                    raise ValueError("pending disagreement requires escalation")
            s["status"], s["evidence"] = outcome, evidence
            task["last_session"] = s.copy()
            task["status"] = "open" if outcome in ("yielded", "failed") else outcome
            if outcome == "failed" and task["retries"] >= RETRY_LIMIT:
                task["status"] = "escalated"
                task["stop_reason"] = "restart limit reached; intervention required"
            self._put(tx, "session", s)
            return self._put(tx, "task", task)

        return self._mutate(actor, job)

    def cancel_task(self, actor, task_id):
        def job(tx):
            task = self._task(tx, task_id)
            self._owned(task, actor)
            task["status"] = "cancelled"
            for session in self._objects(tx, "session"):
                if session["task_id"] == task_id and session["status"] == "active":
                    session["status"] = "cancelled"
                    self._put(tx, "session", session)
            return self._put(tx, "task", task)

        return self._mutate(actor, job)

    def begin_action(self, actor, session_id, generation, intent, idempotent=False):
        # idempotent is accepted for older callers and ignored: no flag licenses a restart.
        bounded(intent, "action intent")
        ident = uid()

        def job(tx):
            s = self._lease(tx, actor, session_id, generation)
            action = dict(
                id=ident,
                task_id=s["task_id"],
                intent=intent,
                status="planned",
            )
            return self._put(tx, "action", action)

        return self._mutate(actor, job)

    def action_outcome(self, actor, session_id, generation, action_id, status, evidence):
        bounded(evidence, "action evidence")
        transitions = {
            "planned": {"started", "failed"},
            "started": {"completed", "failed", "outcome-unknown"},
            "outcome-unknown": {"completed", "failed"},
        }

        def job(tx):
            s = self._lease(tx, actor, session_id, generation)
            action = self._object(tx, "action", action_id)
            if not action or action["task_id"] != s["task_id"]:
                raise ValueError("unknown action for this task")
            # A caller's idempotent flag never licenses a restart, matching troubleshooting actions.
            if action["status"] == "outcome-unknown" and status == "started":
                raise ValueError("uncertain external effect requires reconciliation")
            if status not in transitions.get(action["status"], set()):
                raise ValueError("invalid action transition")
            if status in ("completed", "failed") and not evidence:
                raise ValueError("outcome requires evidence references")
            action.update(status=status, evidence=evidence)
            return self._put(tx, "action", action)

        return self._mutate(actor, job)

    def send_message(
        self,
        actor,
        recipient,
        content,
        task_id=None,
        message_type="response",
        evidence=None,
        in_reply_to=None,
    ):
        evidence = [] if evidence is None else evidence
        if message_type not in TYPES or not references(evidence):
            raise ValueError("invalid message type or evidence references")
        bounded(content, "message", 16384)
        if not isinstance(content, dict) or not isinstance(recipient, str) or not recipient:
            raise ValueError("message requires a recipient and object content")
        ident = uid()

        def job(tx):
            tx.execute(
                "INSERT INTO messages (project_id, id, task_id, sender, recipient, message_type, "
                "content, evidence, in_reply_to, created_us) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    self.project,
                    ident,
                    task_id,
                    actor,
                    recipient,
                    message_type,
                    encoded(content),
                    encoded(evidence),
                    in_reply_to,
                    now_us(),
                ],
            )
            tx.audit("message", ident, {"to": recipient})
            tx.change("message", ident, {"recipient": recipient})
            return {"id": ident}

        return self._mutate(actor, job)

    def claim_messages(self, actor, session_id, generation, limit=40):
        def fn(con):
            self._lease(con, actor, session_id, generation)
            return self._inbox(con, actor)[: max(1, min(limit, 40))]

        return self.store.read(fn)

    def acknowledge(self, actor, session_id, generation, message_id):
        def job(tx):
            self._lease(tx, actor, session_id, generation)
            tx.execute(
                "UPDATE messages SET acknowledged = 1 "
                "WHERE project_id = ? AND id = ? AND recipient = ?",
                [self.project, message_id, actor],
            )
            tx.audit("acknowledge", message_id, {})
            return {"acknowledged": message_id}

        return self._mutate(actor, job)

    def human_decision(self, actor, task_id, decision, evidence, reopen=False):
        """Human maintainers only. A decision records evidence without resetting task budgets."""
        if not decision.strip() or not evidence or not references(evidence):
            raise ValueError("human decision and evidence references required")

        def job(tx):
            task = self._task(tx, task_id)
            if reopen and task["status"] != "escalated":
                raise ValueError("only escalation can be reopened; cancellation is terminal")
            record = dict(
                id=uid(), task_id=task_id, decision=decision, evidence=evidence, reopen=reopen
            )
            self._put(tx, "human_decision", record)
            task["human_decision"] = record["id"]
            task["resolved_disagreements"] = self._disagreement_ids(
                tx, task_id, task["agent"] or task["owner"]
            )
            if reopen:
                task["status"] = "open"
            self._put(tx, "task", task)
            return record

        return self._mutate(actor, job)

    def work_read(self, actor, kind, ident=None, task_id=None):
        def fn(con):
            if kind == "disagreement":
                if not task_id:
                    raise ValueError("disagreements require task_id")
                return self._disagreements(con, actor, task_id)
            if kind == "message":
                if not ident:
                    raise ValueError("message archive requires an ID")
                rows = con.execute(
                    "SELECT id, sender, recipient, content, message_type, in_reply_to, evidence "
                    "FROM messages WHERE project_id = ? AND id = ? AND ? IN (sender, recipient)",
                    [self.project, ident, actor],
                )
                return [
                    dict(
                        id=r[0],
                        sender=r[1],
                        recipient=r[2],
                        content=json.loads(r[3]),
                        message_type=r[4],
                        in_reply_to=r[5],
                        evidence=json.loads(r[6]),
                    )
                    for r in rows
                ]
            if kind not in WORK_KINDS:
                raise ValueError("unknown kind")
            return [
                r
                for r in self._mine(con, actor, kind)
                if (not ident or r["id"] == ident) and (not task_id or r.get("task_id") == task_id)
            ]

        return self.store.read(fn)

    def changes(self, actor, cursor=0, limit=40):
        if not isinstance(cursor, int) or cursor < 0 or not 1 <= limit <= 1000:
            raise ValueError("invalid cursor or page size")

        def fn(con):
            rows = con.execute(
                "SELECT seq, operation, object_id, actor, detail FROM changes "
                "WHERE project_id = ? AND seq > ? ORDER BY seq LIMIT ?",
                [self.project, cursor, limit],
            ).fetchall()
            # Private work never leaks through the change feed; the cursor still advances past it.
            items = [
                dict(seq=r[0], operation=r[1], id=r[2], actor=r[3], detail=json.loads(r[4]))
                for r in rows
                if self._visible(con, r[2], actor)
            ]
            return {"items": items, "cursor": rows[-1][0] if rows else cursor}

        return self.store.read(fn)
