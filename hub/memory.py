"""Project memory ported from aic/kernel.py: write, revise (supersede), revoke, boot card.

A mixin for hub.work.Work, which supplies _mutate, _object and _task. Ranked recall is M4.
"""

import json
import math
import uuid

from hub.index import deindex, index
from hub.library import disclosable, withdraw
from hub.store import encoded, now_us

PROVENANCE = ("stated", "tested", "assumed", "inferred")
CARD_LIMIT = 40
PER_NAMESPACE = 8
COLUMNS = (
    "id, task_id, namespace, kind, body, hook, provenance, confidence, author, evidence, "
    "visibility, revoked, superseded_by, created_us, owner, agent_session"
)


def _record(row):
    record = dict(row)
    record["evidence"] = json.loads(record["evidence"])
    record["revoked"] = bool(record["revoked"])
    return record


def owner_of(db, project, actor, write=False):
    """The human an agent acts for, else the actor; unbound agents may read, not write."""
    row = db.execute("SELECT kind, acts_for FROM principals WHERE id = ?", [actor]).fetchone()
    if not row or row[0] != "agent":
        return actor
    if row[1]:
        if (
            write
            and not db.execute(
                "SELECT 1 FROM grants WHERE principal_id = ? AND project_id = ? "
                "AND role = 'maintainer'",
                [row[1], project],
            ).fetchone()
        ):
            raise ValueError("the agent's human owner must be a project maintainer")
        return row[1]
    if write:
        raise ValueError("agent must be bound to a human owner")
    return actor


class Memory:
    def _owner(self, db, actor, write=False):
        return owner_of(db, self.project, actor, write)

    def _memory_allowed(self, db, actor, task_id=None):
        """No-memory tasks keep execution state but neither read nor write long-term memory."""
        session = self._object(db, "session", actor)
        if session and session["status"] == "active":
            if self._task(db, session["task_id"])["no_memory"]:
                return False
        if task_id:
            task = self._task(db, task_id)
            if actor not in (task["owner"], task["agent"]):
                raise ValueError("task ownership required")
            return not task["no_memory"]
        return True

    def _memory_row(self, db, memory_id):
        row = db.execute(
            f"SELECT {COLUMNS} FROM memory_records WHERE project_id = ? AND id = ?",
            [self.project, memory_id],
        ).fetchone()
        if not row:
            return None
        from hub.freshness import details

        return _record(row) | details(db, self.project, memory_id)

    @staticmethod
    def _memory_visible(record, owner):
        return record["visibility"] == "project" or record["owner"] == owner

    def remember(
        self,
        actor,
        namespace,
        kind,
        body,
        provenance,
        confidence,
        evidence,
        task_id=None,
        hook="",
        visibility="project",
        supersedes=None,
        temporal_kind="unclassified",
        observed_us=None,
        review_due_us=None,
        claim_key=None,
        expected_revision=None,
    ):
        if provenance not in PROVENANCE:
            raise ValueError("every memory record needs a provenance")
        if (
            not isinstance(confidence, (float, int))
            or not math.isfinite(confidence)
            or not 0 <= confidence <= 1
        ):
            raise ValueError("confidence must be finite and between zero and one")
        if visibility not in ("private", "project"):
            raise ValueError("invalid visibility")
        if not all(isinstance(x, str) and x for x in (namespace, kind, body)):
            raise ValueError("namespace, kind and body are required")
        if (
            not isinstance(evidence, list)
            or not evidence
            or not all(isinstance(x, str) and x.strip() for x in evidence)
        ):
            raise ValueError("evidence must be a nonempty list of source references")
        if len(namespace.encode()) > 128 or len(kind.encode()) > 64:
            raise ValueError("namespace or kind exceeds field limit")
        if len(body.encode()) > 262144 or len(hook.encode()) > 480:
            raise ValueError("body or hook exceeds field limit")
        from hub.freshness import validate

        validate(temporal_kind, observed_us, review_due_us, claim_key)
        ident = str(uuid.uuid4())

        def job(tx):
            if not self._memory_allowed(tx, actor, task_id):
                return {"id": None}
            owner = self._owner(tx, actor, write=True)
            if supersedes:
                old = self._memory_row(tx, supersedes)
                if not old or old["owner"] != owner or old["revoked"] or old["superseded_by"]:
                    raise ValueError("revision requires an active record owned by the same human")
                if expected_revision is not None and old["freshness_revision"] != expected_revision:
                    from hub.common import Stale

                    raise Stale("freshness revision changed")
                tx.execute(
                    "UPDATE memory_freshness SET active=0 WHERE project_id=? AND memory_id=?",
                    [self.project, supersedes],
                )
            if (
                claim_key
                and tx.execute(
                    "SELECT 1 FROM memory_freshness WHERE project_id=? AND owner=? AND namespace=? "
                    "AND visibility=? AND claim_key=? AND active=1",
                    [self.project, owner, namespace, visibility, claim_key],
                ).fetchone()
            ):
                raise ValueError("active claim exists; explicitly supersede it")
            tx.execute(
                f"INSERT INTO memory_records (project_id, {COLUMNS}) VALUES "
                "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, ?, ?, ?)",
                [
                    self.project,
                    ident,
                    task_id,
                    namespace,
                    kind,
                    body,
                    hook or body[:120],
                    provenance,
                    confidence,
                    actor,
                    encoded(evidence),
                    visibility,
                    now_us(),
                    owner,
                    self.agent_session,
                ],
            )
            tx.execute(
                "UPDATE memory_freshness SET temporal_kind=?,observed_us=?,review_due_us=?,"
                "claim_key=? "
                "WHERE project_id=? AND memory_id=?",
                [temporal_kind, observed_us, review_due_us, claim_key, self.project, ident],
            )
            if supersedes:
                tx.execute(
                    "UPDATE memory_source_checks SET state='stopped',generation=generation+1 "
                    "WHERE project_id=? AND memory_id=?",
                    [self.project, supersedes],
                )
                tx.execute(
                    "UPDATE memory_records SET superseded_by = ? WHERE project_id = ? AND id = ?",
                    [ident, self.project, supersedes],
                )
                deindex(tx, "memory", supersedes)
                withdraw(tx, self.project, supersedes)
                tx.change("supersede", supersedes, {"superseded_by": ident})
            index(tx, "memory", ident, 1, body)
            if supersedes:
                from hub import federation

                federation.successor(tx, supersedes, ident)
            tx.change("remember", ident, {"visibility": visibility})
            # Audit names what changed, never the body: audit is readable without record access.
            tx.audit("write", ident, {"namespace": namespace, "kind": kind})
            return {"id": ident}

        return self._mutate(actor, job)

    def revise_memory(
        self,
        actor,
        memory_id,
        body,
        provenance,
        confidence,
        evidence,
        hook="",
        expected_revision=None,
        temporal_kind=None,
        observed_us=None,
        review_due_us=None,
        claim_key=None,
    ):
        old = self.store.read(lambda con: self._memory_row(con, memory_id))
        if not old:
            raise ValueError("owned record required")  # remember() checks the owner
        return self.remember(
            actor,
            old["namespace"],
            old["kind"],
            body,
            provenance,
            confidence,
            evidence,
            task_id=old["task_id"],
            hook=hook,
            visibility=old["visibility"],
            supersedes=memory_id,
            expected_revision=expected_revision,
            temporal_kind=temporal_kind or old["temporal_kind"],
            observed_us=observed_us,
            review_due_us=review_due_us if review_due_us is not None else old["review_due_us"],
            claim_key=claim_key if claim_key is not None else old["claim_key"],
        )

    def _revoke(self, tx, memory_id):
        """Revocation effects shared by revoke_memory and freshness retirement."""
        tx.execute(
            "UPDATE memory_records SET revoked = 1 WHERE project_id = ? AND id = ?",
            [self.project, memory_id],
        )
        tx.execute(
            "UPDATE memory_freshness SET active=0 WHERE project_id=? AND memory_id=?",
            [self.project, memory_id],
        )
        tx.execute(
            "UPDATE memory_source_checks SET state='stopped',generation=generation+1 "
            "WHERE project_id=? AND memory_id=?",
            [self.project, memory_id],
        )
        deindex(tx, "memory", memory_id)
        withdraw(tx, self.project, memory_id)
        from hub import federation

        federation.changed(tx, memory_id)
        tx.audit("revoke", memory_id, {})
        tx.change("revoke", memory_id, {})

    def revoke_memory(self, actor, memory_id, maintainer=False):
        """Owners revoke their records; maintainers also revoke project-visible ones."""

        def job(tx):
            record = self._memory_row(tx, memory_id)
            allowed = record and (
                record["owner"] == self._owner(tx, actor)
                or (maintainer and record["visibility"] == "project")
            )
            if not allowed:
                raise ValueError("owned record required")
            if not record["revoked"]:
                self._revoke(tx, memory_id)
            return {"revoked": memory_id}

        return self._mutate(actor, job)

    def record(self, actor, memory_id):
        """The governance archive: visible records, including revoked and superseded ones."""

        def fn(con):
            record = self._memory_row(con, memory_id)
            visible = (
                record
                and self._memory_visible(record, self._owner(con, actor))
                and disclosable(con, self.project, memory_id, actor=actor)
            )
            return record if visible else None

        return self.store.read(fn)

    def _boot_card(self, db, actor):
        if not self._memory_allowed(db, actor):
            return []
        rows = db.execute(
            "SELECT id, namespace, kind, hook, provenance, confidence FROM memory_records "
            "WHERE project_id = ? AND owner = ? AND NOT revoked AND superseded_by IS NULL "
            "ORDER BY created_us DESC, id",
            [self.project, self._owner(db, actor)],
        )
        seen, out = {}, []
        from hub.freshness import details

        rows = [(row, details(db, self.project, row[0])) for row in rows]
        rows.sort(key=lambda pair: pair[1]["freshness"] != "current")
        for row, fresh in rows:
            if not disclosable(db, self.project, row[0], actor=actor):
                continue
            if fresh["freshness"] not in ("current", "freshness unknown"):
                continue
            if seen.get(row[1], 0) >= PER_NAMESPACE:
                continue
            seen[row[1]] = seen.get(row[1], 0) + 1
            out.append(" ".join(str(part) for part in [*row, fresh["freshness"]]))
            if len(out) >= CARD_LIMIT:
                break
        return out[::-1]

    def boot_card(self, actor):
        return self.store.read(lambda con: self._boot_card(con, actor))
