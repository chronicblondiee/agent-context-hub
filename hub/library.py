"""The general troubleshooting library: reviewed publication and troubleshooting retrieval.

The library is one dedicated project an administrator designates. Agents propose sanitized
copies of active project records; a human maintainer of both projects publishes the exact
reviewed revision. A library copy is disclosed only while its publication is current: revising,
revoking or superseding the source withdraws it until a fresh proposal is published.
"""

import hashlib
import json
from pathlib import Path

from hub.common import NotFound, Stale, bounded, references, uid
from hub.identity import SYSTEM
from hub.index import generation, index
from hub.store import Tx, encoded, now_us

STARTER = Path(__file__).with_name("tshoot_starter.json")
LIMIT, GENERAL = 5, 2  # matches per answer, of which at most two come from the library
NAMESPACE = "troubleshooting"
# Only records published at their current revision are library results.
PUBLISHED = (
    " AND EXISTS (SELECT 1 FROM publications p WHERE p.library_project=f.project_id"
    " AND p.dest_id=f.record_id AND p.status='published' AND p.dest_revision=f.revision)"
)


def library_of(db):
    row = db.execute("SELECT project_id FROM tshoot_library").fetchone()
    return row[0] if row else None


def granted(db, principal, project, roles=None):
    sql = "SELECT 1 FROM grants WHERE principal_id=? AND project_id=?"
    if roles:
        sql += f" AND role IN ({','.join('?' * len(roles))})"
    return bool(db.execute(sql, [principal, project, *(roles or ())]).fetchone())


def disclosable(db, project, ident, revision=None, actor=None):
    """False for a library copy whose publication is not current; library maintainers still
    read the governance history when actor is given."""
    rows = db.execute(
        "SELECT status, dest_revision FROM publications WHERE library_project=? AND dest_id=?",
        [project, ident],
    ).fetchall()
    if all(r[0] == "published" and revision in (None, r[1]) for r in rows):
        return True
    return actor is not None and granted(db, actor, project, ("maintainer",))


def configure(store, actor, project_id):
    """Designate the library project (service administrator)."""

    def job(tx):
        if (
            not isinstance(project_id, str)
            or not tx.execute(
                "SELECT 1 FROM projects WHERE id=? AND id<>?", [project_id, SYSTEM]
            ).fetchone()
        ):
            raise ValueError("unknown project")
        tx.execute(
            "INSERT INTO tshoot_library VALUES (1, ?) "
            "ON CONFLICT(singleton) DO UPDATE SET project_id=excluded.project_id",
            [project_id],
        )
        tx.audit("tshoot_library.set", project_id, {})
        return {"library": project_id}

    return store.mutate(SYSTEM, actor, job)


def withdraw(tx, project, source_id):
    """The source changed or ended: its proposals and publications leave normal retrieval."""
    rows = tx.execute(
        "SELECT id, library_project, dest_id, status FROM publications "
        "WHERE source_project=? AND source_id=? AND status IN ('proposed','published')",
        [project, source_id],
    ).fetchall()
    for row in rows:
        tx.execute("UPDATE publications SET status='withdrawn' WHERE id=?", [row["id"]])
        tx.audit("publication.withdraw", row["id"], {"source": source_id})
        if row["status"] == "published":
            library = Tx(tx.con, row["library_project"], tx.actor)
            generation(library)
            library.audit("publication.withdraw", row["id"], {})
            library.change("publication.withdraw", row["dest_id"], {})


def _memory(tx, project, ident, kind, body, hook, provenance, confidence, author, owner, evidence):
    tx.execute(
        "INSERT INTO memory_records (project_id, id, task_id, namespace, kind, body, hook, "
        "provenance, confidence, author, evidence, visibility, revoked, superseded_by, "
        "created_us, owner, agent_session) "
        "VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, 'project', 0, NULL, ?, ?, NULL)",
        [
            project,
            ident,
            NAMESPACE,
            kind,
            body,
            hook or body[:120],
            provenance,
            confidence,
            author,
            encoded(evidence),
            now_us(),
            owner,
        ],
    )
    target = tx if tx.project_id == project else Tx(tx.con, project, tx.actor)
    index(target, "memory", ident, 1, body)


def _proposal(row):
    found = dict(row)
    found["applicability"] = json.loads(found["applicability"])
    found["evidence"] = json.loads(found["evidence"])
    return found


def _trust(item):
    return {"verified": "verified", "review": "under review"}.get(item["status"], "unverified")


class Library:
    def _publishable(self, db, source_id):
        """(kind, revision, row) for an active project-visible source; private reads as absent."""
        record = self._memory_row(db, source_id)
        if record and record["visibility"] == "project":
            if record["revoked"] or record["superseded_by"]:
                raise ValueError("source record is revoked or superseded")
            return "memory", 1, record
        solution = self._solution(db, source_id)
        if solution:
            if solution["status"] in ("revoked", "superseded"):
                raise ValueError("source solution is revoked or superseded")
            return "solution", solution["current_revision"], solution
        raise NotFound("unknown source record")

    def tshoot_context(
        self,
        actor,
        query,
        task_id=None,
        thread_id=None,
        environment=None,
        max_chars=8000,
        max_bytes=None,
    ):
        """This project plus the general library: at most five matches, two of them general."""
        from hub import retrieval

        environment = retrieval.validate(query, LIMIT, max_chars, max_bytes, environment)
        if thread_id is not None and not isinstance(thread_id, str):
            raise ValueError("thread_id must be a string")

        def search(db):
            # No-memory comes first: neither source is searched.
            if not self._memory_allowed(db, actor, task_id):
                return {**retrieval.envelope(db, self.project), "library": "skipped"}
            if thread_id is not None:
                self._thread(db, thread_id)
                if not db.execute(
                    "SELECT 1 FROM troubleshooting_participants WHERE project_id=? "
                    "AND thread_id=? AND actor=?",
                    [self.project, thread_id, actor],
                ).fetchone():
                    raise ValueError("thread participation required")
            owner = self._owner(db, actor)
            found, ran = retrieval.ranked(db, self, owner, query, vector, environment)
            for item in found:
                item.update(project_id=self.project, source="project")
            library, status = library_of(db), "unavailable"
            # One configured library, only with an explicit grant there; never other projects.
            # Without one the answer is the same as with no library at all.
            if library and library != self.project and granted(db, actor, library):
                shelf = type(self)(self.store, library)
                general, general_ran = retrieval.ranked(
                    db, shelf, owner, query, vector, environment, PUBLISHED
                )
                ran, status = ran and general_ran, "searched"
                local = {item["id"] for item in found}
                for item in general:
                    row = db.execute(
                        "SELECT id, source_project, source_id, reviewer, decided_us "
                        "FROM publications WHERE library_project=? AND dest_id=? "
                        "AND status='published'",
                        [library, item["id"]],
                    ).fetchone()
                    if row["source_project"] == self.project and row["source_id"] in local:
                        continue  # the project's own record already answers
                    item.update(
                        project_id=library,
                        source="general",
                        publication={
                            "id": row["id"],
                            "reviewer": row["reviewer"],
                            "published_us": row["decided_us"],
                        },
                    )
                    found.append(item)
            # Project results win ties on trust, applicability and relevance.
            found.sort(key=lambda r: (*retrieval.order(r), r["source"] != "project", r["id"]))
            selected, bodies, general_count, truncated = [], set(), 0, False
            for item in found:
                digest = hashlib.sha256(item["summary"].encode()).hexdigest()
                if digest in bodies:
                    continue  # the same text from both sources
                if len(selected) == LIMIT or (
                    item["source"] == "general" and general_count == GENERAL
                ):
                    truncated = True
                    continue
                bodies.add(digest)
                general_count += item["source"] == "general"
                item["trust"] = _trust(item)
                # A lead is a hypothesis to test: unverified, or with unchecked applicability.
                item["lead"] = item["trust"] != "verified" or bool(
                    item.get("applicability_missing")
                )
                selected.append(item)
            matches, truncated = retrieval.budget(selected, max_chars, truncated)
            return {
                **retrieval.envelope(db, self.project, "hybrid" if ran else "keyword_only"),
                "library": status,
                "truncated": truncated,
                "matches": matches,
            }

        with retrieval.SEARCHES:
            vector = retrieval.embedded(query)
            return retrieval.fit_context_bytes(self.store.read(search), max_bytes)

    def tshoot_propose(
        self, actor, source_id, body, evidence, applicability=None, hook="", task_id=None
    ):
        """Propose a sanitized library copy of an active project-visible record."""
        if not isinstance(body, str) or not body.strip() or len(body.encode()) > 16384:
            raise ValueError("sanitized body required, at most 16 KiB")
        if not isinstance(hook, str) or len(hook.encode()) > 480:
            raise ValueError("hook exceeds 480 bytes")
        if not isinstance(evidence, list) or not evidence or not references(evidence):
            raise ValueError("safe evidence references required")
        bounded(evidence, "evidence", 4096)
        applicability = {} if applicability is None else applicability
        if not isinstance(applicability, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in applicability.items()
        ):
            raise ValueError("applicability must map strings to strings")
        bounded(applicability, "applicability", 2048)
        ident = uid()

        def job(tx):
            if not self._memory_allowed(tx, actor, task_id):
                return {"id": None}
            library = library_of(tx)
            if not library:
                raise ValueError("no troubleshooting library is configured")
            if library == self.project:
                raise ValueError("propose from the originating project")
            kind, revision, _ = self._publishable(tx, source_id)
            tx.execute(
                "INSERT INTO publications (id, source_project, source_kind, source_id, "
                "source_revision, library_project, body, hook, applicability, evidence, status, "
                "proposer, created_us) VALUES (?,?,?,?,?,?,?,?,?,?,'proposed',?,?)",
                [
                    ident,
                    self.project,
                    kind,
                    source_id,
                    revision,
                    library,
                    body,
                    hook or body[:120],
                    encoded(applicability),
                    encoded(evidence),
                    actor,
                    now_us(),
                ],
            )
            tx.audit("publication.propose", ident, {"source": source_id, "revision": revision})
            return {"id": ident, "status": "proposed", "source_revision": revision}

        return self._mutate(actor, job)

    def tshoot_proposals(self, actor, status=None, cursor=0, limit=40):
        """Governance history where this project is the source or the library (maintainers)."""
        if status not in (None, "proposed", "published", "rejected", "withdrawn"):
            raise ValueError("invalid status")
        if type(cursor) is not int or cursor < 0 or type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("invalid pagination")
        sql = "SELECT * FROM publications WHERE (source_project=? OR library_project=?)"
        args = [self.project, self.project]
        if status:
            sql += " AND status=?"
            args.append(status)
        sql += " ORDER BY created_us, id LIMIT ? OFFSET ?"
        return self.store.read(
            lambda db: [_proposal(r) for r in db.execute(sql, [*args, limit, cursor])]
        )

    def tshoot_publication_decide(self, actor, proposal_id, action, reason):
        """Publish or reject a proposal; needs maintainer authority in both projects."""
        if action not in ("publish", "reject"):
            raise ValueError("action must be publish or reject")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("decision reason required")
        bounded(reason, "reason", 2048)

        def job(tx):
            row = tx.execute(
                "SELECT * FROM publications WHERE id=? AND source_project=?",
                [proposal_id, self.project],
            ).fetchone()
            if not row:
                raise NotFound("unknown proposal")
            p = _proposal(row)
            if p["status"] != "proposed":
                raise ValueError("proposal is " + p["status"])
            library = p["library_project"]
            if not granted(tx, actor, library, ("maintainer",)):
                raise ValueError("publication requires maintainer authority in the library")
            if action == "reject":
                tx.execute(
                    "UPDATE publications SET status='rejected', reviewer=?, reason=?, "
                    "decided_us=? WHERE id=?",
                    [actor, reason, now_us(), proposal_id],
                )
                tx.audit("publication.reject", proposal_id, {})
                return {"id": proposal_id, "status": "rejected"}
            kind, revision, source = self._publishable(tx, p["source_id"])
            if kind != p["source_kind"] or revision != p["source_revision"]:
                raise Stale("source changed since the proposal; propose again")
            dest, target = uid(), Tx(tx.con, library, actor)
            if kind == "memory":
                _memory(
                    tx,
                    library,
                    dest,
                    source["kind"],
                    p["body"],
                    p["hook"],
                    source["provenance"],
                    source["confidence"],
                    p["proposer"],
                    source["owner"],  # memory stays owned by its human
                    p["evidence"],
                )
            else:
                rev = self._revision(tx, p["source_id"], revision)
                tx.execute(
                    "INSERT INTO solutions VALUES (?, ?, ?, 'unverified', 1, NULL, ?, ?)",
                    [library, dest, source["author"], source["problem_key"], now_us()],
                )
                # Trust starts over: only evidence or approval for this exact copy verifies it.
                tx.execute(
                    "INSERT INTO solution_revisions VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, '[]', ?)",
                    [
                        library,
                        dest,
                        p["body"],
                        hashlib.sha256(p["body"].encode()).hexdigest(),
                        source["author"],
                        rev["repository_commit"],
                        rev["image_digest"],
                        rev["checks_sha256"],
                        encoded(p["applicability"]),
                        now_us(),
                    ],
                )
                index(target, "solution", dest, 1, p["body"])
            tx.execute(
                "UPDATE publications SET status='published', dest_id=?, dest_revision=1, "
                "reviewer=?, reason=?, decided_us=? WHERE id=?",
                [dest, actor, reason, now_us(), proposal_id],
            )
            tx.audit("publication.publish", proposal_id, {"library": library})
            target.audit("publication.publish", proposal_id, {"dest": dest, "kind": kind})
            target.change("publication.publish", dest, {"kind": kind})
            return {
                "id": proposal_id,
                "status": "published",
                "library_project": library,
                "dest_id": dest,
                "dest_revision": 1,
            }

        return self._mutate(actor, job)

    def tshoot_seed_starter(self, actor):
        """Propose the sourced starter diagnostic methods once each, as sourced project
        memory. A seed that was ever proposed, including withdrawn ones, is skipped."""
        entries = json.loads(STARTER.read_text())

        def job(tx):
            library = library_of(tx)
            if not library or library == self.project:
                raise ValueError("seed from a source project once a library is configured")
            owner = self._owner(tx, actor, write=True)
            proposed = []
            for e in entries:
                if tx.execute("SELECT 1 FROM publications WHERE seed_key=?", [e["key"]]).fetchone():
                    continue
                record, ident = uid(), uid()
                _memory(
                    tx,
                    self.project,
                    record,
                    "diagnostic-method",
                    e["body"],
                    e["hook"],
                    "stated",
                    0.8,
                    actor,
                    owner,
                    e["sources"],
                )
                tx.change("remember", record, {"visibility": "project"})
                tx.execute(
                    "INSERT INTO publications (id, source_project, source_kind, source_id, "
                    "source_revision, library_project, body, hook, applicability, evidence, "
                    "seed_key, status, proposer, created_us) "
                    "VALUES (?,?,'memory',?,1,?,?,?,'{}',?,?,'proposed',?,?)",
                    [
                        ident,
                        self.project,
                        record,
                        library,
                        e["body"],
                        e["hook"],
                        encoded(e["sources"]),
                        e["key"],
                        actor,
                        now_us(),
                    ],
                )
                proposed.append({"id": ident, "key": e["key"], "source_id": record})
            tx.audit("publication.seed", self.project, {"proposed": len(proposed)})
            return {"proposed": proposed}

        return self._mutate(actor, job)
