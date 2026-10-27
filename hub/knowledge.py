"""Project knowledge lifecycle; evidence changes trust only for the bound revision."""

import hashlib
import json
import re

from hub.common import NotFound, Stale, bounded, references, uid
from hub.index import deindex, generation, index
from hub.library import disclosable, withdraw
from hub.store import encoded, now_us

SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40,64}$")
IMAGE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _sha(value, name):
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 hex digest")
    return value


class Knowledge:
    def _solution(self, db, ident):
        row = db.execute(
            "SELECT * FROM solutions WHERE project_id=? AND id=?", [self.project, ident]
        ).fetchone()
        return dict(row) if row else None

    def _revision(self, db, ident, revision):
        row = db.execute(
            "SELECT * FROM solution_revisions WHERE project_id=? AND solution_id=? AND revision=?",
            [self.project, ident, revision],
        ).fetchone()
        if not row:
            return None
        result = dict(row)
        result["applicability"] = json.loads(result["applicability"])
        result["conflicts_with"] = json.loads(result["conflicts_with"])
        return result

    def attempt_record(self, actor, approach, outcome, evidence, task_id=None):
        if not all(isinstance(x, str) and x.strip() for x in (approach, outcome)):
            raise ValueError("approach and outcome required")
        if not references(evidence) or not evidence:
            raise ValueError("evidence references required")
        bounded(approach, "approach", 8192)
        bounded(outcome, "outcome", 8192)
        bounded(evidence, "evidence", 8192)
        ident = uid()

        def job(tx):
            if not self._memory_allowed(tx, actor, task_id):
                return {"id": None}
            tx.execute(
                "INSERT INTO attempts VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    self.project,
                    ident,
                    task_id,
                    actor,
                    approach,
                    outcome,
                    encoded(evidence),
                    now_us(),
                ],
            )
            index(tx, "attempt", ident, 1, approach + "\n" + outcome)
            tx.audit("attempt.record", ident, {})
            tx.change("attempt.record", ident, {})
            return {"id": ident}

        return self._mutate(actor, job)

    def solution_propose(
        self,
        actor,
        body,
        problem_key,
        repository_commit,
        image_digest,
        checks_sha256,
        applicability=None,
        conflicts_with=None,
        solution_id=None,
        expected_revision=None,
        task_id=None,
    ):
        if not isinstance(body, str) or not body.strip() or len(body.encode()) > 262144:
            raise ValueError("solution body required, at most 256 KiB")
        if not isinstance(problem_key, str) or not problem_key.strip() or len(problem_key) > 256:
            raise ValueError("problem_key required, at most 256 characters")
        if not isinstance(repository_commit, str) or not COMMIT.fullmatch(repository_commit):
            raise ValueError("repository_commit must be a full lowercase Git hash")
        if not isinstance(image_digest, str) or not IMAGE.fullmatch(image_digest):
            raise ValueError("image_digest must be sha256:<64 hex>")
        _sha(checks_sha256, "checks_sha256")
        applicability = {} if applicability is None else applicability
        conflicts_with = [] if conflicts_with is None else conflicts_with
        if not isinstance(applicability, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in applicability.items()
        ):
            raise ValueError("applicability must map strings to strings")
        if not isinstance(conflicts_with, list) or not all(
            isinstance(x, str) for x in conflicts_with
        ):
            raise ValueError("conflicts_with must be a list of solution IDs")
        bounded(applicability, "applicability", 2048)
        bounded(conflicts_with, "conflicts_with", 2048)
        if solution_id is None and expected_revision is not None:
            raise ValueError("expected_revision needs solution_id")
        if solution_id is not None and (
            not isinstance(expected_revision, int)
            or isinstance(expected_revision, bool)
            or expected_revision < 1
        ):
            raise ValueError("expected_revision must be a positive integer")
        ident = solution_id or uid()

        def job(tx):
            if not self._memory_allowed(tx, actor, task_id):
                return {"id": None}
            old = self._solution(tx, ident)
            if solution_id:
                if not old:
                    raise NotFound("unknown solution")
                if old["author"] != actor or old["status"] in ("revoked", "superseded"):
                    raise ValueError("active owned solution required")
                if expected_revision != old["current_revision"]:
                    raise Stale("stale solution revision")
                revision = expected_revision + 1
                deindex(tx, "solution", ident)
                withdraw(tx, self.project, ident)  # a revision needs fresh publication
                tx.execute(
                    "UPDATE solutions SET status='unverified', current_revision=?, problem_key=? "
                    "WHERE project_id=? AND id=?",
                    [revision, problem_key, self.project, ident],
                )
            else:
                revision = 1
                tx.execute(
                    "INSERT INTO solutions VALUES (?, ?, ?, 'unverified', 1, NULL, ?, ?)",
                    [self.project, ident, actor, problem_key, now_us()],
                )
            for other in conflicts_with:
                if other == ident or not self._solution(tx, other):
                    raise NotFound("conflicting solution not found")
            content_sha256 = _digest(body)
            tx.execute(
                "INSERT INTO solution_revisions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    self.project,
                    ident,
                    revision,
                    body,
                    content_sha256,
                    actor,
                    repository_commit,
                    image_digest,
                    checks_sha256,
                    encoded(applicability),
                    encoded(conflicts_with),
                    now_us(),
                ],
            )
            index(tx, "solution", ident, revision, body)
            tx.audit("solution.propose", ident, {"revision": revision})
            tx.change("solution.propose", ident, {"revision": revision, "status": "unverified"})
            return {
                "id": ident,
                "revision": revision,
                "content_sha256": content_sha256,
                "status": "unverified",
            }

        return self._mutate(actor, job)

    def outcome_report(self, actor, solution_id, revision, result, evidence, task_id=None):
        if result not in ("success", "failure") or not references(evidence) or not evidence:
            raise ValueError("result and evidence references required")
        bounded(evidence, "evidence", 8192)
        ident = uid()

        def job(tx):
            if not self._memory_allowed(tx, actor, task_id):
                return {"id": None}
            if not self._revision(tx, solution_id, revision):
                raise NotFound("unknown solution revision")
            tx.execute(
                "INSERT INTO outcomes VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    self.project,
                    ident,
                    solution_id,
                    revision,
                    actor,
                    result,
                    encoded(evidence),
                    now_us(),
                ],
            )
            tx.audit("outcome.report", ident, {"solution": solution_id, "revision": revision})
            tx.change("outcome.report", solution_id, {"revision": revision, "result": result})
            return {"id": ident}

        return self._mutate(actor, job)

    def _promote(self, tx, solution, revision):
        conflicts = set(revision["conflicts_with"])
        conflicts.update(
            r[0]
            for r in tx.execute(
                "SELECT s.id FROM solutions s JOIN solution_revisions r "
                "ON r.project_id=s.project_id AND r.solution_id=s.id "
                "AND r.revision=s.current_revision WHERE s.project_id=? AND s.status='verified' "
                "AND EXISTS (SELECT 1 FROM json_each(r.conflicts_with) WHERE value=?)",
                [self.project, solution["id"]],
            )
        )
        verified = [
            other
            for ident in conflicts
            if (other := self._solution(tx, ident)) and other["status"] == "verified"
        ]
        status = "review" if verified else "verified"
        tx.execute(
            "UPDATE solutions SET status=? WHERE project_id=? AND id=?",
            [status, self.project, solution["id"]],
        )
        for other in verified:
            tx.execute(
                "UPDATE solutions SET status='review' WHERE project_id=? AND id=?",
                [self.project, other["id"]],
            )
            tx.change("solution.review", other["id"], {"reason": "explicit conflict"})
        generation(tx)
        return status

    def evidence_submit(
        self,
        actor,
        solution_id,
        revision,
        content_sha256,
        checks_sha256,
        repository_commit,
        image_digest,
        result,
        artifacts,
    ):
        for name, value in (("content_sha256", content_sha256), ("checks_sha256", checks_sha256)):
            _sha(value, name)
        if result not in ("pass", "fail"):
            raise ValueError("result must be pass or fail")
        if not isinstance(artifacts, list) or not artifacts:
            raise ValueError("artifact hashes required")
        for item in artifacts:
            _sha(item, "artifact")
        ident = uid()

        def job(tx):
            solution = self._solution(tx, solution_id)
            rev = self._revision(tx, solution_id, revision)
            if not solution:
                raise NotFound("unknown solution")
            if not rev or solution["current_revision"] != revision:
                raise Stale("stale solution revision")
            if actor == solution["author"]:
                raise ValueError("a proposer cannot verify their own solution")
            if solution["status"] in ("revoked", "superseded"):
                raise ValueError("inactive solution")
            if (
                content_sha256 != rev["content_sha256"]
                or checks_sha256 != rev["checks_sha256"]
                or repository_commit != rev["repository_commit"]
                or image_digest != rev["image_digest"]
            ):
                raise ValueError("evidence does not match the proposed revision")
            tx.execute(
                "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    self.project,
                    ident,
                    solution_id,
                    revision,
                    actor,
                    content_sha256,
                    checks_sha256,
                    repository_commit,
                    image_digest,
                    result,
                    encoded(artifacts),
                    now_us(),
                ],
            )
            status = solution["status"]
            if result == "pass":
                status = self._promote(tx, solution, rev)
            elif status == "verified":
                tx.execute(
                    "UPDATE solutions SET status='review' WHERE project_id=? AND id=?",
                    [self.project, solution_id],
                )
                generation(tx)
                status = "review"
            tx.audit(
                "evidence.submit",
                ident,
                {"solution": solution_id, "revision": revision, "result": result},
            )
            tx.change("evidence.submit", solution_id, {"revision": revision, "status": status})
            return {"id": ident, "status": status}

        return self._mutate(actor, job)

    def solution_decide(self, actor, solution_id, revision, action, reason, target_id=None):
        if action not in ("approve", "review", "revoke", "supersede"):
            raise ValueError("invalid decision action")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("decision reason required")
        bounded(reason, "reason", 2048)
        ident = uid()

        def job(tx):
            solution = self._solution(tx, solution_id)
            rev = self._revision(tx, solution_id, revision)
            if not solution:
                raise NotFound("unknown solution")
            if not rev or solution["current_revision"] != revision:
                raise Stale("stale solution revision")
            if actor == solution["author"]:
                raise ValueError("self-approval is forbidden")
            if solution["status"] in ("revoked", "superseded"):
                raise ValueError("inactive solution")
            if action == "supersede":
                target = self._solution(tx, target_id)
                if not target:
                    raise NotFound("supersession target not found")
                if target_id == solution_id or target["status"] != "verified":
                    raise ValueError("supersession requires another verified solution")
                tx.execute(
                    "UPDATE solutions SET status='superseded', superseded_by=? "
                    "WHERE project_id=? AND id=?",
                    [target_id, self.project, solution_id],
                )
                deindex(tx, "solution", solution_id)
                withdraw(tx, self.project, solution_id)
                status = "superseded"
            elif action == "revoke":
                tx.execute(
                    "UPDATE solutions SET status='revoked' WHERE project_id=? AND id=?",
                    [self.project, solution_id],
                )
                deindex(tx, "solution", solution_id)
                withdraw(tx, self.project, solution_id)
                status = "revoked"
            elif action == "approve":
                status = self._promote(tx, solution, rev)
            else:
                tx.execute(
                    "UPDATE solutions SET status='review' WHERE project_id=? AND id=?",
                    [self.project, solution_id],
                )
                generation(tx)
                status = "review"
            tx.execute(
                "INSERT INTO decisions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    self.project,
                    ident,
                    solution_id,
                    revision,
                    actor,
                    action,
                    reason,
                    target_id,
                    now_us(),
                ],
            )
            tx.audit("solution.decide", ident, {"solution": solution_id, "action": action})
            tx.change("solution.decide", solution_id, {"revision": revision, "status": status})
            return {"id": ident, "status": status}

        return self._mutate(actor, job)

    def knowledge_record(self, actor, ident):
        def read(db):
            solution = self._solution(db, ident)
            if solution and not disclosable(
                db, self.project, ident, solution["current_revision"], actor
            ):
                return None
            if solution:
                revision = self._revision(db, ident, solution["current_revision"])
                evidence = [
                    {**dict(row), "artifacts": json.loads(row["artifacts"])}
                    for row in db.execute(
                        "SELECT id, revision, verifier, result, artifacts, created_us "
                        "FROM evidence "
                        "WHERE project_id=? AND solution_id=? ORDER BY created_us",
                        [self.project, ident],
                    )
                ]
                outcomes = [
                    {**dict(row), "evidence": json.loads(row["evidence"])}
                    for row in db.execute(
                        "SELECT id, revision, author, result, evidence, created_us FROM outcomes "
                        "WHERE project_id=? AND solution_id=? ORDER BY created_us",
                        [self.project, ident],
                    )
                ]
                return {
                    "kind": "solution",
                    **solution,
                    "revision": revision,
                    "evidence": evidence,
                    "outcomes": outcomes,
                }
            row = db.execute(
                "SELECT * FROM attempts WHERE project_id=? AND id=?", [self.project, ident]
            ).fetchone()
            return (
                {"kind": "attempt", **dict(row), "evidence": json.loads(row["evidence"])}
                if row
                else None
            )

        return self.store.read(read)
