"""Durable API-only source checking; no external I/O occurs inside these transactions."""

import json
import os
import random
import re
import uuid

from hub.common import Stale
from hub.store import encoded, now_us

LEASE_US = 60_000_000
MAX_ATTEMPTS = 5


def validate_source(source):
    if not isinstance(source, dict) or set(source) - {
        "endpoint",
        "repository",
        "kind",
        "ref",
        "path",
        "number",
    }:
        raise ValueError("invalid source binding")
    allowed = json.loads(os.environ.get("HUB_CHECK_ENDPOINTS", "[]"))
    if source.get("endpoint") not in allowed:
        raise ValueError("source endpoint is not operator configured")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", source.get("repository", "")):
        raise ValueError("invalid repository")
    if source.get("kind") == "file":
        if set(source) != {"endpoint", "repository", "kind", "ref", "path"}:
            raise ValueError("file requires ref and path")
        for key in ("ref", "path"):
            value = source[key]
            if (
                not isinstance(value, str)
                or not value
                or len(value) > 1024
                or any(p in ("", ".", "..") for p in value.split("/"))
            ):
                raise ValueError("invalid file ref/path")
    elif source.get("kind") in ("issue", "pull"):
        if (
            set(source) != {"endpoint", "repository", "kind", "number"}
            or type(source["number"]) is not int
            or source["number"] <= 0
        ):
            raise ValueError("issue/pull requires positive number")
    else:
        raise ValueError("unsupported source kind")
    return encoded(source)


def fingerprint(value):
    if not isinstance(value, str) or not re.fullmatch("[0-9a-f]{64}", value):
        raise ValueError("fingerprint must be SHA-256 hex")
    return value


class SourceChecks:
    def memory_source_bind(self, actor, memory_id, expected_revision, source, baseline=None):
        source = validate_source(source)
        if baseline is not None:
            fingerprint(baseline)

        def job(tx):
            self._review_owned(tx, actor, memory_id, expected_revision)
            existing = tx.execute(
                "SELECT id,baseline FROM memory_source_checks WHERE project_id=? "
                "AND memory_id=? AND source=?",
                [self.project, memory_id, source],
            ).fetchone()
            if existing:
                if existing["baseline"] != baseline:
                    raise ValueError("binding exists with a different baseline")
                return {"id": existing["id"]}
            ident = str(uuid.uuid4())
            tx.execute(
                "INSERT INTO memory_source_checks(project_id,id,memory_id,source,baseline,due_us) "
                "VALUES (?,?,?,?,?,?)",
                [self.project, ident, memory_id, source, baseline, now_us()],
            )
            tx.execute(
                "UPDATE memory_freshness SET revision=revision+1 WHERE "
                "project_id=? AND memory_id=?",
                [self.project, memory_id],
            )
            tx.audit("source.bind", memory_id, {"binding": ident})
            tx.change("memory.review", memory_id, {"source_binding": ident})
            return {"id": ident}

        return self._mutate(actor, job)

    def source_check_claim(self, actor):
        def job(tx):
            now = now_us()
            # Stop obsolete targets, and exhaust crashed workers after the same bounded budget.
            tx.execute(
                "UPDATE memory_source_checks SET state='stopped',generation=generation+1 "
                "WHERE project_id=? AND state IN ('pending','claimed') AND memory_id IN "
                "(SELECT id FROM memory_records WHERE project_id=? AND "
                "(revoked OR superseded_by IS NOT NULL))",
                [self.project, self.project],
            )
            expired = tx.execute(
                "SELECT id,memory_id FROM memory_source_checks WHERE project_id=? "
                "AND state='claimed' AND lease_until_us<=? AND attempts>=?",
                [self.project, now, MAX_ATTEMPTS],
            ).fetchall()
            for row in expired:
                tx.execute(
                    "UPDATE memory_source_checks SET "
                    "state='failed',failure='lease expired',generation=generation+1 "
                    "WHERE project_id=? AND id=?",
                    [self.project, row["id"]],
                )
                tx.execute(
                    "UPDATE memory_freshness SET "
                    "review_reason=coalesce(review_reason,'failed source checks'),"
                    "revision=revision+1 WHERE project_id=? AND memory_id=?",
                    [self.project, row["memory_id"]],
                )
                tx.change("memory.review", row["memory_id"], {"reason": "failed source checks"})
            active = tx.execute(
                "SELECT 1 FROM memory_source_checks WHERE project_id=? AND state='claimed' "
                "AND lease_until_us>?",
                [self.project, now],
            ).fetchone()
            row = (
                None
                if active
                else tx.execute(
                    "SELECT c.*,f.revision FROM memory_source_checks c JOIN memory_freshness f "
                    "ON f.project_id=c.project_id AND f.memory_id=c.memory_id WHERE c.project_id=? "
                    "AND ((c.state='pending' AND c.due_us<=?) OR "
                    "(c.state='claimed' AND c.lease_until_us<=?)) "
                    "ORDER BY c.due_us,c.id LIMIT 1",
                    [self.project, now, now],
                ).fetchone()
            )
            tx.audit("source.claim", row["id"] if row else "queue", {"expired": len(expired)})
            if not row:
                return {"job": None}
            tx.execute(
                "UPDATE memory_source_checks SET state='claimed',generation=generation+1,"
                "lease_until_us=?,claimant=?,target_revision=?,attempts=attempts+1 "
                "WHERE project_id=? AND id=?",
                [now + LEASE_US, actor, row["revision"], self.project, row["id"]],
            )
            return {
                "job": {
                    "id": row["id"],
                    "generation": row["generation"] + 1,
                    "target_revision": row["revision"],
                    "source": json.loads(row["source"]),
                    "lease_until_us": now + LEASE_US,
                }
            }

        return self._mutate(actor, job)

    def source_check_complete(
        self,
        actor,
        job_id,
        generation,
        target_revision,
        observed_fingerprint=None,
        failure=None,
        retry_after_seconds=None,
    ):
        if any(type(v) is not int or v < 1 for v in (generation, target_revision)):
            raise ValueError("positive integer generation and target_revision required")
        if (observed_fingerprint is None) == (failure is None):
            raise ValueError("provide exactly one fingerprint or failure")
        if observed_fingerprint is not None:
            fingerprint(observed_fingerprint)
        if failure is not None and failure not in (
            "unavailable",
            "timeout",
            "overloaded",
            "invalid response",
        ):
            raise ValueError("invalid failure category")
        if retry_after_seconds is not None and (
            type(retry_after_seconds) is not int or not 0 <= retry_after_seconds <= 86400
        ):
            raise ValueError("invalid retry delay")

        def job(tx):
            request = encoded(
                dict(
                    target_revision=target_revision,
                    observed_fingerprint=observed_fingerprint,
                    failure=failure,
                    retry_after_seconds=retry_after_seconds,
                )
            )
            prior = tx.execute(
                "SELECT * FROM source_check_results WHERE project_id=? AND "
                "job_id=? AND generation=?",
                [self.project, job_id, generation],
            ).fetchone()
            if prior:
                if prior["actor"] != actor or prior["request"] != request:
                    raise Stale("completion differs from original result")
                return json.loads(prior["result"])
            now = now_us()
            row = tx.execute(
                "SELECT c.*,f.revision,m.revoked,m.superseded_by FROM memory_source_checks c "
                "JOIN memory_freshness f ON f.project_id=c.project_id AND f.memory_id=c.memory_id "
                "JOIN memory_records m ON m.project_id=c.project_id AND m.id=c.memory_id "
                "WHERE c.project_id=? AND c.id=?",
                [self.project, job_id],
            ).fetchone()
            if (
                not row
                or row["state"] != "claimed"
                or row["claimant"] != actor
                or row["generation"] != generation
                or row["lease_until_us"] <= now
                or row["target_revision"] != target_revision
                or row["revision"] != target_revision
                or row["revoked"]
                or row["superseded_by"]
            ):
                raise Stale("expired claim or changed target revision")
            reason = (
                "failed source checks"
                if failure
                # No baseline: the first observation becomes it; earlier changes go unseen.
                else (
                    "source changed"
                    if row["baseline"] is not None and observed_fingerprint != row["baseline"]
                    else None
                )
            )
            if reason:
                tx.execute(
                    "UPDATE memory_freshness SET review_reason=CASE WHEN review_reason IN "
                    "('conflicting evidence','source changed') THEN "
                    "review_reason ELSE ? END,revision=revision+1 "
                    "WHERE project_id=? AND memory_id=?",
                    [reason, self.project, row["memory_id"]],
                )
                tx.change("memory.review", row["memory_id"], {"reason": reason})
            # Source equality never confirms the claim or clears an existing review.
            interval = max(60, min(86400, int(os.environ.get("HUB_CHECK_INTERVAL_SECONDS", "900"))))
            delay = (
                max(
                    retry_after_seconds or 0,
                    min(3600, 15 * 2 ** row["attempts"]) + random.randrange(16),
                )
                if failure
                else interval
            )
            state = "failed" if failure and row["attempts"] >= MAX_ATTEMPTS else "pending"
            tx.execute(
                "UPDATE memory_source_checks SET "
                "state=?,due_us=?,lease_until_us=NULL,claimant=NULL,"
                "checked_us=?,observed_fingerprint=?,failure=?,attempts=?,"
                "baseline=coalesce(baseline,?) "
                "WHERE project_id=? AND id=?",
                [
                    state,
                    now + delay * 1_000_000,
                    now,
                    observed_fingerprint,
                    failure,
                    row["attempts"] if failure else 0,
                    observed_fingerprint,
                    self.project,
                    job_id,
                ],
            )
            tx.audit("source.complete", job_id, {"state": state, "reason": reason})
            result = {"id": job_id, "state": state, "reason": reason}
            tx.execute(
                "INSERT INTO source_check_results VALUES (?,?,?,?,?,?)",
                [self.project, job_id, generation, actor, request, encoded(result)],
            )
            return result

        return self._mutate(actor, job)

    def memory_source_retry(self, actor, job_id, expected_revision, baseline=None):
        if baseline is not None:
            fingerprint(baseline)

        def job(tx):
            row = tx.execute(
                "SELECT * FROM memory_source_checks WHERE project_id=? AND id=?",
                [self.project, job_id],
            ).fetchone()
            if not row:
                raise ValueError("unknown source binding")
            self._review_owned(tx, actor, row["memory_id"], expected_revision)
            tx.execute(
                "UPDATE memory_source_checks SET state='pending',generation=generation+1,"
                "attempts=0,due_us=?,baseline=?,lease_until_us=NULL WHERE project_id=? AND id=?",
                [now_us(), baseline or row["baseline"], self.project, job_id],
            )
            tx.execute(
                "UPDATE memory_freshness SET revision=revision+1 WHERE "
                "project_id=? AND memory_id=?",
                [self.project, row["memory_id"]],
            )
            tx.audit("source.retry", job_id, {})
            return {"id": job_id}

        return self._mutate(actor, job)

    def source_check_status(self, actor):
        def read(db):
            row = db.execute(
                "SELECT count(*) FILTER(WHERE state='pending'),min(due_us) "
                "FILTER(WHERE state='pending'),"
                "count(*) FILTER(WHERE state='failed'),count(*) "
                "FILTER(WHERE state='claimed' AND lease_until_us<=?) "
                "FROM memory_source_checks WHERE project_id=?",
                [now_us(), self.project],
            ).fetchone()
            return dict(
                queue_depth=row[0],
                oldest_pending_age_us=max(0, now_us() - row[1]) if row[1] else 0,
                failures=row[2],
                expired_claims=row[3],
                writer=self.store.write_metrics(),
            )

        return self.store.read(read)
