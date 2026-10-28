"""Temporal assessment and review, separate from trust and immutable memory content."""

import json
import uuid

from hub.common import Stale, references
from hub.store import encoded, now_us

KINDS = ("unclassified", "durable", "changing", "historical")


def validate(kind, observed, due, claim):
    if kind not in KINDS:
        raise ValueError("invalid temporal_kind")
    for value in (observed, due):
        if value is not None and (type(value) is not int or value <= 0):
            raise ValueError("timestamps must be positive integer microseconds")
    if claim is not None and (not isinstance(claim, str) or not claim.strip() or len(claim) > 128):
        raise ValueError("claim_key must be 1 to 128 characters")
    if kind == "changing" and (due is None or claim is None):
        raise ValueError("changing state requires review_due_us and claim_key")


def details(db, project, ident):
    # Copies inherit the source assessment, including deadlines, without inheriting trust.
    source = db.execute(
        "SELECT source_project,source_id FROM publications WHERE library_project=? "
        "AND dest_id=? AND status='published'",
        [project, ident],
    ).fetchone()
    if source:
        project, ident = source
    row = db.execute(
        "SELECT * FROM memory_freshness WHERE project_id=? AND memory_id=?", [project, ident]
    ).fetchone()
    data = (
        dict(row)
        if row
        else dict(
            temporal_kind="unclassified",
            revision=1,
            observed_us=None,
            checked_us=None,
            review_due_us=None,
            reminder_us=None,
            claim_key=None,
            review_reason=None,
            review_evidence="[]",
            proposed_correction=None,
        )
    )
    reasons = []
    if data["temporal_kind"] == "unclassified":
        reasons.append("unassessed")
    if data["review_due_us"] is not None and data["review_due_us"] <= now_us():
        reasons.append("overdue")
    if data["review_reason"]:
        reasons.append(data["review_reason"])
    status = (
        "historical"
        if data["temporal_kind"] == "historical"
        else "review required"
        if any(r not in ("unassessed", "failed source checks") for r in reasons)
        else "freshness unknown"
        if data["temporal_kind"] == "unclassified"
        else "current"
    )
    result = {
        k: data[k]
        for k in (
            "temporal_kind",
            "observed_us",
            "checked_us",
            "review_due_us",
            "reminder_us",
            "claim_key",
            "proposed_correction",
        )
    } | {
        "freshness_revision": data["revision"],
        "freshness": status,
        "review_reasons": reasons,
        "review_evidence": json.loads(data["review_evidence"]),
    }

    latest = db.execute(
        "SELECT max(checked_us) FROM memory_source_checks WHERE project_id=? AND memory_id=?",
        [project, ident],
    ).fetchone()[0]
    result["source_checked_us"] = latest
    if source:
        # The destination grant does not grant access to source evidence or proposed prose.
        result.update(claim_key=None, proposed_correction=None, review_evidence=[])
    return result


def eligibility(view):
    if view not in ("current", "history", "all"):
        raise ValueError("view must be current, history or all")
    if view == "all":
        return ""
    current = """(f.kind='solution' OR (f.kind='memory'
        AND coalesce(mf.temporal_kind,'unclassified')<>'historical'
        AND (mf.review_due_us IS NULL OR mf.review_due_us>FRESHNESS_NOW)
        AND (mf.review_reason IS NULL OR mf.review_reason='failed source checks')))""".replace(
        "FRESHNESS_NOW", str(now_us())
    )
    return " AND " + (current if view == "current" else "NOT " + current)


class Freshness:
    def memory_claim_get(self, actor, namespace, claim_key, visibility="project"):
        if visibility not in ("project", "private"):
            raise ValueError("invalid visibility")

        def read(db):
            if not self._memory_allowed(db, actor):
                return None
            row = db.execute(
                "SELECT memory_id FROM memory_freshness WHERE project_id=? "
                "AND owner=? AND namespace=? AND visibility=? AND claim_key=? AND active=1",
                [self.project, self._owner(db, actor), namespace, visibility, claim_key],
            ).fetchone()
            return self._memory_row(db, row[0]) if row else None

        return self.store.read(read)

    def _review_owned(self, tx, actor, memory_id, expected_revision):
        if not self._memory_allowed(tx, actor):
            raise ValueError("memory disabled")
        if tx.execute(
            "SELECT 1 FROM publications WHERE library_project=? AND dest_id=?",
            [self.project, memory_id],
        ).fetchone():
            raise ValueError("review the publication source")
        record = self._memory_row(tx, memory_id)
        if (
            not record
            or record["owner"] != self._owner(tx, actor, write=True)
            or record["revoked"]
            or record["superseded_by"]
        ):
            raise ValueError("active owned record required")
        if type(expected_revision) is not int or record["freshness_revision"] != expected_revision:
            raise Stale("freshness revision changed")
        return record

    def memory_review_list(self, actor, reason=None, limit=100, after=""):
        if type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError("limit must be 1 to 200")
        if reason not in (
            None,
            "unassessed",
            "overdue",
            "source changed",
            "conflicting evidence",
            "failed source checks",
        ):
            raise ValueError("invalid review reason")

        def read(db):
            if not self._memory_allowed(db, actor):
                return []
            owner = self._owner(db, actor)
            rows = db.execute(
                "SELECT id FROM memory_records WHERE project_id=? AND id>? "
                "AND NOT revoked AND superseded_by IS NULL AND (visibility='project' OR owner=?) "
                "ORDER BY id",
                [self.project, after, owner],
            )
            out = []
            for row in rows:
                record = self._memory_row(db, row[0])
                from hub.library import disclosable

                if not disclosable(db, self.project, row[0], actor=actor):
                    continue
                if record["reminder_us"] is not None and record["reminder_us"] > now_us():
                    continue  # deferred: hidden from the inbox, still not current
                if record["review_reasons"] and (
                    reason is None or reason in record["review_reasons"]
                ):
                    record["sources"] = [
                        dict(r)
                        for r in db.execute(
                            "SELECT "
                            "id,source,baseline,observed_fingerprint,checked_us,state,failure "
                            "FROM memory_source_checks WHERE project_id=? AND memory_id=?",
                            [self.project, row[0]],
                        )
                    ]
                    record["replacements"] = [
                        r[0]
                        for r in db.execute(
                            "SELECT id FROM memory_records WHERE project_id=? AND superseded_by=?",
                            [self.project, row[0]],
                        )
                    ]
                    out.append(record)
                    if len(out) == limit:
                        break
            return out

        return self.store.read(read)

    def memory_review(
        self,
        actor,
        memory_id,
        expected_revision,
        action,
        evidence=None,
        temporal_kind=None,
        observed_us=None,
        review_due_us=None,
        claim_key=None,
        reminder_us=None,
        proposed_correction=None,
    ):
        if action not in ("confirm", "classify", "historical", "retire", "defer", "conflict"):
            raise ValueError("invalid review action")
        if not references(evidence or []) or (action in ("confirm", "conflict") and not evidence):
            raise ValueError("evidence references required")
        if proposed_correction is not None and (
            not isinstance(proposed_correction, str) or len(proposed_correction) > 262144
        ):
            raise ValueError("invalid proposed correction")

        def job(tx):
            old = self._review_owned(tx, actor, memory_id, expected_revision)
            kind = "historical" if action == "historical" else temporal_kind or old["temporal_kind"]
            due = review_due_us if review_due_us is not None else old["review_due_us"]
            observed = observed_us if observed_us is not None else old["observed_us"]
            claim = claim_key if claim_key is not None else old["claim_key"]
            if (
                action not in ("confirm", "historical", "defer")
                and old["review_due_us"] is not None
                and due != old["review_due_us"]
            ):
                raise ValueError("renewing a deadline requires confirmation with evidence")
            validate(kind, observed, due, claim)
            if action == "confirm" and (
                kind == "unclassified" or (due is not None and due <= now_us())
            ):
                raise ValueError(
                    "confirmation requires classification and a future deadline if present"
                )
            reason = old["review_reasons"]
            reason = next((r for r in reason if r not in ("unassessed", "overdue")), None)
            checked = old["checked_us"]
            if action == "confirm":
                reason, checked = None, now_us()
            elif action == "conflict":
                reason = "conflicting evidence"
            elif action == "defer":
                if type(reminder_us) is not int or reminder_us <= now_us():
                    raise ValueError("deferral requires a future reminder_us")
                # Deferral cannot reclassify, renew a deadline or clear an evidence flag.
                kind, due, observed, claim = (
                    old[k] for k in ("temporal_kind", "review_due_us", "observed_us", "claim_key")
                )
            review_evidence = evidence or old["review_evidence"]
            correction = (
                proposed_correction
                if proposed_correction is not None
                else old["proposed_correction"]
            )
            if action == "defer":
                review_evidence, correction = old["review_evidence"], old["proposed_correction"]
            elif action == "confirm":
                correction = None
            tx.execute(
                "UPDATE memory_freshness SET revision=revision+1,temporal_kind=?, "
                "observed_us=?,checked_us=?,review_due_us=?,claim_key=?,reminder_us=?, "
                "review_reason=?,review_evidence=?,proposed_correction=? "
                "WHERE project_id=? AND memory_id=?",
                [
                    kind,
                    observed,
                    checked,
                    due,
                    claim,
                    reminder_us,
                    reason,
                    encoded(review_evidence),
                    correction,
                    self.project,
                    memory_id,
                ],
            )
            if action == "retire":
                self._revoke(tx, memory_id)
            tx.audit("memory.review", memory_id, {"action": action})
            tx.change("memory.review", memory_id, {"revision": expected_revision + 1})
            return self._memory_row(tx, memory_id)

        return self._mutate(actor, job)

    def memory_review_bulk(
        self,
        actor,
        records,
        action,
        preview=True,
        temporal_kind=None,
        reminder_us=None,
        preview_token=None,
    ):
        if (
            action not in ("classify", "historical", "defer")
            or not isinstance(records, list)
            or not 1 <= len(records) <= 100
        ):
            raise ValueError("bulk review allows 1 to 100 classifications or deferrals")
        if type(preview) is not bool:
            raise ValueError("preview must be a boolean")
        if not all(
            isinstance(r, dict)
            and set(r) == {"memory_id", "expected_revision"}
            and isinstance(r["memory_id"], str)
            and type(r["expected_revision"]) is int
            for r in records
        ):
            raise ValueError("records require memory_id and expected_revision")
        if len({r["memory_id"] for r in records}) != len(records):
            raise ValueError("duplicate record")

        # A durable token binds approval to the exact previewed revisions and action.
        # Each execution is one transaction; no partially applied bulk operation.
        def job(tx):
            request = encoded(
                dict(
                    records=records,
                    action=action,
                    temporal_kind=temporal_kind,
                    reminder_us=reminder_us,
                )
            )
            token = str(uuid.uuid4()) if preview else preview_token
            if not preview:
                prior = tx.execute(
                    "SELECT * FROM memory_review_previews WHERE project_id=? AND token=?",
                    [self.project, token],
                ).fetchone()
                if (
                    not prior
                    or prior["actor"] != actor
                    or prior["request"] != request
                    or prior["expires_us"] <= now_us()
                ):
                    raise Stale("matching unexpired preview required")
            found = [
                self._review_owned(tx, actor, r["memory_id"], r["expected_revision"])
                for r in records
            ]
            if action == "classify" and temporal_kind not in (
                "durable",
                "historical",
                "unclassified",
            ):
                raise ValueError("bulk classification requires durable, historical or unclassified")
            if action == "defer" and (type(reminder_us) is not int or reminder_us <= now_us()):
                raise ValueError("future reminder required")
            if not preview:
                for r in found:
                    if action == "defer":
                        tx.execute(
                            "UPDATE memory_freshness SET reminder_us=?,revision=revision+1 "
                            "WHERE project_id=? AND memory_id=?",
                            [reminder_us, self.project, r["id"]],
                        )
                    else:
                        tx.execute(
                            "UPDATE memory_freshness SET temporal_kind=?,revision=revision+1 "
                            "WHERE project_id=? AND memory_id=?",
                            [
                                "historical" if action == "historical" else temporal_kind,
                                self.project,
                                r["id"],
                            ],
                        )
                    tx.change("memory.review", r["id"], {"action": action})
            if preview:
                tx.execute(
                    "INSERT INTO memory_review_previews VALUES (?,?,?,?,?)",
                    [self.project, token, actor, request, now_us() + 900_000_000],
                )
            else:
                tx.execute(
                    "DELETE FROM memory_review_previews WHERE project_id=? AND token=?",
                    [self.project, token],
                )
            tx.audit(
                "memory.review.preview" if preview else "memory.review.bulk",
                token,
                {"count": len(found), "action": action},
            )
            return {"preview": preview, "preview_token": token, "action": action, "records": found}

        return self._mutate(actor, job)
