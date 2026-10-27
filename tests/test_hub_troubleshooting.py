"""Synthetic incidents only: concurrency, project isolation, fencing and recovery."""

import sqlite3
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from hub import api
from hub.common import NotFound, Stale
from hub.identity import Principal
from hub.work import Work
from tests import test_hub_work as fixtures


class TroubleshootingTest(unittest.TestCase):
    setUp = fixtures.WorkTest.setUp
    tearDown = fixtures.WorkTest.tearDown
    open = fixtures.WorkTest.open
    session = fixtures.WorkTest.session
    expire = fixtures.WorkTest.expire
    stored_task = fixtures.WorkTest.stored_task

    def incident(self, target="CT:122"):
        return self.w.tshoot_open("claude", target)["id"]

    def reservation(self, resource="ct:122"):
        thread = self.incident()
        _, f = self.session()
        action = self.w.tshoot_action_reserve(
            **f, thread_id=thread, resource=resource, intent="test"
        )
        return thread, action["id"], f

    def test_concurrent_open_append_and_pagination(self):
        def join(i):
            return self.w.tshoot_open("agent-" + str(i), "  CT:122  ")

        with ThreadPoolExecutor(max_workers=8) as pool:
            opened = list(pool.map(join, range(20)))
        self.assertEqual(len({t["id"] for t in opened}), 1)
        ident = opened[0]["id"]
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(
                pool.map(
                    lambda i: self.w.tshoot_append(
                        "agent-" + str(i), ident, "finding", "observed", ["synthetic:source"]
                    ),
                    range(20),
                )
            )
        first = self.w.tshoot_read("reader", ident, limit=20)
        second = self.w.tshoot_read("reader", ident, cursor=first["cursor"], limit=20)
        self.assertEqual(len(first["events"]) + len(second["events"]), 40)
        self.assertEqual(len(first["participants"]), 20)
        self.assertLess(first["cursor"], second["cursor"])
        self.assertEqual(len({e["seq"] for e in first["events"] + second["events"]}), 40)

    def test_new_incident_links_resolved_predecessor(self):
        ident = self.incident()
        with self.assertRaises(ValueError):
            self.w.tshoot_close("claude", ident, "fixed", [])
        self.w.tshoot_close("claude", ident, "fixed", ["synthetic:check"])
        new = self.w.tshoot_open("codex", "ct:122")
        self.assertEqual(new["predecessor"], ident)
        self.assertNotEqual(new["id"], ident)
        with self.assertRaisesRegex(ValueError, "resolved"):
            self.w.tshoot_append("claude", ident, "finding", "late", [])

    def test_cross_project_and_private_work(self):
        ident = self.incident()
        with self.assertRaises(NotFound):
            Work(self.s, "p2").tshoot_read("claude", ident)
        p = Principal("reader", "agent", False, "test", {"p1": frozenset({"reader"})})
        with self.assertRaises(api.Denied):
            api.call(self.s, p, "p2", "tshoot_read", {"thread_id": ident})
        with self.assertRaises(api.Denied):
            api.call(self.s, p, "p1", "tshoot_open", {"target": "x"}, "once")
        self.w.tshoot_open("worker", "ct:122")
        self.assertEqual(self.stored_task()["owner"], "worker")
        self.assertIsNone(self.stored_task()["agent"])

    def test_event_cursors_do_not_reveal_other_project_activity(self):
        one = self.incident()
        first = self.w.tshoot_read("reader", one)["cursor"]
        Work(self.s, "p2").tshoot_open("reader", "unrelated")
        event = self.w.tshoot_append("claude", one, "finding", "next", ["synthetic:source"])
        self.assertEqual(event["seq"], first + 1)

    def test_authenticated_authorship_and_idempotency(self):
        p = Principal("claude", "agent", False, "test", {"p1": frozenset({"contributor"})})
        args = {"target": "ct:122", "actor": "forged", "author": "forged"}
        t = api.call(self.s, p, "p1", "tshoot_open", args, "open")
        self.assertEqual(t, api.call(self.s, p, "p1", "tshoot_open", args, "open"))
        events = self.w.tshoot_read("codex", t["id"])["events"]
        self.assertEqual([e["actor"] for e in events], ["claude"])
        with self.assertRaises(api.Denied):
            api.call(self.s, p, "p1", "tshoot_append", {})

    def test_resource_exclusion_across_threads(self):
        thread, ident, f = self.reservation()
        another = self.incident("service:hub")
        with self.assertRaises(sqlite3.IntegrityError):
            self.w.tshoot_action_reserve(**f, thread_id=another, resource="ct:122", intent="test")
        self.w.tshoot_action_reserve(**f, thread_id=another, resource="ct:123", intent="test")
        read = self.w.tshoot_read("codex", thread)
        self.assertEqual(read["actions"][0]["id"], ident)
        self.assertNotIn("task_id", read["actions"][0])
        self.assertNotIn("session_id", read["actions"][0])

    def expire_reservation(self):
        self.expire()

        def expire(tx):
            tx.execute("UPDATE troubleshooting_actions SET expires_us=0 WHERE project_id=?", ["p1"])
            tx.audit("synthetic.expire", "reservation", {})
            return {}

        self.s.mutate("p1", "test", expire)

    def test_started_expiry_blocks_replay_close_and_reserve(self):
        thread, ident, f = self.reservation()
        self.w.tshoot_action_start(**f, action_id=ident)
        with self.assertRaisesRegex(ValueError, "replay"):
            self.w.tshoot_action_start(**f, action_id=ident)
        self.expire_reservation()
        _, new = self.session()
        self.assertEqual(
            self.w.tshoot_read("reader", thread)["actions"][0]["status"], "outcome-unknown"
        )
        with self.assertRaises(Stale):
            self.w.tshoot_action_start(**f, action_id=ident)
        with self.assertRaises(Stale):
            self.w.tshoot_action_start(**new, action_id=ident)
        with self.assertRaises(sqlite3.IntegrityError):
            self.w.tshoot_action_reserve(**new, thread_id=thread, resource="ct:122", intent="retry")
        with self.assertRaisesRegex(ValueError, "uncertain"):
            self.w.tshoot_close("claude", thread, "done", ["synthetic:check"])
        with self.assertRaises(ValueError):
            self.w.tshoot_action_reconcile(**new, action_id=ident, status="completed", evidence=[])
        self.w.tshoot_action_reconcile(
            **new, action_id=ident, status="completed", evidence=["synthetic:external-inspection"]
        )
        self.w.tshoot_close("claude", thread, "done", ["synthetic:check"])

    def test_concurrent_resource_reservations_and_start_idempotency(self):
        thread = self.incident()
        _, first = self.session()
        task = self.w.create_task("codex", "independent", [])
        session = self.w.resume("codex", task["id"])["session"]
        second = dict(
            actor="codex", session_id=session["session_id"], generation=session["generation"]
        )

        def reserve(f):
            try:
                return self.w.tshoot_action_reserve(
                    **f, thread_id=thread, resource="CT:122", intent="check"
                )
            except sqlite3.IntegrityError:
                return None

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(reserve, [first, second]))
        self.assertEqual(sum(r is not None for r in results), 1)
        index = next(i for i, r in enumerate(results) if r is not None)
        f = [first, second][index]
        principal = Principal(
            f["actor"], "agent", False, "test", {"p1": frozenset({"contributor"})}
        )
        args = {k: v for k, v in f.items() if k != "actor"}
        args["action_id"] = results[index]["id"]
        once = api.call(self.s, principal, "p1", "tshoot_action_start", args, "start-once")
        self.assertEqual(
            once, api.call(self.s, principal, "p1", "tshoot_action_start", args, "start-once")
        )
        self.assertEqual(
            sum(
                e["kind"] == "action.start" for e in self.w.tshoot_read("reader", thread)["events"]
            ),
            1,
        )

    def test_additive_migration_from_previous_schema(self):
        from hub import store

        path = Path(self.tmp.name) / "previous.sqlite3"
        with patch.object(store, "MIGRATIONS", store.MIGRATIONS[:10]):  # before troubleshooting
            store.migrate(path)
        self.assertEqual(store.migrate(path), store.SCHEMA_VERSION)
        with store.connect(path) as db:
            self.assertEqual(store.schema_version(db), store.SCHEMA_VERSION)
            self.assertIsNotNone(
                db.execute(
                    "SELECT name FROM sqlite_master WHERE name='troubleshooting_events'"
                ).fetchone()
            )

    def test_unused_expiry_releases_and_heartbeat_renews(self):
        thread, ident, f = self.reservation()
        self.w.tshoot_action_heartbeat(**f, action_id=ident)
        self.expire_reservation()
        _, new = self.session()
        replacement = self.w.tshoot_action_reserve(
            **new, thread_id=thread, resource="ct:122", intent="new"
        )
        self.assertNotEqual(ident, replacement["id"])
        with self.assertRaises(Stale):
            self.w.tshoot_action_start(**new, action_id=ident)

    def test_another_actor_cannot_reconcile_private_action(self):
        _, ident, f = self.reservation()
        self.w.tshoot_action_start(**f, action_id=ident)
        task = self.w.create_task("codex", "independent", [])
        packet = self.w.resume("codex", task["id"])
        s = packet["session"]
        with self.assertRaisesRegex(ValueError, "owned"):
            self.w.tshoot_action_reconcile(
                "codex", ident, s["session_id"], s["generation"], "completed", ["synthetic:check"]
            )

    def test_corrections_append_and_no_automatic_memory(self):
        ident = self.incident()
        e = self.w.tshoot_append("claude", ident, "finding", "old", ["synthetic:a"])
        self.w.tshoot_append("codex", ident, "finding", "corrected", ["synthetic:b"], e["seq"])
        rows = self.w.tshoot_read("claude", ident)["events"]
        self.assertEqual(rows[1]["body"], "old")
        self.assertEqual(rows[2]["corrects"], e["seq"])
        with self.assertRaises(ValueError):
            self.w.tshoot_append("codex", ident, "finding", "oops", [], 999)
        self.assertEqual(
            self.s.read(lambda db: db.execute("SELECT count(*) FROM memory_records").fetchone()[0]),
            0,
        )
