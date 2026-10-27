"""Memory contracts ported from tests/test_durable.py: sources, revisions, privacy, no-memory."""

import os
import tempfile
import unittest

from hub import identity
from hub.store import Store, encoded, migrate
from hub.work import Work

AGENT, OTHER = "worker", "reviewer"


class MemoryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        path = os.path.join(self.tmp.name, "hub.sqlite3")
        migrate(path)
        self.s = Store(path)
        self.s.create_project("p1", "one", "operator")
        self.s.create_project("p2", "two", "operator")
        self.w = Work(self.s, "p1")

    def tearDown(self):
        self.s.close()
        self.tmp.cleanup()

    def memory(self, text="fact", actor=AGENT, **kw):
        return self.w.remember(actor, "project", "fact", text, "tested", 1, ["test://e"], **kw)[
            "id"
        ]

    def session(self, task):
        s = self.w.resume(AGENT, task)
        return s, dict(actor=AGENT, session_id=s["session"]["session_id"], generation=1)

    def test_memory_requires_source(self):
        for evidence in ([], [" "], [None], "test://e"):
            with self.assertRaisesRegex(ValueError, "source"):
                self.w.remember(AGENT, "ns", "fact", "value", "tested", 1, evidence)
        with self.assertRaisesRegex(ValueError, "provenance"):
            self.w.remember(AGENT, "ns", "fact", "value", "guessed", 1, ["x"])

    def test_no_memory_keeps_execution_state(self):
        ident = self.memory()
        task = self.w.create_task(AGENT, "quiet", [], no_memory=True)["id"]
        packet, fence = self.session(task)
        self.assertNotIn("memory", packet)
        self.assertIsNone(self.memory("during quiet task"))
        self.assertEqual(self.w.boot_card(AGENT), [])
        with self.assertRaisesRegex(ValueError, "ownership"):
            self.memory(actor=OTHER, task_id=task)
        self.w.checkpoint(
            **fence,
            completed="c",
            evidence=[],
            open_questions=[],
            workspace_revision="r",
            pending_actions=[],
            next_step="n",
        )
        self.assertTrue(self.s.read(lambda con: self.w._task(con, task))["checkpoint"])
        self.assertTrue(self.w.record(AGENT, ident))  # the governance archive remains

    def test_packet_carries_bounded_boot_card(self):
        for _ in range(100):
            self.memory("雪" * 2000, hook="雪" * 100)
        task = self.w.create_task(AGENT, "goal", [])["id"]
        packet, _ = self.session(task)
        self.assertLessEqual(len(encoded(packet).encode()), 8192)
        self.assertTrue(0 < len(packet["memory"]) <= 40)

    def test_explicit_revision_keeps_independent_and_opposing_facts(self):
        first = self.memory("one")
        second = self.memory("opposing")
        self.assertIsNone(self.w.record(AGENT, first)["superseded_by"])
        revised = self.w.revise_memory(AGENT, first, "corrected", "tested", 1, ["test://r"])["id"]
        self.assertEqual(self.w.record(AGENT, first)["superseded_by"], revised)
        self.assertIsNone(self.w.record(AGENT, second)["superseded_by"])
        with self.assertRaisesRegex(ValueError, "active record"):
            self.memory("again", supersedes=first)
        with self.assertRaisesRegex(ValueError, "owned"):
            self.w.revise_memory(OTHER, second, "hijack", "tested", 1, ["x"])
        self.assertEqual(len(self.w.boot_card(AGENT)), 2)  # superseded records leave the card

    def test_changes_replay_and_revocation(self):
        first = self.w.changes(AGENT)["cursor"]
        ident = self.memory()
        with self.assertRaisesRegex(ValueError, "owned"):
            self.w.revoke_memory(OTHER, ident)
        self.w.revoke_memory(AGENT, ident)
        a = self.w.changes(AGENT, first, limit=1)
        self.assertEqual(a, self.w.changes(AGENT, first, limit=1))
        b = self.w.changes(AGENT, a["cursor"])
        self.assertEqual(b["items"][0]["operation"], "revoke")
        self.assertTrue(self.w.record(OTHER, ident)["revoked"])
        self.assertEqual(self.w.boot_card(AGENT), [])

    def test_private_memory_and_its_changes_stay_private(self):
        ident = self.memory("secret", visibility="private")
        self.w.revoke_memory(AGENT, ident)
        self.assertIsNone(self.w.record(OTHER, ident))
        self.assertTrue(self.w.record(AGENT, ident))
        self.assertNotIn(ident, {i["id"] for i in self.w.changes(OTHER, limit=1000)["items"]})
        self.assertIn(ident, {i["id"] for i in self.w.changes(AGENT, limit=1000)["items"]})
        with self.assertRaisesRegex(ValueError, "owned"):
            self.w.revise_memory(OTHER, ident, "x", "tested", 1, ["x"])
        with self.assertRaisesRegex(ValueError, "owned"):  # maintainers never reach private memory
            self.w.revoke_memory(OTHER, ident, maintainer=True)

    def test_maintainer_revokes_project_memory(self):
        ident = self.memory("shared mistake")
        self.w.revoke_memory(OTHER, ident, maintainer=True)
        self.assertTrue(self.w.record(AGENT, ident)["revoked"])

    def test_memory_is_project_scoped(self):
        ident = self.memory("p1 only")
        other = Work(self.s, "p2")
        self.assertIsNone(other.record(AGENT, ident))
        self.assertEqual(other.boot_card(AGENT), [])
        with self.assertRaisesRegex(ValueError, "owned"):
            other.revoke_memory(AGENT, ident)


class HumanOwnershipTest(unittest.TestCase):
    """Agents write for the human they act for; the agent and its session are attribution."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        path = os.path.join(self.tmp.name, "hub.sqlite3")
        migrate(path)
        self.s = Store(path)
        identity.bootstrap(self.s, "root")
        identity.create_project(self.s, "root", "p1", "one")
        for name, kind in (("ann", "human"), ("bob", "human"), ("claude", "agent")):
            identity.create_principal(self.s, "root", name, kind)
        identity.create_principal(self.s, "root", "codex", "agent", acts_for="ann")
        identity.create_principal(self.s, "root", "stray", "agent", acts_for="bob")
        for human in ("ann", "bob"):
            identity.grant(self.s, "root", human, "p1", "maintainer")
        self.w = Work(self.s, "p1", agent_session="codex-thread-1")

    def tearDown(self):
        self.s.close()
        self.tmp.cleanup()

    def memory(self, actor, **kw):
        return self.w.remember(actor, "ops", "fact", "body", "tested", 1, ["test:e"], **kw)["id"]

    def test_unbound_agent_reads_but_cannot_write(self):
        with self.assertRaisesRegex(ValueError, "bound to a human"):
            self.memory("claude")
        self.assertIsNone(
            Work(self.s, "p1").record("claude", self.memory("codex", visibility="private"))
        )

    def test_agents_of_one_human_share_ownership_with_attribution(self):
        moved = identity.bind(self.s, "root", "claude", "ann")
        self.assertEqual(moved["acts_for"], "ann")
        shared = self.memory("codex")
        private = self.memory("codex", visibility="private")
        record = self.w.record("claude", private)
        self.assertEqual(
            (record["owner"], record["author"], record["agent_session"]),
            ("ann", "codex", "codex-thread-1"),
        )
        self.assertEqual(self.w.record("ann", private)["id"], private)  # the human sees it too
        revised = self.w.revise_memory("claude", shared, "newer", "tested", 1, ["test:f"])["id"]
        self.assertEqual(self.w.record("ann", revised)["author"], "claude")
        self.w.revoke_memory("claude", private)
        self.assertTrue(self.w.record("codex", private)["revoked"])

    def test_another_humans_agent_has_no_ownership(self):
        private = self.memory("codex", visibility="private")
        shared = self.memory("codex")
        self.assertIsNone(self.w.record("stray", private))
        with self.assertRaisesRegex(ValueError, "owned"):
            self.w.revise_memory("stray", shared, "x", "tested", 1, ["test:x"])
        with self.assertRaisesRegex(ValueError, "owned"):
            self.w.revoke_memory("stray", private)

    def test_owner_must_be_a_project_maintainer(self):
        identity.grant(self.s, "root", "ann", "p1", "maintainer", revoke=True)
        with self.assertRaisesRegex(ValueError, "maintainer"):
            self.memory("codex")

    def test_bind_adopts_unowned_records_and_rebinding_keeps_history(self):
        with self.assertRaisesRegex(ValueError, "only an agent"):
            identity.bind(self.s, "root", "claude", "codex")
        with self.assertRaisesRegex(ValueError, "only an agent"):
            identity.bind(self.s, "root", "ann", "bob")

        # A record written before the binding existed (owner = author, as the migration sets it).
        def legacy(tx):
            tx.execute(
                "INSERT INTO memory_records (project_id, id, namespace, kind, body, hook, "
                "provenance, confidence, author, evidence, visibility, created_us, owner) "
                "VALUES ('p1', 'old', 'ops', 'fact', 'b', 'b', 'tested', 1, 'claude', "
                "'[\"test:e\"]', 'private', 0, 'claude')"
            )
            tx.audit("write", "old", {})

        self.s.mutate("p1", "claude", legacy)
        self.assertEqual(identity.bind(self.s, "root", "claude", "ann")["records"], 1)
        self.assertEqual(self.w.record("codex", "old")["owner"], "ann")
        identity.bind(self.s, "root", "claude", "bob")
        self.assertEqual(self.w.record("ann", "old")["owner"], "ann")  # history stays with ann
        self.assertIsNone(self.w.record("claude", "old"))


if __name__ == "__main__":
    unittest.main()
