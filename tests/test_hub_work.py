"""Work contracts ported from tests/test_durable.py, plus cross-project isolation."""

import os
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from hub.store import Store, encoded, migrate
from hub.work import Work

AGENT, OTHER = "worker", "reviewer"


class WorkTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "hub.sqlite3")
        migrate(self.path)
        self.open()
        self.s.create_project("p1", "one", "operator")
        self.s.create_project("p2", "two", "operator")
        self.task = self.w.create_task(AGENT, "Implement API", ["tests pass"])["id"]

    def tearDown(self):
        self.s.close()
        self.tmp.cleanup()

    def open(self):
        self.s = Store(self.path)
        self.w = Work(self.s, "p1")

    def restart(self):
        self.s.close()
        self.open()

    def session(self):
        packet = self.w.resume(AGENT, self.task)
        s = packet["session"]
        return packet, dict(actor=AGENT, session_id=s["session_id"], generation=s["generation"])

    def checkpoint(self, fence):
        return self.w.checkpoint(
            **fence,
            completed="tests passed",
            evidence=["artifact:tests"],
            open_questions=[],
            workspace_revision="git:abc",
            pending_actions=[],
            next_step="review patch",
        )

    def message(self, message_type="response", content=None, evidence=()):
        return self.w.send_message(
            OTHER, AGENT, content or {}, self.task, message_type, list(evidence)
        )["id"]

    def expire(self):
        def job(tx):
            s = self.w._object(tx, "session", AGENT)
            s["expires_us"] = 0
            return self.w._put(tx, "session", s)

        self.s.mutate("p1", "test", job)

    def stored_task(self):
        return self.s.read(lambda con: self.w._task(con, self.task))

    def test_reopen_recovers_without_transcript_and_fences_old_writer(self):
        _, old = self.session()
        checkpoint = self.checkpoint(old)
        self.message("disagreement", {"positions": ["ship", "test first"]}, ["review"])
        self.expire()
        self.restart()
        packet, replacement = self.session()
        self.assertEqual(packet["checkpoint"]["id"], checkpoint["id"])
        self.assertEqual(packet["checkpoint"]["next_step"], "review patch")
        self.assertEqual(packet["disagreements"][0]["message_type"], "disagreement")
        with self.assertRaisesRegex(ValueError, "stale"):
            self.checkpoint(old)
        self.checkpoint(replacement)

    def test_packet_bound_unicode_and_large_history(self):
        for _ in range(100):
            self.message(content={"text": "雪" * 1000})
        packet, _ = self.session()
        self.assertLessEqual(len(encoded(packet).encode()), 8192)
        self.assertIn("references", packet)
        self.assertTrue(packet["messages"])
        with self.assertRaises(ValueError):
            self.w.create_task(AGENT, "goal", [], instructions="雪" * 3000)

    def test_started_action_becomes_uncertain_even_if_declared_idempotent(self):
        _, old = self.session()
        action = self.w.begin_action(**old, intent="send payment", idempotent=True)
        self.w.action_outcome(**old, action_id=action["id"], status="started", evidence=[])
        self.expire()
        packet, replacement = self.session()
        self.assertEqual(packet["actions"][0]["status"], "outcome-unknown")
        with self.assertRaisesRegex(ValueError, "reconciliation"):
            self.w.action_outcome(
                **replacement, action_id=action["id"], status="started", evidence=[]
            )
        self.w.action_outcome(
            **replacement, action_id=action["id"], status="completed", evidence=["receipt:123"]
        )

    def test_retry_budget_and_cancel_survive_restarts(self):
        for _ in range(4):
            self.session()
            self.expire()
            self.restart()
        with self.assertRaisesRegex(ValueError, "restart limit"):
            self.session()
        self.assertEqual(self.stored_task()["status"], "escalated")  # committed despite error
        self.w.cancel_task(AGENT, self.task)
        with self.assertRaisesRegex(ValueError, "stopped"):
            self.session()

    def test_checkpoint_turn_budget_survives_restarts(self):
        self.task = self.w.create_task(AGENT, "goal", [], turn_limit=1)["id"]
        _, fence = self.session()
        self.checkpoint(fence)
        self.w.finish(**fence, outcome="yielded", evidence=[])
        self.restart()
        with self.assertRaisesRegex(ValueError, "budget"):
            self.session()

    def test_explicit_ack_survives_session_replacement(self):
        ident = self.message()
        _, old = self.session()
        self.assertEqual(self.w.claim_messages(**old)[0]["id"], ident)
        self.expire()
        _, new = self.session()
        with self.assertRaises(ValueError):
            self.w.acknowledge(**old, message_id=ident)
        self.assertEqual(self.w.claim_messages(**new)[0]["id"], ident)
        self.w.acknowledge(**new, message_id=ident)
        self.assertEqual(self.w.claim_messages(**new), [])

    def test_work_state_is_scoped_to_the_agent(self):
        _, fence = self.session()
        self.checkpoint(fence)
        for kind in ("task", "session", "checkpoint"):
            self.assertTrue(self.w.work_read(AGENT, kind), kind)
            self.assertEqual(self.w.work_read(OTHER, kind), [], kind)

    def test_creator_claim_cancel_and_finish_retry(self):
        with self.assertRaisesRegex(ValueError, "ownership"):
            self.w.resume(OTHER, self.task)
        _, fence = self.session()
        self.w.cancel_task(AGENT, self.task)
        with self.assertRaisesRegex(ValueError, "stale"):
            self.w.finish(**fence, outcome="completed", evidence=[])
        self.assertEqual(self.stored_task()["status"], "cancelled")
        self.task = self.w.create_task(AGENT, "another", [])["id"]
        _, fence = self.session()
        first = self.w.finish(**fence, outcome="completed", evidence=["test:result"])
        self.assertEqual(
            first, self.w.finish(**fence, outcome="completed", evidence=["test:result"])
        )

    def test_private_work_is_absent_from_changes(self):
        _, fence = self.session()
        checkpoint = self.checkpoint(fence)
        message = self.message()
        ids = {self.task, checkpoint["id"], AGENT, message}
        mine = self.w.changes(AGENT)
        self.assertLessEqual(ids, {i["id"] for i in self.w.changes(AGENT, limit=1000)["items"]})
        self.assertEqual(mine, self.w.changes(AGENT))  # replayable
        theirs = self.w.changes("stranger", limit=1000)
        self.assertEqual({i["id"] for i in theirs["items"]}, {"p1"})
        self.assertEqual(theirs["cursor"], self.w.changes(AGENT, limit=1000)["cursor"])

    def test_acknowledging_disagreement_does_not_resolve_it(self):
        _, fence = self.session()
        ident = self.message("disagreement", {"positions": ["ship", "wait"]}, ["test:review"])
        self.w.acknowledge(**fence, message_id=ident)
        with self.assertRaisesRegex(ValueError, "disagreement"):
            self.w.finish(**fence, outcome="completed", evidence=[])
        self.w.finish(**fence, outcome="escalated", evidence=["test:review"])
        self.w.human_decision("operator", self.task, "wait", ["user:decision"], reopen=True)
        self.assertEqual(self.stored_task()["turns"], 0)
        self.assertEqual(len(self.w.work_read(AGENT, "session_history")), 0)
        _, fence = self.session()
        self.assertEqual(len(self.w.work_read(AGENT, "session_history")), 1)
        self.w.finish(**fence, outcome="completed", evidence=["test:done"])

    def test_retry_count_survives_intervening_task(self):
        _, fence = self.session()
        self.w.finish(**fence, outcome="failed", evidence=["test:failure"])
        original = self.task
        self.task = self.w.create_task(AGENT, "intervening", [])["id"]
        _, fence = self.session()
        self.w.finish(**fence, outcome="yielded", evidence=[])
        self.task = original
        packet, _ = self.session()
        self.assertEqual(packet["task"]["retries"], 1)
        self.assertEqual(len(self.w.work_read(AGENT, "session_history")), 2)

    def test_disagreement_survives_consumption_and_recovery(self):
        _, fence = self.session()
        ident = self.message("disagreement", {"positions": ["continue", "stop"]}, ["test:review"])
        self.w.acknowledge(**fence, message_id=ident)
        self.expire()
        packet, _ = self.session()
        self.assertEqual(packet["disagreements"][0]["id"], ident)
        self.assertEqual(self.w.work_read(OTHER, "disagreement", task_id=self.task), [])

    def test_cancel_races_finish_and_remains_terminal(self):
        _, fence = self.session()
        barrier = threading.Barrier(2)

        def finish():
            barrier.wait()
            try:
                self.w.finish(**fence, outcome="completed", evidence=[])
            except ValueError:
                pass

        def cancel():
            barrier.wait()
            self.w.cancel_task(AGENT, self.task)

        with ThreadPoolExecutor(max_workers=2) as pool:
            a, b = pool.submit(finish), pool.submit(cancel)
            a.result()
            b.result()
        self.assertEqual(self.stored_task()["status"], "cancelled")
        with self.assertRaisesRegex(ValueError, "terminal"):
            self.w.human_decision("operator", self.task, "reopen", ["user:decision"], reopen=True)

    def test_idempotent_create_replays(self):
        keyed = Work(self.s, "p1", idempotency_key="k", request={"goal": "once"})
        first = keyed.create_task(AGENT, "once", [])
        self.assertEqual(first, keyed.create_task(AGENT, "once", []))
        self.assertEqual(len(self.w.work_read(AGENT, "task")), 2)

    def test_projects_are_isolated(self):
        _, fence = self.session()
        self.checkpoint(fence)
        self.message()
        other = Work(self.s, "p2")
        for kind in ("task", "session", "checkpoint"):
            self.assertEqual(other.work_read(AGENT, kind), [], kind)
        with self.assertRaisesRegex(ValueError, "unknown"):
            other.resume(AGENT, self.task)
        self.assertEqual({i["id"] for i in other.changes(AGENT)["items"]}, {"p2"})
        # The same agent may hold an independent session in another project.
        task = other.create_task(AGENT, "elsewhere", [])["id"]
        s = other.resume(AGENT, task)["session"]
        self.assertEqual(s["generation"], 1)
        self.assertEqual(other.claim_messages(AGENT, s["session_id"], 1), [])


if __name__ == "__main__":
    unittest.main()
