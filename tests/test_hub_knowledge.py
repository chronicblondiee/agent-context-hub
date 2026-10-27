"""M4 search, queue, and revision-bound trust contracts."""

import os
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from hub import store as store_module
from hub.embed import MODEL, Embedder
from hub.index import finish_job, index, pending_job
from hub.store import Store, connect, migrate
from hub.work import Work

COMMIT = "a" * 40
IMAGE = "sha256:" + "b" * 64
CHECKS = "c" * 64
ARTIFACT = "d" * 64


class KnowledgeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "hub.sqlite3")
        migrate(self.path)
        self.store = Store(self.path)
        self.store.create_project("one", "one", "test")
        self.store.create_project("two", "two", "test")
        self.work = Work(self.store, "one")
        self.keyword = patch("hub.retrieval.EMBEDDER.embed", return_value=None)
        self.keyword.start()

    def tearDown(self):
        self.keyword.stop()
        self.store.close()
        self.tmp.cleanup()

    def propose(self, actor="alice", **kwargs):
        return self.work.solution_propose(
            actor,
            "Restart the local Docker service",
            "docker-restart",
            COMMIT,
            IMAGE,
            CHECKS,
            **kwargs,
        )

    def test_private_candidates_cannot_starve_permitted_top_k(self):
        for _ in range(60):
            self.work.remember(
                "alice",
                "n",
                "fact",
                "docker restart error",
                "tested",
                1,
                ["test:private"],
                visibility="private",
            )
        visible = self.work.remember(
            "bob", "n", "fact", "docker restart error", "tested", 1, ["test:shared"]
        )["id"]
        page = self.work.context_get("bob", "docker restart error")
        self.assertEqual([r["id"] for r in page["matches"]], [visible])
        self.assertEqual(page["retrieval_mode"], "keyword_only")  # no embedder: a fault
        with patch("hub.retrieval.EMBEDDER.embed", return_value=[[0.0] * 384]):
            with patch("hub.retrieval._semantic", return_value=[]):  # ran, nothing near
                self.assertEqual(self.work.context_get("bob", "docker")["retrieval_mode"], "hybrid")
            with patch("hub.retrieval._semantic", side_effect=sqlite3.OperationalError("vec")):
                mode = self.work.context_get("bob", "docker")["retrieval_mode"]
                self.assertEqual(mode, "keyword_only")
        self.assertEqual(
            Work(self.store, "two").context_get("bob", "docker restart")["matches"], []
        )

    def test_stopwords_and_single_shared_words_are_not_matches(self):
        fix = self.work.remember(
            "bob",
            "n",
            "fact",
            "Fix: add the user to the docker group, then log in again",
            "tested",
            1,
            ["test:shared"],
        )["id"]
        for query in ("what is the best way to do it", "windows registry fix bluetooth pairing"):
            self.assertEqual(self.work.context_get("bob", query)["matches"], [], query)
        page = self.work.context_get("bob", "docker group fix")
        self.assertEqual([r["id"] for r in page["matches"]], [fix])

    def test_semantic_acl_precedes_top_k_and_unrelated_vectors_are_dropped(self):
        vector = [1.0] + [0.0] * (MODEL["dim"] - 1)
        for i in range(55):
            ident = self.work.remember(
                "alice",
                "n",
                "fact",
                f"private needle {i}",
                "tested",
                1,
                ["test:private"],
                visibility="private",
            )["id"]
            finish_job(
                self.store,
                {"project_id": "one", "kind": "memory", "record_id": ident, "revision": 1},
                [vector],
            )
        visible = self.work.remember(
            "bob", "n", "fact", "shared needle", "tested", 1, ["test:shared"]
        )["id"]
        finish_job(
            self.store,
            {"project_id": "one", "kind": "memory", "record_id": visible, "revision": 1},
            [vector],
        )
        with patch("hub.retrieval.EMBEDDER.embed", return_value=[vector]):
            page = self.work.context_get("bob", "semantic-only-query")
        self.assertEqual([item["id"] for item in page["matches"]], [visible])
        self.assertIn("semantic", page["matches"][0]["reasons"])
        unrelated = [0.0, 1.0] + [0.0] * (MODEL["dim"] - 2)
        with patch("hub.retrieval.EMBEDDER.embed", return_value=[unrelated]):
            self.assertEqual(self.work.context_get("bob", "semantic-only-query")["matches"], [])

    def test_no_memory_suppresses_long_term_reads_and_writes(self):
        self.work.remember("alice", "n", "fact", "docker restart", "tested", 1, ["test:1"])
        task = self.work.create_task("alice", "quiet", [], no_memory=True)["id"]
        self.work.resume("alice", task)
        self.assertEqual(self.work.context_get("alice", "docker")["matches"], [])
        self.assertEqual(
            self.work.context_get("alice", "docker")["retrieval_mode"], "memory_disabled"
        )
        self.assertIsNone(self.work.attempt_record("alice", "try", "failed", ["test:2"])["id"])
        self.assertIsNone(self.propose()["id"])

    def test_evidence_is_independent_exact_and_revision_bound(self):
        proposal = self.propose()
        ident = proposal["id"]
        base = dict(
            solution_id=ident,
            revision=1,
            content_sha256=proposal["content_sha256"],
            checks_sha256=CHECKS,
            repository_commit=COMMIT,
            image_digest=IMAGE,
            result="pass",
            artifacts=[ARTIFACT],
        )
        with self.assertRaisesRegex(ValueError, "proposer"):
            self.work.evidence_submit("alice", **base)
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.work.evidence_submit("verifier", **{**base, "checks_sha256": "0" * 64})
        self.assertEqual(self.work.evidence_submit("verifier", **base)["status"], "verified")
        with self.assertRaisesRegex(ValueError, "self-approval"):
            self.work.solution_decide("alice", ident, 1, "approve", "own work")
        revised = self.propose(solution_id=ident, expected_revision=1)
        self.assertEqual(revised["status"], "unverified")
        with self.assertRaisesRegex(ValueError, "stale"):
            self.work.evidence_submit("verifier", **base)
        self.assertEqual(
            self.work.solution_decide("boss", ident, 2, "approve", "reviewed")["status"], "verified"
        )
        self.assertEqual(
            self.work.solution_decide("boss", ident, 2, "revoke", "obsolete")["status"], "revoked"
        )
        self.assertEqual(self.work.context_get("bob", "Docker service")["matches"], [])
        self.assertIsNotNone(self.work.knowledge_record("bob", ident))

    def test_applicability_distinguishes_match_conflict_and_unknown(self):
        ident = self.propose(applicability={"os": "linux"})["id"]

        def get(environment):
            matches = self.work.context_get("bob", "Docker service", environment=environment)
            return {r["id"]: r for r in matches["matches"]}.get(ident)

        self.assertIn("applicability match", get({"os": "linux"})["reasons"])
        self.assertIsNone(get({"os": "mac"}))
        unknown = get({})
        self.assertIn("applicability unknown", unknown["reasons"])
        self.assertNotIn("applicability match", unknown["reasons"])
        self.assertEqual(unknown["applicability_missing"], ["os"])

    def test_explicit_verified_conflict_enters_review(self):
        first = self.propose()["id"]
        second = self.work.solution_propose(
            "bob",
            "Use a different Docker socket repair",
            "docker-restart",
            COMMIT,
            IMAGE,
            CHECKS,
            conflicts_with=[first],
        )["id"]
        self.assertEqual(
            self.work.solution_decide("boss", first, 1, "approve", "reviewed")["status"], "verified"
        )
        self.assertEqual(
            self.work.solution_decide("boss", second, 1, "approve", "reviewed")["status"], "review"
        )
        self.assertEqual(self.work.knowledge_record("alice", first)["status"], "review")

    def test_jobs_survive_restart_and_stale_results_are_discarded(self):
        ident = self.work.remember("alice", "n", "fact", "docker restart", "tested", 1, ["test:1"])[
            "id"
        ]
        job = self.store.read(pending_job)
        self.assertEqual(job["record_id"], ident)
        self.store.close()
        self.store = Store(self.path)
        self.work = Work(self.store, "one")
        self.assertEqual(self.store.read(pending_job), job)
        revised = self.work.revise_memory("alice", ident, "new text", "tested", 1, ["test:2"])["id"]
        self.assertFalse(finish_job(self.store, job, [[0.0] * MODEL["dim"]])["stored"])
        self.assertEqual(self.store.read(pending_job)["record_id"], revised)

    def test_index_rollback_leaves_no_job_or_fts_row(self):
        def failed(tx):
            index(tx, "attempt", "rolled-back", 1, "needle")
            raise ValueError("abort")

        with self.assertRaisesRegex(ValueError, "abort"):
            self.store.mutate("one", "alice", failed)
        self.assertEqual(
            self.store.read(
                lambda db: db.execute(
                    "SELECT count(*) FROM embedding_jobs WHERE record_id='rolled-back'"
                ).fetchone()[0]
            ),
            0,
        )
        self.assertEqual(
            self.store.read(
                lambda db: db.execute(
                    "SELECT count(*) FROM search_fts WHERE record_id='rolled-back'"
                ).fetchone()[0]
            ),
            0,
        )

    def test_concurrent_searches_run_one_at_a_time(self):
        active, peak, lock = [0], [0], threading.Lock()

        def embed(texts):
            with lock:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            time.sleep(0.02)
            with lock:
                active[0] -= 1

        with patch("hub.retrieval.EMBEDDER.embed", side_effect=embed):
            threads = [
                threading.Thread(target=self.work.context_get, args=("alice", "docker"))
                for _ in range(4)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        self.assertEqual(peak[0], 1)


class EmbeddingTest(unittest.TestCase):
    def test_offline_model_vector_and_missing_directory(self):
        model = Embedder()
        chunks = model.chunks("word " * 600)
        self.assertGreater(len(chunks), 1)
        vector = model.embed(["Docker restart error"])[0]
        self.assertEqual(len(vector), 384)
        self.assertAlmostEqual(sum(x * x for x in vector), 1, places=5)
        self.assertEqual(vector, model.embed(["Docker restart error"])[0])
        self.assertIsNone(Embedder("/missing-model-directory").load())


class MigrationTest(unittest.TestCase):
    def test_m3_memory_is_backfilled_without_revoked_records(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "old.sqlite3")
            with (
                patch.object(store_module, "MIGRATIONS", store_module.MIGRATIONS[:4]),
                patch.object(store_module, "SCHEMA_VERSION", 4),
            ):
                migrate(path)
            con = connect(path)
            con.execute("INSERT INTO projects VALUES ('old', 'old', 1)")
            for ident, revoked in (("active", 0), ("revoked", 1)):
                con.execute(
                    "INSERT INTO memory_records VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        "old",
                        ident,
                        None,
                        "ns",
                        "fact",
                        "legacy docker error",
                        "legacy",
                        "tested",
                        1.0,
                        "alice",
                        '["test:old"]',
                        "project",
                        revoked,
                        None,
                        1,
                    ),
                )
            con.close()
            self.assertEqual(migrate(path), store_module.SCHEMA_VERSION)
            con = connect(path)
            self.assertEqual(
                [r[0] for r in con.execute("SELECT record_id FROM search_fts")], ["active"]
            )
            self.assertEqual(
                [r[0] for r in con.execute("SELECT record_id FROM embedding_jobs")], ["active"]
            )
            con.close()


if __name__ == "__main__":
    unittest.main()
