"""M4 search, queue, and revision-bound trust contracts."""

import json
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

    def test_equal_scores_order_by_best_rank_then_newer(self):
        from hub.retrieval import order, tiebreak

        # A real tie: rank 1 in one list (1/61) vs. rank 62 in both (1/122 + 1/122).
        base = {"status": "unverified", "applicability": {}}
        items = [
            {**base, "id": "0", "best": 62, "score": 1 / 122 + 1 / 122, "created_us": 3},
            {**base, "id": "1", "best": 1, "score": 1 / 61, "created_us": 1},
            {**base, "id": "2", "best": 1, "score": 1 / 61, "created_us": 2},
        ]
        self.assertEqual(items[0]["score"], items[1]["score"])
        items.sort(key=lambda r: (*order(r), *tiebreak(r)))
        self.assertEqual([r["id"] for r in items], ["2", "1", "0"])

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

    def _max_bytes_record(self, actor="bob", **kwargs):
        return self.work.remember(
            actor,
            "n",
            "fact",
            'docker restart 雪🙂"\\\n' * 3,
            "tested",
            1,
            ["test:bytes:" + str(i) + ":" + "x" * 48 for i in range(3)],
            **kwargs,
        )["id"]

    def _context_bytes(self, result):
        return len(
            json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        )

    def test_max_bytes_none_preserves_legacy_and_max_chars(self):
        self._max_bytes_record()
        legacy = self.work.context_get("bob", "docker restart", max_chars=8)
        self.assertNotIn("byte_omitted_matches", legacy)
        self.assertEqual(
            self.work.context_get("bob", "docker restart", max_chars=8, max_bytes=None),
            legacy,
        )
        bounded = self.work.context_get("bob", "docker restart", max_chars=8, max_bytes=65536)
        self.assertEqual(bounded, {**legacy, "byte_omitted_matches": 0})
        self.assertLessEqual(sum(len(row["summary"]) for row in bounded["matches"]), 8)

    def test_max_bytes_exact_fit_and_one_byte_under(self):
        self._max_bytes_record()
        full = self.work.context_get("bob", "docker restart", max_bytes=65536)
        size = self._context_bytes(full)
        self.assertEqual(self.work.context_get("bob", "docker restart", max_bytes=size), full)
        smaller = self.work.context_get("bob", "docker restart", max_bytes=size - 1)
        self.assertLessEqual(self._context_bytes(smaller), size - 1)
        self.assertEqual(smaller["matches"], [])
        self.assertEqual(smaller["byte_omitted_matches"], 1)
        self.assertTrue(smaller["truncated"])

    def test_max_bytes_keeps_ranked_prefix_and_all_metadata(self):
        for _ in range(3):
            self._max_bytes_record()
        full = self.work.context_get("bob", "docker restart", max_bytes=65536)
        self.assertEqual(len(full["matches"]), 3)
        expected = {
            **full,
            "matches": full["matches"][:-1],
            "byte_omitted_matches": 1,
            "truncated": True,
        }
        size = self._context_bytes(expected)
        page = self.work.context_get("bob", "docker restart", max_bytes=size)
        self.assertEqual(page, expected)
        self.assertEqual(self._context_bytes(page), size)
        self.assertGreater(self._context_bytes(full), len(store_module.encoded(full)))
        for actual, original in zip(page["matches"], full["matches"], strict=False):
            self.assertEqual(actual, original)  # citation/author/provenance/revision intact
        self.assertEqual(full["byte_omitted_matches"], 0)

    def test_max_bytes_rejects_invalid_or_impossible_budgets(self):
        for invalid in (True, False, 0, -1, 65537, 1.5, "100", [], {}):
            with self.subTest(max_bytes=invalid):
                with self.assertRaisesRegex(ValueError, "max_bytes"):
                    self.work.context_get("bob", "docker restart", max_bytes=invalid)
        with self.assertRaisesRegex(ValueError, "max_bytes too small for context envelope"):
            self.work.context_get("bob", "docker restart", max_bytes=1)

    def test_max_bytes_no_matches_and_memory_disabled(self):
        self._max_bytes_record()
        for expected_mode, query in (
            ("keyword_only", "unmatched zzqq"),
            ("memory_disabled", "docker restart"),
        ):
            page = self.work.context_get("alice", query, max_bytes=1024)
            self.assertEqual(page["matches"], [])
            self.assertEqual(page["retrieval_mode"], expected_mode)
            self.assertEqual(page["byte_omitted_matches"], 0)
            self.assertFalse(page["truncated"])
            self.assertLessEqual(self._context_bytes(page), 1024)
            size = self._context_bytes(page)
            self.assertEqual(self.work.context_get("alice", query, max_bytes=size), page)
            with self.assertRaisesRegex(ValueError, "context envelope"):
                self.work.context_get("alice", query, max_bytes=size - 1)
            with self.assertRaisesRegex(ValueError, "max_bytes too small for context envelope"):
                self.work.context_get("alice", query, max_bytes=1)
            if expected_mode == "keyword_only":
                task = self.work.create_task("alice", "quiet", [], no_memory=True)["id"]
                self.work.resume("alice", task)

    def test_max_bytes_does_not_count_inaccessible_or_other_project_records(self):
        hidden = self._max_bytes_record("alice", visibility="private")
        visible = self._max_bytes_record("bob")
        page = self.work.context_get("bob", "docker restart", max_bytes=65536)
        self.assertEqual([row["id"] for row in page["matches"]], [visible])
        self.assertNotIn(hidden, store_module.encoded(page))
        self.assertEqual(page["byte_omitted_matches"], 0)
        other = Work(self.store, "two").context_get("bob", "docker restart", max_bytes=1024)
        self.assertEqual(other["matches"], [])
        self.assertEqual(other["byte_omitted_matches"], 0)

    def test_max_bytes_mixed_ranked_records_and_empty_boundary(self):
        self._max_bytes_record()
        self.work.attempt_record("bob", "docker restart", "tested 雪", ["test:attempt"])
        solution = self.propose(applicability={"os": "linux", "version": "1"})["id"]
        self.propose(
            solution_id=solution, expected_revision=1, applicability={"os": "linux", "version": "2"}
        )
        self.work.solution_decide("boss", solution, 2, "approve", "reviewed")
        options = {"environment": {"os": "linux"}, "view": "all"}
        full = self.work.context_get("bob", "docker restart", max_bytes=65536, **options)
        self.assertEqual({r["kind"] for r in full["matches"]}, {"memory", "attempt", "solution"})
        first = full["matches"][0]
        self.assertEqual(
            (first["id"], first["revision"], first["status"]), (solution, 2, "verified")
        )
        self.assertEqual(first["applicability"], {"os": "linux", "version": "2"})
        self.assertEqual(first["applicability_missing"], ["version"])
        for retained in (2, 1, 0):
            expected = {
                **full,
                "matches": full["matches"][:retained],
                "byte_omitted_matches": 3 - retained,
                "truncated": True,
            }
            size = self._context_bytes(expected)
            actual = self.work.context_get("bob", "docker restart", max_bytes=size, **options)
            self.assertEqual(actual, expected)
            self.assertEqual(self._context_bytes(actual), size)
        with self.assertRaisesRegex(ValueError, "context envelope"):
            self.work.context_get("bob", "docker restart", max_bytes=size - 1, **options)

    def test_max_bytes_after_limit_and_summary_budget(self):
        for _ in range(5):
            self._max_bytes_record()
        all_rows = self.work.context_get("bob", "docker restart")["matches"]
        chars = len(all_rows[0]["summary"]) + 7
        options = {"limit": 3, "max_chars": chars}
        full = self.work.context_get("bob", "docker restart", **options)
        self.assertEqual(len(full["matches"]), 2)
        self.assertEqual(len(full["matches"][1]["summary"]), 7)
        expected = {**full, "matches": full["matches"][:1], "byte_omitted_matches": 1}
        page = self.work.context_get(
            "bob", "docker restart", max_bytes=self._context_bytes(expected), **options
        )
        self.assertEqual(page, expected)
        self.assertTrue(page["truncated"])
        # Limit alone removes two eligible rows; only the additional byte omission counts.
        limited = self.work.context_get("bob", "docker restart", limit=3)
        expected = {**limited, "matches": limited["matches"][:2], "byte_omitted_matches": 1}
        self.assertEqual(
            self.work.context_get(
                "bob", "docker restart", limit=3, max_bytes=self._context_bytes(expected)
            ),
            expected,
        )

    def test_max_bytes_lifecycle_filters_before_counting(self):
        self._max_bytes_record("alice", visibility="private")
        revoked = self._max_bytes_record()
        self.work.revoke_memory("bob", revoked)
        old = self._max_bytes_record()
        current = self.work.revise_memory(
            "bob", old, "docker restart new 雪", "tested", 1, ["test:new"]
        )["id"]
        Work(self.store, "two").remember(
            "bob", "n", "fact", "docker restart", "tested", 1, ["test:other"]
        )
        full = self.work.context_get("bob", "docker restart", max_bytes=65536)
        self.assertEqual([r["id"] for r in full["matches"]], [current])
        expected = {**full, "matches": [], "truncated": True, "byte_omitted_matches": 1}
        self.assertEqual(
            self.work.context_get("bob", "docker restart", max_bytes=self._context_bytes(expected)),
            expected,
        )

    def test_max_bytes_real_vector_prefix_and_fallback(self):
        vector = [1.0] + [0.0] * (MODEL["dim"] - 1)
        for _ in range(3):
            ident = self._max_bytes_record()
            finish_job(
                self.store,
                {"project_id": "one", "kind": "memory", "record_id": ident, "revision": 1},
                [vector],
            )
        for embedded, query, mode, reason in (
            ([vector], "semantic-only-query", "hybrid", "semantic"),
            (None, "docker restart", "keyword_only", "keyword"),
        ):
            with patch("hub.retrieval.EMBEDDER.embed", return_value=embedded):
                full = self.work.context_get("bob", query, max_bytes=65536)
                self.assertEqual(len(full["matches"]), 3)
                self.assertEqual(full["retrieval_mode"], mode)
                self.assertTrue(all(reason in row["reasons"] for row in full["matches"]))
                expected = {
                    **full,
                    "matches": full["matches"][:2],
                    "truncated": True,
                    "byte_omitted_matches": 1,
                }
                self.assertEqual(
                    self.work.context_get("bob", query, max_bytes=self._context_bytes(expected)),
                    expected,
                )

    def test_semantic_freshness_eligibility_precedes_top_k(self):
        from hub.embed import MODEL, MODEL_KEY

        vector = [1.0] + [0.0] * (MODEL["dim"] - 1)
        import struct

        blob = struct.pack(f"<{MODEL['dim']}f", *vector)
        records = []
        for i in range(55):
            records.append(
                self.work.remember(
                    "alice",
                    "ops",
                    "fact",
                    f"unrelated synthetic record {i}",
                    "stated",
                    1,
                    ["source:synthetic"],
                    temporal_kind="historical",
                )["id"]
            )
        live = self.work.remember(
            "alice",
            "ops",
            "fact",
            "unrelated live synthetic",
            "stated",
            1,
            ["source:synthetic"],
            temporal_kind="durable",
        )["id"]

        def vectors(tx):
            for ident in [*records, live]:
                tx.execute(
                    "INSERT INTO chunk_vectors(project_id,kind,record_id,revision,"
                    "chunk,model,dim,vector) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    ["one", "memory", ident, 1, 0, MODEL_KEY, MODEL["dim"], blob],
                )
            tx.audit("test.vectors", "synthetic", {})

        self.store.mutate("one", "alice", vectors)
        with patch("hub.retrieval.embedded", return_value=vector):
            matches = self.work.context_get("bob", "semantic-only-query")["matches"]
        self.assertEqual([r["id"] for r in matches], [live])


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
            migrated = Store(path)
            try:
                old = Work(migrated, "old").record("alice", "active")
                self.assertEqual(old["freshness"], "freshness unknown")
                self.assertIsNone(old["observed_us"])
                self.assertIsNone(old["checked_us"])
            finally:
                migrated.close()
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
