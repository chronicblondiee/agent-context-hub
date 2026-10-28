"""Synthetic lifecycle, pre-limit eligibility and durable source-check contracts."""

import os
import unittest
from unittest.mock import patch

from hub.common import Stale
from tests.test_hub_memory import AGENT, OTHER, MemoryTest


class FreshnessTest(unittest.TestCase):
    setUp = MemoryTest.setUp
    tearDown = MemoryTest.tearDown
    memory = MemoryTest.memory

    def review(self, ident, action, **kw):
        revision = self.w.record(AGENT, ident)["freshness_revision"]
        return self.w.memory_review(AGENT, ident, revision, action, **kw)

    def context(self, view="current"):
        with patch("hub.retrieval.embedded", return_value=None):
            return self.w.context_get(AGENT, "router", view=view)["matches"]

    def test_current_history_unknown_and_deadline(self):
        unknown = self.memory("router legacy")
        stable = self.memory("router stable", temporal_kind="durable", observed_us=1)
        historical = self.memory("router previous", temporal_kind="historical")
        with patch("hub.freshness.now_us", return_value=100):
            changing = self.memory(
                "router deployed",
                temporal_kind="changing",
                claim_key="deployment",
                review_due_us=101,
            )
            self.assertEqual({r["id"] for r in self.context()[:2]}, {changing, stable})
        with patch("hub.freshness.now_us", return_value=101):
            matches = self.context()
            self.assertEqual([r["id"] for r in matches], [stable, unknown])
            self.assertEqual(matches[-1]["freshness"], "freshness unknown")
            self.assertEqual({r["id"] for r in self.context("history")}, {changing, historical})
        self.assertEqual(len(self.context("all")), 4)

    def test_claim_uniqueness_and_replacement(self):
        args = dict(
            temporal_kind="changing", claim_key="deployment", review_due_us=9999999999999999
        )
        old = self.memory("router version one", **args)
        with self.assertRaisesRegex(ValueError, "active claim"):
            self.memory("router version two", **args)
        new = self.memory("router version two", supersedes=old, **args)
        self.assertEqual(self.w.record(AGENT, old)["superseded_by"], new)
        self.memory("router private", visibility="private", **args)
        self.memory("router another owner", actor=OTHER, **args)

    def test_conflict_deferral_confirmation_and_fence(self):
        ident = self.memory("router config", temporal_kind="durable")
        self.review(ident, "conflict", evidence=["source:new"])
        self.assertEqual(self.context(), [])
        self.review(ident, "defer", reminder_us=9999999999999999, temporal_kind="durable")
        self.assertEqual(self.context(), [])
        with self.assertRaises(Stale):
            self.w.memory_review(AGENT, ident, 1, "confirm", evidence=["source:new"])
        result = self.review(ident, "confirm", evidence=["source:checked"])
        self.assertEqual(result["freshness"], "current")
        self.assertEqual(self.context()[0]["status"], "unverified")
        with self.assertRaises(ValueError):
            self.w.memory_review(OTHER, ident, result["freshness_revision"], "historical")

    def test_eligibility_before_candidate_limit(self):
        for i in range(60):
            self.memory(f"router router router {i}", temporal_kind="historical")
        current = self.memory("router live", temporal_kind="durable")
        self.assertEqual([r["id"] for r in self.context()], [current])

    def test_deferral_hides_from_inbox_until_reminder(self):
        ident = self.memory("router deferred")
        with patch("hub.freshness.now_us", return_value=500):
            self.review(ident, "defer", reminder_us=1000)
            self.assertNotIn(ident, [r["id"] for r in self.w.memory_review_list(AGENT)])
        with patch("hub.freshness.now_us", return_value=10**18):
            self.assertIn(ident, [r["id"] for r in self.w.memory_review_list(AGENT)])
        self.assertEqual(self.w.record(AGENT, ident)["freshness"], "freshness unknown")

    def test_bulk_requires_matching_preview(self):
        ident = self.memory("router old")
        args = dict(records=[dict(memory_id=ident, expected_revision=1)], action="historical")
        with self.assertRaises(Stale):
            self.w.memory_review_bulk(AGENT, **args, preview=False)
        preview = self.w.memory_review_bulk(AGENT, **args)
        self.assertEqual(self.w.record(AGENT, ident)["temporal_kind"], "unclassified")
        self.w.memory_review_bulk(
            AGENT, **args, preview=False, preview_token=preview["preview_token"]
        )
        self.assertEqual(self.context(), [])


class SourceCheckTest(unittest.TestCase):
    tearDown = MemoryTest.tearDown
    memory = MemoryTest.memory

    def setUp(self):
        MemoryTest.setUp(self)
        self.env = patch.dict(os.environ, HUB_CHECK_ENDPOINTS='["forge"]')
        self.env.start()
        self.addCleanup(self.env.stop)
        self.ident = self.memory("router stable", temporal_kind="durable")
        self.source = dict(
            endpoint="forge", repository="example/repo", kind="file", ref="main", path="README.md"
        )
        self.job = self.w.memory_source_bind(AGENT, self.ident, 1, self.source, "a" * 64)["id"]

    def claim(self):
        return self.w.source_check_claim("checker")["job"]

    def complete(self, job, **kw):
        return self.w.source_check_complete(
            "checker", job["id"], job["generation"], job["target_revision"], **kw
        )

    def test_unique_binding_claim_and_replay(self):
        self.assertEqual(
            self.w.memory_source_bind(AGENT, self.ident, 2, self.source, "a" * 64)["id"], self.job
        )
        claim = self.claim()
        self.assertIsNone(self.claim())
        args = dict(observed_fingerprint="b" * 64)
        result = self.complete(claim, **args)
        self.assertEqual(self.complete(claim, **args), result)
        self.assertEqual(self.w.record(AGENT, self.ident)["review_reasons"], ["source changed"])
        with self.assertRaises(Stale):
            self.complete(claim, observed_fingerprint="c" * 64)

    def test_expired_lease_and_changed_revision(self):
        with patch("hub.source_checks.now_us", return_value=9999999999999999):
            first = self.claim()
        with patch("hub.source_checks.now_us", return_value=9999999999999999 + 60_000_000):
            with self.assertRaises(Stale):
                self.complete(first, observed_fingerprint="a" * 64)
            second = self.claim()
            self.assertGreater(second["generation"], first["generation"])
            self.w.memory_review(AGENT, self.ident, 2, "historical")
            with self.assertRaises(Stale):
                self.complete(second, observed_fingerprint="a" * 64)

    def test_retry_exhaustion_and_manual_retry(self):
        for i in range(5):
            with patch(
                "hub.source_checks.now_us", return_value=9999999999999999 + i * 100000000000
            ):
                claim = self.claim()
                result = self.complete(claim, failure="timeout")
        self.assertEqual(result["state"], "failed")
        revision = self.w.record(AGENT, self.ident)["freshness_revision"]
        self.w.memory_source_retry(AGENT, self.job, revision)
        self.assertIsNotNone(self.claim())
        self.assertIn("failed source checks", self.w.record(AGENT, self.ident)["review_reasons"])

    def test_unchanged_source_never_confirms(self):
        claim = self.claim()
        self.complete(claim, observed_fingerprint="a" * 64)
        record = self.w.record(AGENT, self.ident)
        self.assertIsNone(record["checked_us"])
        self.assertEqual(record["provenance"], "tested")

    def test_retire_revokes_and_stops_source_jobs(self):
        revision = self.w.record(AGENT, self.ident)["freshness_revision"]
        self.w.memory_review(AGENT, self.ident, revision, "retire")
        self.assertTrue(self.w.record(AGENT, self.ident)["revoked"])
        operations = [c["operation"] for c in self.w.changes(AGENT, 0, 100)["items"]]
        self.assertIn("revoke", operations)
        self.assertIsNone(self.claim())

    def test_missing_baseline_adopts_first_observation(self):
        ident = self.memory("router unbaselined", temporal_kind="durable")
        source = dict(self.source, path="CHANGELOG.md")
        self.w.memory_source_bind(AGENT, ident, 1, source)

        def check(now, observed):
            with patch("hub.source_checks.now_us", return_value=now):
                while (job := self.claim())["source"] != source:
                    self.complete(job, observed_fingerprint="a" * 64)  # the setUp binding
                return self.complete(job, observed_fingerprint=observed)["reason"]

        self.assertIsNone(check(9999999999999999, "b" * 64))
        self.assertNotIn("source changed", self.w.record(AGENT, ident)["review_reasons"])
        self.assertEqual(check(9999999999999999 + 10**12, "c" * 64), "source changed")

    def test_no_memory_and_foreign_owner(self):
        with self.assertRaises(ValueError):
            self.w.memory_source_bind(OTHER, self.ident, 2, self.source, "a" * 64)
        task = self.w.create_task(AGENT, "quiet", [], no_memory=True)["id"]
        self.w.resume(AGENT, task)
        self.assertEqual(self.w.memory_review_list(AGENT), [])
        with self.assertRaises(ValueError):
            self.w.memory_review(AGENT, self.ident, 2, "historical")

    def test_concurrent_claims_and_crash_exhaustion(self):
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: self.claim(), range(2)))
        self.assertEqual(sum(r is not None for r in results), 1)
        first = next(r for r in results if r)
        for i in range(5):
            with patch(
                "hub.source_checks.now_us", return_value=first["lease_until_us"] + i * 60_000_000
            ):
                result = self.claim()
        self.assertIsNone(result)
        self.assertEqual(self.w.source_check_status("checker")["failures"], 1)

    def test_stalled_fetch_does_not_block_memory_writer(self):
        import concurrent.futures
        import threading

        from hub.source_checker import source_fingerprint

        entered, release = threading.Event(), threading.Event()

        def fetch(*args, **kw):
            entered.set()
            release.wait(5)
            return {"content": "YQ=="}

        self.claim()
        config = {"forge": {"url": "https://example.test", "token_file": "/unused"}}
        with (
            patch("hub.source_checker.Path.read_text", return_value="synthetic"),
            patch("hub.source_checker.request", side_effect=fetch),
        ):
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                future = executor.submit(source_fingerprint, self.source, config)
                self.assertTrue(entered.wait(1))
                try:
                    ident = executor.submit(self.memory, "ordinary write during fetch").result(
                        timeout=1
                    )
                    self.assertTrue(ident)
                finally:
                    release.set()
                self.assertEqual(len(future.result()), 64)
