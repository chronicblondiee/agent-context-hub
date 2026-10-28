"""Synthetic library publication and troubleshooting retrieval: gates, ranking, budgets."""

import asyncio
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

import httpx2
import uvicorn
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from hub import api, app, backup, identity, library
from hub.common import NotFound, Stale
from hub.store import Store, migrate
from hub.work import Work

COMMIT = "a" * 40
IMAGE = "sha256:" + "b" * 64
CHECKS = "c" * 64
SAFE = ["https://example.test/redacted-check"]


def principals(s):
    """lib is the library; worker reads it, outsider does not; boss maintains both, solo one."""
    identity.bootstrap(s, "root")
    for project in ("p1", "p2", "lib"):
        identity.create_project(s, "root", project, project)
    for name, kind, grants in (
        ("boss", "human", [("p1", "maintainer"), ("p2", "maintainer"), ("lib", "maintainer")]),
        ("solo", "human", [("p1", "maintainer")]),
        ("worker", "agent", [("p1", "contributor"), ("p2", "contributor"), ("lib", "reader")]),
        ("outsider", "agent", [("p1", "contributor"), ("p2", "contributor")]),
        ("checker", "verifier", [("lib", "verifier")]),
    ):
        identity.create_principal(s, "root", name, kind)
        for project, role in grants:
            identity.grant(s, "root", name, project, role)
    identity.bind(s, "root", "worker", "boss")
    identity.bind(s, "root", "outsider", "boss")
    library.configure(s, "root", "lib")


class LibraryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "hub.sqlite3")
        migrate(self.path)
        self.s = Store(self.path)
        principals(self.s)
        self.p1, self.p2, self.lib = (Work(self.s, p) for p in ("p1", "p2", "lib"))
        self.keyword = patch("hub.retrieval.EMBEDDER.embed", return_value=None)
        self.keyword.start()

    def tearDown(self):
        self.keyword.stop()
        self.s.close()
        self.tmp.cleanup()

    def memory(self, body, work=None, visibility="project"):
        work = work or self.p1
        return work.remember(
            "worker", "ops", "fact", body, "tested", 0.9, ["test:1"], visibility=visibility
        )["id"]

    def publish(self, source, body, applicability=None, work=None):
        work = work or self.p1
        proposal = work.tshoot_propose("worker", source, body, SAFE, applicability)["id"]
        return work.tshoot_publication_decide("boss", proposal, "publish", "reviewed")

    def ask(self, query, work=None, actor="worker", **kwargs):
        return (work or self.p2).tshoot_context(actor, query, **kwargs)

    def test_only_published_entries_reach_library_readers(self):
        source = self.memory("nginx 502 bad gateway: upstream keepalive timeout too short")
        proposal = self.p1.tshoot_propose(
            "worker", source, "nginx 502 bad gateway: raise upstream keepalive timeout", SAFE
        )
        self.assertEqual(self.ask("nginx 502 bad gateway")["matches"], [])  # proposed only
        published = self.p1.tshoot_publication_decide(
            "boss", proposal["id"], "publish", "sanitized, reviewed"
        )
        found = self.ask("nginx 502 bad gateway")
        self.assertEqual(found["library"], "searched")
        (match,) = found["matches"]
        self.assertEqual(
            (match["project_id"], match["id"], match["source"], match["trust"], match["lead"]),
            ("lib", published["dest_id"], "general", "unverified", True),
        )
        self.assertEqual(match["publication"]["reviewer"], "boss")
        self.assertNotIn("source_id", json.dumps(match))  # restricted provenance stays internal
        record = self.lib.record("worker", published["dest_id"])
        self.assertEqual((record["owner"], record["author"]), ("boss", "worker"))
        # Private sources read as absent; proposals are not searchable from their own project.
        private = self.memory("private nginx detail", visibility="private")
        with self.assertRaises(NotFound):
            self.p1.tshoot_propose("worker", private, "x", SAFE)

    def test_library_needs_an_explicit_grant_and_reveals_nothing(self):
        source = self.memory("disk full on /var: journald vacuum")
        self.publish(source, "disk full on /var: vacuum the journal")
        denied = self.ask("disk full var", actor="outsider")
        self.assertEqual((denied["library"], denied["matches"]), ("unavailable", []))
        with patch("hub.library.library_of", return_value=None):
            unconfigured = self.ask("disk full var")
        self.assertEqual(set(denied), set(unconfigured))
        self.assertEqual(unconfigured["library"], "unavailable")
        # The library is never searched as a second copy of itself.
        self.assertEqual(
            self.lib.tshoot_context("worker", "disk full var")["library"], "unavailable"
        )

    def test_publication_needs_a_human_maintainer_of_both_projects(self):
        source = self.memory("dns resolution fails in container")
        proposal = self.p1.tshoot_propose("worker", source, "dns fails in container", SAFE)["id"]
        with self.assertRaisesRegex(ValueError, "maintainer authority in the library"):
            self.p1.tshoot_publication_decide("solo", proposal, "publish", "ok")
        rejected = self.p1.tshoot_publication_decide("boss", proposal, "reject", "too specific")
        self.assertEqual(rejected["status"], "rejected")
        with self.assertRaisesRegex(ValueError, "proposal is rejected"):
            self.p1.tshoot_publication_decide("boss", proposal, "publish", "changed my mind")
        with self.assertRaises(NotFound):  # decided in its source project only
            self.p2.tshoot_publication_decide("boss", proposal, "publish", "x")

    def test_revocation_and_supersession_withdraw_publications(self):
        for change in ("revoke", "revise"):
            source = self.memory(f"redis oom {change}: maxmemory policy noeviction")
            dest = self.publish(source, f"redis oom {change}: set an eviction policy")["dest_id"]
            pending = self.p1.tshoot_propose("worker", source, f"redis {change} again", SAFE)["id"]
            if change == "revoke":
                self.p1.revoke_memory("worker", source)
            else:
                self.p1.revise_memory("worker", source, "redis oom revised", "tested", 1, ["t:2"])
            self.assertEqual(self.ask(f"redis oom {change}")["matches"], [])
            self.assertIsNone(self.lib.record("worker", dest))  # direct ID access
            changes = self.lib.changes("worker")["items"]
            self.assertNotIn(dest, {c["id"] for c in changes})
            self.assertEqual(self.lib.context_get("worker", f"redis oom {change}")["matches"], [])
            self.assertIsNotNone(self.lib.record("boss", dest))  # governance history
            with self.assertRaisesRegex(ValueError, "proposal is withdrawn"):
                self.p1.tshoot_publication_decide("boss", pending, "publish", "x")
        statuses = {p["status"] for p in self.p1.tshoot_proposals("boss")}
        self.assertEqual(statuses, {"withdrawn"})

    def test_solution_copies_need_their_own_trust_and_revisions_need_republication(self):
        made = self.p1.solution_propose(
            "worker",
            "postgres too many connections: add pgbouncer",
            "pg-conn",
            COMMIT,
            IMAGE,
            CHECKS,
        )
        copy = self.publish(made["id"], "postgres too many connections: pool with pgbouncer")
        match = self.ask("postgres too many connections")["matches"][0]
        self.assertEqual(
            (match["kind"], match["status"], match["lead"]), ("solution", "unverified", True)
        )
        content = self.lib.knowledge_record("worker", copy["dest_id"])["revision"]["content_sha256"]
        self.lib.evidence_submit(
            "checker", copy["dest_id"], 1, content, CHECKS, COMMIT, IMAGE, "pass", ["d" * 64]
        )
        match = self.ask("postgres too many connections")["matches"][0]
        self.assertEqual((match["trust"], match["lead"]), ("verified", False))
        # A library-side revision is not the reviewed one.
        self.lib.solution_propose(
            "worker",
            "postgres pool edited",
            "pg-conn",
            COMMIT,
            IMAGE,
            CHECKS,
            solution_id=copy["dest_id"],
            expected_revision=1,
        )
        self.assertEqual(self.ask("postgres pool")["matches"], [])
        self.assertIsNone(self.lib.knowledge_record("worker", copy["dest_id"]))
        # A source revision withdraws, and the stale proposal cannot publish.
        again = self.p1.tshoot_propose("worker", made["id"], "pgbouncer again", SAFE)["id"]
        self.p1.solution_propose(
            "worker",
            "postgres v2",
            "pg-conn",
            COMMIT,
            IMAGE,
            CHECKS,
            solution_id=made["id"],
            expected_revision=1,
        )
        with self.assertRaisesRegex(ValueError, "withdrawn"):
            self.p1.tshoot_publication_decide("boss", again, "publish", "x")

    def test_stale_source_cannot_publish(self):
        source = self.memory("kafka lag spike")
        proposal = self.p1.tshoot_propose("worker", source, "kafka lag spike", SAFE)["id"]

        def bump(tx):  # a revision that bypassed withdrawal must still not publish
            tx.execute("UPDATE publications SET source_revision=2 WHERE id=?", [proposal])
            tx.audit("test", proposal, {})

        self.s.mutate("p1", "test", bump)
        with self.assertRaises(Stale):
            self.p1.tshoot_publication_decide("boss", proposal, "publish", "x")

    def test_no_memory_and_thread_scope(self):
        source = self.memory("tls handshake failure expired certificate")
        self.publish(source, "tls handshake failure: check certificate expiry")
        task = self.p2.create_task("worker", "investigate", [], no_memory=True)["id"]
        with patch("hub.library.library_of") as looked_up:
            off = self.ask("tls handshake failure", task_id=task)
        looked_up.assert_not_called()
        self.assertEqual(
            (off["retrieval_mode"], off["library"], off["matches"]),
            ("memory_disabled", "skipped", []),
        )
        other = self.p2.create_task("outsider", "theirs", [])["id"]
        with self.assertRaisesRegex(ValueError, "task ownership"):
            self.ask("tls", task_id=other)
        thread = self.p2.tshoot_open("outsider", "svc:tls")["id"]
        with self.assertRaisesRegex(ValueError, "thread participation"):
            self.ask("tls handshake failure", thread_id=thread)
        with self.assertRaises(NotFound):
            self.ask("tls", thread_id=self.p1.tshoot_open("worker", "svc:p1")["id"])
        self.p2.tshoot_open("worker", "svc:tls")
        self.assertEqual(len(self.ask("tls handshake failure", thread_id=thread)["matches"]), 1)

    def test_caps_ties_and_deduplication(self):
        for i in range(3):
            self.publish(
                self.memory(f"queue backlog grows {i}"), f"queue backlog grows general {i}"
            )
        for i in range(4):
            self.memory(f"queue backlog grows local {i}", self.p2)
        found = self.ask("queue backlog grows")
        sources = [m["source"] for m in found["matches"]]
        self.assertEqual(len(sources), 5)
        self.assertEqual(sources.count("general"), 2)
        self.assertTrue(found["truncated"])
        self.assertEqual(sources[0], "project")  # equal rank: the project wins the tie
        # The source project's own record answers; its library copy is not repeated.
        own = self.memory("zfs scrub slow")
        self.publish(own, "zfs scrub slow")
        self.assertEqual([m["id"] for m in self.ask("zfs scrub slow", self.p1)["matches"]], [own])
        # Identical text from another project's record and the library appears once.
        self.memory("zfs scrub slow", self.p2)
        self.assertEqual(len(self.ask("zfs scrub slow")["matches"]), 1)

    def test_applicability_conflict_unknown_and_match(self):
        source = self.memory("apt lock held by unattended upgrades")
        self.publish(source, "apt lock held: wait for unattended-upgrades", {"os": "debian"})
        query = "apt lock held"
        self.assertEqual(self.ask(query, environment={"os": "alpine"})["matches"], [])
        unknown = self.ask(query)["matches"][0]
        self.assertEqual(unknown["applicability_missing"], ["os"])
        self.assertTrue(unknown["lead"])
        self.assertIn("applicability unknown", unknown["reasons"])
        known = self.ask(query, environment={"os": "debian"})["matches"][0]
        self.assertEqual(known["applicability_missing"], [])
        self.assertIn("applicability match", known["reasons"])

    def test_relevance_exact_paraphrase_irrelevant_and_degradation(self):
        self.publish(
            self.memory("ECONNREFUSED 127.0.0.1:5432 postgres not listening"),
            "ECONNREFUSED 127.0.0.1:5432: postgres is not listening on the socket",
        )
        self.memory("postgres refused the connection after restart", self.p2)
        exact = self.ask("connect ECONNREFUSED 127.0.0.1:5432")
        self.assertEqual(exact["matches"][0]["source"], "general")
        paraphrased = self.ask("database connection refused by postgres")
        self.assertTrue(paraphrased["matches"])
        self.assertEqual(self.ask("chocolate cake recipe")["matches"], [])
        self.assertEqual(exact["retrieval_mode"], "keyword_only")
        with patch("hub.retrieval.EMBEDDER.embed", return_value=[[0.0] * 384]):
            self.assertEqual(self.ask("postgres refused")["retrieval_mode"], "hybrid")

    def test_publication_inherits_freshness_without_private_review_evidence(self):
        source = self.memory("router latest firmware")
        self.publish(source, "router latest firmware")
        self.p1.memory_review(
            "worker",
            source,
            1,
            "conflict",
            evidence=["private:review"],
            proposed_correction="private proposed correction",
        )
        self.assertEqual(self.ask("router latest firmware", view="current")["matches"], [])
        historical = self.ask("router latest firmware")["matches"][0]
        self.assertEqual(historical["freshness"], "review required")
        self.assertNotIn("private:", json.dumps(historical))
        self.assertNotIn("private proposed", json.dumps(historical))
        self.p1.memory_review(
            "worker", source, 2, "confirm", temporal_kind="durable", evidence=["checked:new"]
        )
        self.assertEqual(
            self.ask("router latest firmware", view="current")["matches"][0]["freshness"], "current"
        )

    def test_one_shared_budget(self):
        self.publish(self.memory("oom killer kills java"), "oom killer kills java " + "x" * 300)
        self.memory("oom killer kills java locally " + "y" * 300, self.p2)
        clipped = self.ask("oom killer java", max_chars=100)
        self.assertEqual(sum(len(m["summary"]) for m in clipped["matches"]), 100)
        self.assertTrue(clipped["truncated"])
        full = self.ask("oom killer java", max_bytes=65536)
        expected = {
            **full,
            "matches": full["matches"][:1],
            "byte_omitted_matches": 1,
            "truncated": True,
        }
        size = len(
            json.dumps(expected, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        )
        bounded = self.ask("oom killer java", max_bytes=size)
        self.assertEqual(bounded["byte_omitted_matches"], 1)
        self.assertLessEqual(len(json.dumps(bounded, separators=(",", ":"))), size)
        with self.assertRaisesRegex(ValueError, "max_chars"):
            self.ask("oom", max_chars=0)

    def test_starter_set_is_proposed_once_and_never_recreated(self):
        first = self.p1.tshoot_seed_starter("boss")["proposed"]
        self.assertGreaterEqual(len(first), 5)
        self.assertEqual(self.p1.tshoot_seed_starter("boss")["proposed"], [])
        self.p1.revoke_memory("boss", first[0]["source_id"])
        self.assertEqual(self.p1.tshoot_seed_starter("boss")["proposed"], [])
        for entry in first[1:]:
            self.p1.tshoot_publication_decide("boss", entry["id"], "publish", "starter review")
        self.assertTrue(self.ask("utilization saturation errors resource")["matches"])

    def test_backup_restore_keeps_the_library_and_publications(self):
        dest = self.publish(self.memory("ntp drift skews logs"), "ntp drift skews logs")["dest_id"]
        made = backup.create(self.s, Path(self.tmp.name) / "backups")
        target = Path(self.tmp.name) / "restored" / "hub.sqlite3"
        target.parent.mkdir()
        backup.restore(Path(self.tmp.name) / "backups" / made["backup"], target)
        restored = Store(target)
        try:
            self.assertEqual(restored.read(library.library_of), "lib")
            found = Work(restored, "p2").tshoot_context("worker", "ntp drift")
            self.assertEqual(found["matches"][0]["id"], dest)
        finally:
            restored.close()


class TransportTest(unittest.TestCase):
    """REST and MCP share the operations, the human-only gate and direct-record disclosure."""

    @classmethod
    def setUpClass(cls):
        cls.server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=0, log_level="critical")
        )
        cls.thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.thread.start()
        while not cls.server.started:
            time.sleep(0.01)
        cls.port = cls.server.servers[0].sockets[0].getsockname()[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True
        cls.thread.join()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        path = os.path.join(self.tmp.name, "hub.sqlite3")
        migrate(path)
        self.s = app.state.store = Store(path)
        api._buckets.clear()
        principals(self.s)
        self.keys = {n: identity.issue_key(self.s, "root", n)["key"] for n in ("worker", "boss")}
        self.keyword = patch("hub.retrieval.EMBEDDER.embed", return_value=None)
        self.keyword.start()

    def tearDown(self):
        self.keyword.stop()
        self.s.close()
        self.tmp.cleanup()

    def req(self, method, path, body=None, key="worker", idem=None):
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=None if body is None else json.dumps(body).encode(),
            method=method,
            headers={"Content-Type": "application/json", "Authorization": "Bearer " + key},
        )
        if idem:
            request.add_header("Idempotency-Key", idem)
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.loads(response.read() or b"null")
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read() or b"null")

    def op(self, project, operation, body, key="worker", idem="k"):
        return self.req(
            "POST", f"/v2/projects/{project}/work/{operation}", body, self.keys[key], idem
        )

    def test_rest_and_mcp(self):
        status, made = self.op(
            "p1",
            "remember",
            {
                "namespace": "ops",
                "kind": "fact",
                "body": "haproxy 503 no server available",
                "provenance": "tested",
                "confidence": 1,
                "evidence": ["t:1"],
            },
            idem="m",
        )
        self.assertEqual(status, 200, made)
        status, proposal = self.op(
            "p1",
            "tshoot_propose",
            {"source_id": made["id"], "body": "haproxy 503: no healthy backend", "evidence": SAFE},
            idem="p",
        )
        self.assertEqual(status, 200, proposal)
        decide = {"proposal_id": proposal["id"], "action": "publish", "reason": "ok"}
        self.assertEqual(self.op("p1", "tshoot_publication_decide", decide, idem="d")[0], 403)
        status, published = self.op("p1", "tshoot_publication_decide", decide, "boss", "d")
        self.assertEqual(status, 200, published)
        dest = published["dest_id"]
        status, found = self.req(
            "POST", "/v2/projects/p2/tshoot/context", {"query": "haproxy 503"}, self.keys["worker"]
        )
        self.assertEqual((status, found["matches"][0]["id"]), (200, dest), found)
        record = f"/v2/projects/lib/records/{dest}"
        self.assertEqual(self.req("GET", record, key=self.keys["worker"])[0], 200)

        async def mcp(expect_visible):
            http = httpx2.AsyncClient(headers={"Authorization": "Bearer " + self.keys["worker"]})
            url = f"http://127.0.0.1:{self.port}/mcp"
            async with Client(streamable_http_client(url, http_client=http), mode="legacy") as c:
                result = await c.call_tool(
                    "work",
                    {
                        "project_id": "p2",
                        "operation": "tshoot_context",
                        "arguments": {"query": "haproxy 503"},
                    },
                )
                self.assertFalse(result.is_error, result.content)
                matches = result.structured_content["result"]["matches"]
                self.assertEqual([m["id"] for m in matches], [dest] if expect_visible else [])
                got = await c.call_tool("record_get", {"project_id": "lib", "record_id": dest})
                self.assertEqual(got.is_error, not expect_visible, got.content)

        asyncio.run(mcp(True))
        status, _ = self.op("p1", "revoke_memory", {"memory_id": made["id"]}, idem="r")
        self.assertEqual(status, 200)
        self.assertEqual(self.req("GET", record, key=self.keys["worker"])[0], 404)
        status, changes = self.req("GET", "/v2/projects/lib/changes", key=self.keys["worker"])
        self.assertNotIn(dest, {c["id"] for c in changes["items"]})
        asyncio.run(mcp(False))
        # The library designation is an audited administrator action.
        root = identity.issue_key(self.s, "root", "root")["key"]
        self.assertEqual(
            self.req("POST", "/v2/admin/tshoot-library", {"project": "p2"}, root)[0], 200
        )
        self.assertEqual(
            self.req("POST", "/v2/admin/tshoot-library", {"project": "lib"}, self.keys["boss"])[0],
            403,
        )


if __name__ == "__main__":
    unittest.main()
