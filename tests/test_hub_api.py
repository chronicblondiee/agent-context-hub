"""REST contracts over a real server: authentication, grants, status codes, limits."""

import http.client
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

import uvicorn

from hub import api, app, identity
from hub.store import Overloaded, Store, migrate


class ApiTest(unittest.TestCase):
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
        self.root = identity.bootstrap(self.s, "root")["key"]
        for project in ("p1", "p2"):
            identity.create_project(self.s, "root", project, project)
        self.keys = {}
        for name, kind, grants in (
            ("worker", "agent", [("p1", "contributor"), ("p1", "maintainer")]),
            ("peer", "agent", [("p1", "contributor")]),
            ("viewer", "agent", [("p1", "reader")]),
            ("boss", "human", [("p1", "maintainer")]),
            ("lead", "human", [("p1", "maintainer")]),
        ):
            identity.create_principal(self.s, "root", name, kind)
            for project, role in grants:
                identity.grant(self.s, "root", name, project, role)
            self.keys[name] = identity.issue_key(self.s, "root", name)
        identity.bind(self.s, "root", "worker", "boss")
        identity.bind(self.s, "root", "peer", "lead")

    def tearDown(self):
        self.s.close()
        self.tmp.cleanup()

    def req(self, method, path, body=None, key="worker", idem=None, headers=None):
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=None if body is None else json.dumps(body).encode(),
            method=method,
            headers={"Content-Type": "application/json", **(headers or {})},
        )
        if key:
            request.add_header("Authorization", "Bearer " + self.keys.get(key, {"key": key})["key"])
        if idem:
            request.add_header("Idempotency-Key", idem)
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.loads(response.read() or b"null")
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read() or b"null")

    def op(self, operation, body=None, key="worker", idem="k", project="p1"):
        return self.req("POST", f"/v2/projects/{project}/work/{operation}", body or {}, key, idem)

    def task(self, key="worker", idem="t"):
        status, task = self.op("create_task", {"goal": "g", "acceptance": []}, key, idem)
        self.assertEqual(status, 200, task)
        return task

    def test_only_liveness_is_anonymous(self):
        self.assertEqual(self.req("GET", "/health/live", key=None)[0], 200)
        for method, path in (
            ("POST", "/v2/projects/p1/work/work_read"),
            ("GET", "/v2/projects/p1/changes"),
            ("GET", "/v2/projects/p1/records/x"),
            ("POST", "/v2/admin/principals"),
        ):
            self.assertEqual(self.req(method, path, {}, key=None)[0], 401, path)
            self.assertEqual(self.req(method, path, {}, key="hub_bogus")[0], 401, path)
        self.assertEqual(self.req("GET", "/docs", key=None)[0], 404)

    def test_grants_roles_and_admin_separation(self):
        self.assertEqual(self.op("work_read", {"kind": "task"}, project="p2")[0], 404)
        self.assertEqual(self.op("work_read", {"kind": "task"}, project="_system")[0], 404)
        self.assertEqual(self.op("create_task", {"goal": "g", "acceptance": []}, "viewer")[0], 403)
        self.assertEqual(self.op("work_read", {"kind": "task"}, "viewer")[0], 200)
        # Service administration grants no content access.
        self.keys["root"] = {"key": self.root}
        self.assertEqual(self.op("work_read", {"kind": "task"}, "root")[0], 404)
        self.assertEqual(self.req("GET", "/v2/projects/p1/changes", key="root")[0], 404)
        body = {"id": "intruder", "kind": "agent"}
        self.assertEqual(self.req("POST", "/v2/admin/principals", body, key="worker")[0], 403)
        self.assertEqual(self.req("POST", "/v2/admin/principals", body, key="root")[0], 200)
        self.assertEqual(self.req("POST", "/v2/admin/principals", body, key="root")[0], 409)

    def test_knowledge_routes_share_roles_and_evidence_gate(self):
        identity.create_principal(self.s, "root", "verifier", "verifier")
        identity.grant(self.s, "root", "verifier", "p1", "verifier")
        self.keys["verifier"] = identity.issue_key(self.s, "root", "verifier")
        proposal = {
            "body": "Restart the Docker service",
            "problem_key": "docker-restart",
            "repository_commit": "a" * 40,
            "image_digest": "sha256:" + "b" * 64,
            "checks_sha256": "c" * 64,
        }
        base = "/v2/projects/p1"
        self.assertEqual(self.req("POST", base + "/solutions", proposal, "viewer", "s1")[0], 403)
        status, created = self.req("POST", base + "/solutions", proposal, "worker", "s1")
        self.assertEqual(status, 200, created)
        self.assertEqual(
            self.req("POST", base + "/solutions", proposal, "worker", "s1")[1], created
        )
        status, context = self.req("POST", base + "/context", {"query": "Docker service"}, "viewer")
        self.assertEqual(status, 200, context)
        self.assertEqual(context["matches"][0]["status"], "unverified")
        evidence = {
            "solution_id": created["id"],
            "revision": 1,
            "content_sha256": created["content_sha256"],
            "checks_sha256": "c" * 64,
            "repository_commit": "a" * 40,
            "image_digest": "sha256:" + "b" * 64,
            "result": "pass",
            "artifacts": ["d" * 64],
        }
        self.assertEqual(self.req("POST", base + "/evidence", evidence, "worker", "e1")[0], 403)
        self.assertEqual(
            self.req("POST", base + "/evidence", evidence, "verifier", "e1")[1]["status"],
            "verified",
        )
        self.assertEqual(
            self.req("POST", base + "/context", {"query": "Docker service"}, "viewer")[1][
                "matches"
            ][0]["status"],
            "verified",
        )
        decision = {"revision": 1, "action": "revoke", "reason": "obsolete"}
        path = base + "/solutions/" + created["id"] + "/decisions"
        self.assertEqual(self.req("POST", path, decision, "worker", "d1")[0], 403)
        self.assertEqual(self.req("POST", path, decision, "boss", "d1")[1]["status"], "revoked")
        self.assertEqual(
            self.req("POST", base + "/context", {"query": "Docker service"}, "viewer")[1][
                "matches"
            ],
            [],
        )
        self.assertEqual(
            self.req(
                "POST",
                base + "/outcomes",
                {
                    "solution_id": "missing",
                    "revision": 1,
                    "result": "failure",
                    "evidence": ["test:missing"],
                },
                "worker",
                "missing-outcome",
            )[0],
            404,
        )
        self.assertEqual(
            self.req(
                "POST", base + "/solutions/missing/decisions", decision, "boss", "missing-decision"
            )[0],
            404,
        )

    def test_context_reports_queue_and_search_time(self):
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/v2/projects/p1/context",
            data=json.dumps({"query": "docker"}).encode(),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + self.keys["worker"]["key"],
            },
        )
        with patch("hub.retrieval.EMBEDDER.embed", return_value=None):
            with urllib.request.urlopen(request) as response:
                timing = response.headers["Server-Timing"]
        self.assertRegex(timing, r"^queue;dur=[\d.]+, search;dur=[\d.]+$")

    def test_context_bytes_validation_access_and_private_owners(self):
        memory = {
            "namespace": "n",
            "kind": "fact",
            "body": "docker restart 雪",
            "provenance": "tested",
            "confidence": 1,
            "evidence": ["test:bytes"],
        }
        for i in range(3):
            self.assertEqual(self.op("remember", memory, idem=f"byte-{i}")[0], 200)
        self.assertEqual(
            self.op("remember", {**memory, "visibility": "private"}, key="peer", idem="private")[0],
            200,
        )
        with patch("hub.retrieval.EMBEDDER.embed", return_value=None):
            for suffix in ("context", "work/context_get"):
                path = "/v2/projects/p1/" + suffix
                args = {"query": "docker restart", "max_bytes": 65536}
                status, full = self.req("POST", path, args)
                self.assertEqual(status, 200, full)
                self.assertEqual(len(full["matches"]), 3)
                expected = {
                    **full,
                    "matches": full["matches"][:1],
                    "truncated": True,
                    "byte_omitted_matches": 2,
                }
                budget = len(
                    json.dumps(
                        expected, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                )
                self.assertEqual(
                    self.req("POST", path, {**args, "max_bytes": budget}), (200, expected)
                )
                for row in expected["matches"]:
                    status, record = self.req("GET", f"/v2/projects/p1/records/{row['id']}")
                    self.assertEqual((status, record["id"]), (200, row["id"]))
                for invalid in (True, False, "1024", 1.5, 0, -1, 65537, 1):
                    status, error = self.req("POST", path, {**args, "max_bytes": invalid})
                    self.assertEqual(status, 400, error)
                    self.assertIn("max_bytes", error["error"])
                self.assertEqual(self.req("POST", path, args, key=None)[0], 401)
                self.assertEqual(self.req("POST", path.replace("p1", "p2"), args)[0], 404)

    def test_principal_is_the_actor(self):
        status, task = self.op(
            "create_task", {"goal": "g", "acceptance": [], "actor": "boss", "author": "boss"}
        )
        self.assertEqual((status, task["owner"]), (200, "worker"))
        status, error = self.op("create_task", {"goal": "g", "acceptance": [], "owner": "boss"})
        self.assertEqual(status, 400, error)
        self.assertIn("owner", error["error"])
        self.assertEqual(self.op("create_task", {"acceptance": []})[0], 400)  # missing goal
        self.assertEqual(self.op("revoke_memory", {"memory_id": "x", "maintainer": True})[0], 400)

    def test_memory_belongs_to_the_bound_human_with_session_attribution(self):
        memory = {
            "namespace": "ns",
            "kind": "fact",
            "body": "b",
            "provenance": "tested",
            "confidence": 1,
            "evidence": ["test:e"],
        }
        self.assertEqual(self.req("GET", "/v2/me")[1]["acts_for"], "boss")
        self.assertEqual(self.op("remember", {**memory, "agent_session": "forged"})[0], 400)
        path = "/v2/projects/p1/work/remember"
        status, made = self.req("POST", path, memory, idem="m1", headers={"X-Agent-Session": "s-1"})
        self.assertEqual(status, 200, made)
        status, record = self.req("GET", f"/v2/projects/p1/records/{made['id']}")
        self.assertEqual(
            (record["owner"], record["author"], record["agent_session"]), ("boss", "worker", "s-1")
        )
        bind = "/v2/admin/principals/peer/owner"
        self.assertEqual(self.req("POST", bind, {"human": "boss"}, key="boss")[0], 403)
        status, bound = self.req("POST", bind, {"human": "boss"}, key=self.root)
        self.assertEqual((status, bound["acts_for"]), (200, "boss"))
        revision = {"memory_id": made["id"], "body": "c", "provenance": "tested"}
        revision |= {"confidence": 1, "evidence": ["test:f"]}
        status, _ = self.op("revise_memory", revision, "peer", "m2")
        self.assertEqual(status, 200)  # peer now acts for the same human

    def test_idempotency_key_required_replayed_and_scoped(self):
        self.assertEqual(self.op("create_task", {"goal": "g", "acceptance": []}, idem=None)[0], 400)
        first = self.task(idem="same")
        self.assertEqual(self.task(idem="same"), first)
        status, _ = self.op("create_task", {"goal": "other", "acceptance": []}, idem="same")
        self.assertEqual(status, 409)
        self.assertNotEqual(self.task("peer", idem="same")["id"], first["id"])

    def test_stale_session_conflicts_and_human_decision_needs_a_human(self):
        task = self.task()
        status, packet = self.op("resume", {"task_id": task["id"]}, idem="r1")
        self.assertEqual(status, 200, packet)
        fence = {"session_id": "wrong", "generation": 1}
        self.assertEqual(self.op("heartbeat", fence, idem="h1")[0], 409)
        decision = {"task_id": task["id"], "decision": "stop", "evidence": ["user:x"]}
        self.assertEqual(self.op("human_decision", decision, idem="d1")[0], 403)
        self.assertEqual(self.op("human_decision", decision, "boss", idem="d1")[0], 200)

    def test_records_changes_and_maintainer_revocation(self):
        memory = {
            "namespace": "ns",
            "kind": "fact",
            "body": "b",
            "provenance": "tested",
            "confidence": 1,
            "evidence": ["test:e"],
        }
        _, private = self.op("remember", {**memory, "visibility": "private"}, idem="m1")
        _, shared = self.op("remember", memory, "peer", idem="m2")
        self.assertEqual(self.req("GET", f"/v2/projects/p1/records/{private['id']}")[0], 200)
        path = f"/v2/projects/p1/records/{private['id']}"
        self.assertEqual(self.req("GET", path, key="peer")[0], 404)
        self.assertEqual(self.op("revoke_memory", {"memory_id": private["id"]}, "peer")[0], 400)
        status, _ = self.op("revoke_memory", {"memory_id": shared["id"]}, idem="v1")
        self.assertEqual(status, 200)  # worker holds maintainer in p1
        status, page = self.req("GET", "/v2/projects/p1/changes?cursor=0&limit=1000", key="peer")
        self.assertEqual(status, 200)
        self.assertNotIn(private["id"], {i["id"] for i in page["items"]})

    def test_revocation_applies_to_the_next_call(self):
        self.assertEqual(self.op("work_read", {"kind": "task"})[0], 200)
        identity.revoke_key(self.s, "root", self.keys["worker"]["id"])
        self.assertEqual(self.op("work_read", {"kind": "task"})[0], 401)
        identity.grant(self.s, "root", "viewer", "p1", "reader", revoke=True)
        self.assertEqual(self.op("work_read", {"kind": "task"}, "viewer")[0], 404)

    def test_body_limit(self):
        big = json.dumps({"goal": "x" * (1 << 20)}).encode()
        for headers in ({"Content-Length": str(len(big))}, {"Transfer-Encoding": "chunked"}):
            con = http.client.HTTPConnection("127.0.0.1", self.port)
            con.putrequest("POST", "/v2/projects/p1/work/create_task")
            for name, value in headers.items():
                con.putheader(name, value)
            con.putheader("Authorization", "Bearer " + self.keys["worker"]["key"])
            con.endheaders()
            try:
                if "Transfer-Encoding" in headers:
                    for i in range(0, len(big), 65536):
                        chunk = big[i : i + 65536]
                        con.send(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                    con.send(b"0\r\n\r\n")
                else:
                    con.send(big)
            except (BrokenPipeError, ConnectionResetError):
                pass  # the server may answer before reading the whole body
            self.assertEqual(con.getresponse().status, 413, headers)
            con.close()

    def test_rate_and_queue_limits_return_429(self):
        with patch.object(api, "RATE", 1.0):
            api._buckets.clear()
            codes = [self.op("work_read", {"kind": "task"})[0] for _ in range(4)]
        self.assertEqual(codes[:2], [200, 200])
        self.assertIn(429, codes)
        api._buckets.clear()
        with patch.object(Store, "mutate", side_effect=Overloaded("full")):
            self.assertEqual(self.op("create_task", {"goal": "g", "acceptance": []})[0], 429)

    def test_federation_transport_routes_are_project_bound(self):
        self.keys["root"] = {"key": self.root}
        self.req("POST", "/v2/admin/principals", {"id": "bridge", "kind": "connector"}, "root")
        self.req(
            "POST",
            "/v2/admin/grants",
            {"principal": "bridge", "project": "p1", "role": "connector"},
            "root",
        )
        self.keys["bridge"] = self.req("POST", "/v2/admin/keys", {"principal": "bridge"}, "root")[1]
        peer = {"project": "p1", "remote": "p2", "transport": "bridge"}
        self.assertEqual(self.req("POST", "/v2/admin/federation/peers", peer, "root")[0], 200)
        status, created = self.op(
            "remember",
            {
                "namespace": "ops",
                "kind": "fact",
                "body": "socket repair",
                "provenance": "tested",
                "confidence": 0.9,
                "evidence": ["test:one"],
            },
        )
        self.assertEqual(status, 200)
        share = {"record_id": created["id"], "remote": "p2"}
        self.assertEqual(self.req("POST", "/v2/projects/p1/shares", share, "viewer", "s")[0], 403)
        self.assertEqual(self.req("POST", "/v2/projects/p1/shares", share, "worker", "s")[0], 200)
        path = "/v2/projects/p1/federation/outbox"
        self.assertEqual(self.req("GET", path, key="worker")[0], 403)
        status, out = self.req("GET", path, key="bridge")
        self.assertEqual((status, len(out)), (200, 1))
        self.assertEqual(out[0]["event"]["record"]["body"], "socket repair")
        self.assertEqual(
            self.req(
                "POST",
                "/v2/projects/p1/federation/receipts/p2",
                {"applied": out[0]["event"]["id"]},
                "bridge",
            )[0],
            200,
        )
        self.assertEqual(self.req("GET", path, key="bridge")[1], [])


if __name__ == "__main__":
    unittest.main()

    def test_freshness_review_roles_fencing_and_views(self):
        status, made = self.op(
            "remember",
            dict(
                namespace="ops",
                kind="fact",
                body="router firmware",
                provenance="stated",
                confidence=1,
                evidence=["source:test"],
            ),
            idem="fresh-memory",
        )
        self.assertEqual(status, 200)
        args = dict(memory_id=made["id"], expected_revision=1, action="historical")
        self.assertEqual(self.op("memory_review", args, key="viewer", idem="review-denied")[0], 403)
        self.assertEqual(self.op("memory_review", args, key="peer", idem="review-other")[0], 400)
        self.assertEqual(self.op("memory_review", args, idem="review-ok")[0], 200)
        self.assertEqual(self.op("memory_review", args, idem="review-stale")[0], 409)
        self.assertEqual(self.op("context_get", dict(query="router"))[1]["matches"], [])
        self.assertEqual(
            self.op("context_get", dict(query="router", view="history"))[1]["matches"][0]["id"],
            made["id"],
        )
        self.assertEqual(self.op("source_check_claim", {}, idem="claim-denied")[0], 403)
