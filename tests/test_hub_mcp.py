"""MCP over Streamable HTTP: same keys and policy as REST; revocation ends an open session."""

import asyncio
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

import httpx2
import uvicorn
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from hub import api, app, identity
from hub.store import Store, migrate


class McpTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        path = os.path.join(self.tmp.name, "hub.sqlite3")
        migrate(path)
        self.s = app.state.store = Store(path)
        api._buckets.clear()
        identity.bootstrap(self.s, "root")
        identity.create_project(self.s, "root", "p1", "one")
        identity.create_principal(self.s, "root", "worker", "agent")
        identity.grant(self.s, "root", "worker", "p1", "contributor")
        identity.create_principal(self.s, "root", "boss", "human")
        identity.grant(self.s, "root", "boss", "p1", "maintainer")
        identity.bind(self.s, "root", "worker", "boss")
        self.key = identity.issue_key(self.s, "root", "worker")
        self.server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=0, log_level="critical")
        )
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()
        while not self.server.started:
            time.sleep(0.01)
        self.url = f"http://127.0.0.1:{self.server.servers[0].sockets[0].getsockname()[1]}/mcp"

    def tearDown(self):
        self.server.should_exit = True
        self.thread.join()
        self.s.close()
        self.tmp.cleanup()

    def client(self, key, **headers):
        http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {key}", **headers})
        return Client(streamable_http_client(self.url, http_client=http), mode="legacy")

    def test_anonymous_mcp_is_rejected(self):
        request = urllib.request.Request(self.url, data=b"{}", method="POST")
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request)
        self.assertEqual(caught.exception.code, 401)

    def test_shared_incident_generic_work_transport(self):
        async def scenario():
            async with self.client(self.key["key"]) as client:
                opened = await client.call_tool(
                    "work",
                    {
                        "project_id": "p1",
                        "operation": "tshoot_open",
                        "arguments": {"target": "synthetic:mcp", "author": "forged"},
                        "idempotency_key": "incident-open",
                    },
                )
                self.assertFalse(opened.is_error, opened.content)
                ident = opened.structured_content["result"]["id"]
                read = await client.call_tool(
                    "work",
                    {
                        "project_id": "p1",
                        "operation": "tshoot_read",
                        "arguments": {"thread_id": ident},
                    },
                )
                self.assertFalse(read.is_error, read.content)
                self.assertEqual(read.structured_content["result"]["events"][0]["actor"], "worker")

        asyncio.run(scenario())

    def test_memory_records_the_client_instance_as_attribution(self):
        async def remember(headers, idem):
            async with self.client(self.key["key"], **headers) as client:
                made = await client.call_tool(
                    "work",
                    {
                        "project_id": "p1",
                        "operation": "remember",
                        "arguments": {
                            "namespace": "ops",
                            "kind": "fact",
                            "body": "mcp memory",
                            "provenance": "tested",
                            "confidence": 1,
                            "evidence": ["test:mcp"],
                        },
                        "idempotency_key": idem,
                    },
                )
                self.assertFalse(made.is_error, made.content)
                ident = made.structured_content["result"]["id"]
                read = await client.call_tool(
                    "record_get", {"project_id": "p1", "record_id": ident}
                )
                self.assertFalse(read.is_error, read.content)
                return json.loads(read.content[0].text)

        # Modern MCP is sessionless, so the client's own instance header wins.
        record = asyncio.run(remember({"X-Agent-Session": "s-mcp"}, "m1"))
        self.assertEqual(
            (record["owner"], record["author"], record["agent_session"]),
            ("boss", "worker", "s-mcp"),
        )
        # Without it, a legacy session's mcp-session-id is the fallback.
        self.assertTrue(asyncio.run(remember({}, "m2"))["agent_session"])

    def test_tools_share_policy_and_revocation_ends_an_open_session(self):
        async def scenario():
            async with self.client(self.key["key"]) as client:
                names = {t.name for t in (await client.list_tools()).tools}
                self.assertEqual(
                    names,
                    {
                        "work",
                        "changes_get",
                        "record_get",
                        "share_record",
                        "context_get",
                        "attempt_record",
                        "solution_propose",
                        "outcome_report",
                        "evidence_submit",
                        "solution_decide",
                    },
                )
                described = {t.name: t.description for t in (await client.list_tools()).tools}
                for operation in api.OPERATIONS:  # generated, so a new operation is never hidden
                    self.assertIn(operation + "(", described["work"])
                self.assertIn("human_decision(task_id", described["work"])
                self.assertIn("attempt", described["record_get"])
                created = await client.call_tool(
                    "work",
                    {
                        "project_id": "p1",
                        "operation": "create_task",
                        "arguments": {"goal": "g", "acceptance": [], "actor": "root"},
                        "idempotency_key": "t1",
                    },
                )
                self.assertFalse(created.is_error, created.content)
                self.assertEqual(created.structured_content["result"]["owner"], "worker")
                for arguments, status in (
                    ({"project_id": "p1", "operation": "create_task",
                      "arguments": {"goal": "g", "acceptance": []}}, "400"),  # no idempotency key
                    ({"project_id": "p2", "operation": "work_read",
                      "arguments": {"kind": "task"}}, "404"),
                ):  # fmt: skip
                    denied = await client.call_tool("work", arguments)
                    self.assertTrue(denied.is_error)
                    self.assertIn(f": {status}: ", denied.content[0].text)
                page = await client.call_tool("changes_get", {"project_id": "p1"})
                self.assertFalse(page.is_error, page.content)
                await asyncio.to_thread(identity.revoke_key, self.s, "root", self.key["id"])
                try:
                    after = await client.call_tool(
                        "work",
                        {
                            "project_id": "p1",
                            "operation": "work_read",
                            "arguments": {"kind": "task"},
                        },
                    )
                except Exception:
                    return  # the transport surfaced the 401
                self.assertTrue(after.is_error, after.content)

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
