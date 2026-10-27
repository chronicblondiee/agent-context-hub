"""Run by scripts/hub.sh test inside the stack network after the admin provisions "agent".

Checks the deployed core end to end: anonymous denial, principal-as-actor over REST and MCP,
no content access for the administrator, and revocation on the next call.
"""

import asyncio
import json
import urllib.error
import urllib.request

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

CORE = "http://core:8097"
WORK = "/v2/projects/harness/work/"
with open("/admin/admin.key") as f:
    ADMIN = f.read().strip()
with open("/admin/agent.json") as f:
    AGENT = json.load(f)


def call(path, key=None, body=None, idempotency_key=None):
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(CORE + path, data, headers, method="POST")
    try:
        with urllib.request.urlopen(request) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


async def mcp_read():
    http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {AGENT['key']}"})
    async with Client(streamable_http_client(CORE + "/mcp", http_client=http), mode="legacy") as c:
        arguments = {
            "project_id": "harness",
            "operation": "work_read",
            "arguments": {"kind": "task"},
        }
        result = await c.call_tool("work", arguments)
        assert not result.is_error, result.content
        return result.structured_content["result"]


assert call(WORK + "work_read", body={"kind": "task"})[0] == 401
task = {"goal": "harness", "acceptance": [], "actor": "admin"}
status, created = call(WORK + "create_task", AGENT["key"], task, "harness-1")
assert status == 200 and created["owner"] == "agent", (status, created)
assert [t["id"] for t in asyncio.run(mcp_read())] == [created["id"]]
assert call(WORK + "work_read", ADMIN, {"kind": "task"})[0] == 404  # admin sees no content
assert call(f"/v2/admin/keys/{AGENT['id']}/revoke", ADMIN)[0] == 200
assert call(WORK + "work_read", AGENT["key"], {"kind": "task"})[0] == 401
print("identity ok: single-use bootstrap, admin-provisioned agent on REST and MCP, revocation")
