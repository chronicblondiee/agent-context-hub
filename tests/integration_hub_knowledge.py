"""Real-container M4 REST/MCP, verifier, worker, and revocation flow."""

import asyncio
import json
import time
import urllib.error
import urllib.request

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

CORE = "http://core:8097"
BASE = "/v2/projects/harness"


def key(name):
    with open(f"/admin/{name}.json") as source:
        return json.load(source)["key"]


AGENT, VERIFIER, MAINTAINER = (key(name) for name in ("agent", "verifier", "maintainer"))


def call(path, credential, body, idem=None):
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {credential}"}
    if idem:
        headers["Idempotency-Key"] = idem
    request = urllib.request.Request(CORE + path, json.dumps(body).encode(), headers, method="POST")
    try:
        with urllib.request.urlopen(request) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


async def mcp_context():
    http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {AGENT}"})
    async with Client(streamable_http_client(CORE + "/mcp", http_client=http), mode="legacy") as c:
        result = await c.call_tool(
            "context_get", {"project_id": "harness", "query": "Docker daemon"}
        )
        assert not result.is_error, result.content
        return (
            json.dumps(result.structured_content)
            + "\n"
            + "\n".join(getattr(item, "text", "") for item in result.content)
        )


assert call(BASE + "/context", AGENT, {"query": "Docker"})[0] == 200
attempt = {"approach": "Restart Docker daemon", "outcome": "failed", "evidence": ["test:1"]}
status, recorded = call(BASE + "/attempts", AGENT, attempt, "m4-attempt")
assert status == 200 and recorded["id"], (status, recorded)
proposal = {
    "body": "Restart the Docker daemon after clearing a stale socket",
    "problem_key": "docker-daemon",
    "repository_commit": "a" * 40,
    "image_digest": "sha256:" + "b" * 64,
    "checks_sha256": "c" * 64,
}
status, solution = call(BASE + "/solutions", AGENT, proposal, "m4-solution")
assert status == 200 and solution["status"] == "unverified", (status, solution)
assert call(BASE + "/evidence", AGENT, {}, "m4-unauthorized")[0] == 403

deadline = time.monotonic() + 30
while True:
    status, context = call(BASE + "/context", AGENT, {"query": "Docker daemon"})
    assert status == 200, context
    if context["retrieval_mode"] == "hybrid" and any(
        "semantic" in match["reasons"] for match in context["matches"]
    ):
        break
    assert time.monotonic() < deadline, "embedding jobs did not complete"
    time.sleep(0.25)
assert any(match["id"] == solution["id"] for match in context["matches"])
assert solution["id"] in asyncio.run(mcp_context())

evidence = {
    "solution_id": solution["id"],
    "revision": 1,
    "content_sha256": solution["content_sha256"],
    "checks_sha256": "c" * 64,
    "repository_commit": "a" * 40,
    "image_digest": "sha256:" + "b" * 64,
    "result": "pass",
    "artifacts": ["d" * 64],
}
status, accepted = call(BASE + "/evidence", VERIFIER, evidence, "m4-evidence")
assert status == 200 and accepted["status"] == "verified", (status, accepted)
status, context = call(BASE + "/context", AGENT, {"query": "Docker daemon"})
assert status == 200 and any(
    match["id"] == solution["id"] and match["status"] == "verified" for match in context["matches"]
), context
decision = {"revision": 1, "action": "revoke", "reason": "harness revocation"}
status, revoked = call(
    BASE + f"/solutions/{solution['id']}/decisions", MAINTAINER, decision, "m4-revoke"
)
assert status == 200 and revoked["status"] == "revoked", (status, revoked)
status, context = call(BASE + "/context", AGENT, {"query": "Docker daemon"})
assert status == 200 and all(match["id"] != solution["id"] for match in context["matches"])
print("knowledge ok: durable hybrid search, REST/MCP, independent verification, revocation")
