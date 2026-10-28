"""Authenticated REST surface. MCP calls the same `call` and `authorize`, so both share one policy.

Status codes: 401 bad credentials, 403 missing role, 404 no grant or invisible record,
409 conflict or stale session, 413 oversized body, 429 rate or queue limit.
"""

import inspect
import logging
import os
import re
import sqlite3
import threading
import time
from typing import Annotated

from fastapi import APIRouter, Body, Depends, Header, Request, Response
from fastapi.responses import JSONResponse

from hub import backup, federation, identity, library, retrieval
from hub.common import NotFound
from hub.identity import IDENT, KEY
from hub.store import Conflict, Overloaded
from hub.work import Stale, Work

log = logging.getLogger("hub.auth")
MAX_BODY = 1 << 20
RATE = float(os.environ.get("HUB_RATE", "20"))  # requests per second per key; burst 2x

CONTRIBUTE = frozenset({"contributor"})
# operation -> (accepted roles, writes). Roles are additive: any one accepted role suffices.
OPERATIONS = {
    "work_read": (frozenset({"reader", "contributor", "maintainer"}), False),
    "context_get": (frozenset({"reader", "contributor", "maintainer"}), False),
    "tshoot_context": (frozenset({"reader", "contributor", "maintainer"}), False),
    "tshoot_proposals": (frozenset({"maintainer"}), False),
    "tshoot_publication_decide": (frozenset({"maintainer"}), True),
    "tshoot_seed_starter": (frozenset({"maintainer"}), True),
    "memory_claim_get": (frozenset({"reader", "contributor", "maintainer"}), False),
    "memory_review_list": (frozenset({"reader", "contributor", "maintainer"}), False),
    "source_check_claim": (frozenset({"connector"}), True),
    "source_check_complete": (frozenset({"connector"}), True),
    "source_check_status": (frozenset({"maintainer", "connector"}), False),
    "boot_card": (frozenset({"reader", "contributor", "maintainer"}), False),
    "claim_messages": (CONTRIBUTE, False),
    **{
        name: (CONTRIBUTE, True)
        for name in (
            "create_task",
            "resume",
            "heartbeat",
            "checkpoint",
            "finish",
            "cancel_task",
            "begin_action",
            "action_outcome",
            "send_message",
            "acknowledge",
            "remember",
            "memory_review",
            "memory_source_bind",
            "memory_source_retry",
            "memory_review_bulk",
            "revise_memory",
            "attempt_record",
            "solution_propose",
            "outcome_report",
            "tshoot_propose",
        )
    },
    "evidence_submit": (frozenset({"verifier"}), True),
    "solution_decide": (frozenset({"maintainer"}), True),
    "revoke_memory": (frozenset({"contributor", "maintainer"}), True),
    "human_decision": (frozenset({"maintainer"}), True),
}
OPERATIONS.update(
    {
        name: (
            OPERATIONS["work_read"][0] if name in ("tshoot_list", "tshoot_read") else CONTRIBUTE,
            name not in ("tshoot_list", "tshoot_read"),
        )
        for name in (
            "tshoot_open",
            "tshoot_list",
            "tshoot_read",
            "tshoot_append",
            "tshoot_close",
            "tshoot_action_reserve",
            "tshoot_action_start",
            "tshoot_action_heartbeat",
            "tshoot_action_outcome",
            "tshoot_action_reconcile",
        )
    }
)
HUMAN_ONLY = {
    "human_decision",
    "solution_decide",
    "tshoot_publication_decide",
    "tshoot_seed_starter",
}
SERVER_ARGS = {"actor", "maintainer"}  # supplied from the principal, never from the body
AGENT_SESSION = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
IGNORED_ARGS = {"actor", "author"}


class Denied(Exception):
    def __init__(self, status, message, headers=None):
        super().__init__(message)
        self.status, self.headers = status, headers


_buckets, _bucket_lock = {}, threading.Lock()


def _rate(key_id):
    # ponytail: in-process token bucket, resets on restart; share via SQLite if replicas appear.
    now = time.monotonic()
    with _bucket_lock:
        tokens, last = _buckets.get(key_id, (2 * RATE, now))
        tokens = min(2 * RATE, tokens + (now - last) * RATE)
        if tokens < 1:
            _buckets[key_id] = (tokens, now)
            raise Denied(429, "rate limit exceeded", {"Retry-After": "1"})
        _buckets[key_id] = (tokens - 1, now)


def authenticate(store, authorization):
    scheme, _, credential = (authorization or "").partition(" ")
    principal = identity.authenticate(store, credential) if scheme.lower() == "bearer" else None
    if principal is None:
        match = KEY.match(credential)
        log.warning("authentication failed key_id=%s", match.group(1) if match else "-")
        raise Denied(401, "a valid key is required", {"WWW-Authenticate": "Bearer"})
    _rate(principal.key_id)
    return principal


def authorize(principal, project_id, accepted):
    """The principal's roles in the project; no grant reads as a missing project."""
    roles = principal.roles(project_id) if IDENT.match(project_id or "") else frozenset()
    if not roles & accepted:
        log.warning("denied principal=%s project=%s", principal.id, project_id)
    if not roles:
        raise Denied(404, "not found")
    if not roles & accepted:
        raise Denied(403, f"requires one of: {', '.join(sorted(accepted))}")
    return roles


def call(
    store, principal, project_id, operation, arguments, idempotency_key=None, agent_session=None
):
    if operation not in OPERATIONS:
        raise Denied(404, "unknown operation")
    accepted, writes = OPERATIONS[operation]
    roles = authorize(principal, project_id, accepted)
    if operation in HUMAN_ONLY and principal.kind != "human":
        raise Denied(403, "requires a human principal")
    if operation == "evidence_submit" and principal.kind != "verifier":
        raise Denied(403, "requires a verifier principal")
    if writes and not idempotency_key:
        raise Denied(400, "writes require an Idempotency-Key")
    if not isinstance(arguments, dict):
        raise Denied(400, "arguments must be an object")
    arguments = {k: v for k, v in arguments.items() if k not in IGNORED_ARGS}
    signature = inspect.signature(getattr(Work, operation))
    unknown = set(arguments) - (set(signature.parameters) - {"self"} - SERVER_ARGS)
    if unknown:
        raise Denied(400, f"unknown arguments: {', '.join(sorted(unknown))}")
    try:
        signature.bind(None, principal.id, **arguments)
    except TypeError as error:
        raise Denied(400, str(error)) from None
    request = {"operation": operation, "arguments": arguments}
    if operation == "revoke_memory":
        arguments = {**arguments, "maintainer": "maintainer" in roles}
    # Attribution only: which client instance of the principal wrote; never authority.
    session = agent_session if AGENT_SESSION.match(agent_session or "") else None
    work = Work(store, project_id, idempotency_key if writes else None, request, session)
    return getattr(work, operation)(principal.id, **arguments)


def _principal(request: Request, authorization: Annotated[str | None, Header()] = None):
    return authenticate(request.app.state.store, authorization)


Caller = Annotated[identity.Principal, Depends(_principal)]
Json = Annotated[dict | None, Body()]
router = APIRouter(prefix="/v2")


@router.get("/me")
def me(principal: Caller):
    return {
        "id": principal.id,
        "kind": principal.kind,
        "acts_for": principal.acts_for,
        "grants": {p: sorted(r) for p, r in principal.grants.items()},
        "capabilities": sorted(OPERATIONS),
        "workflow_version": 1,
    }


@router.post("/projects/{project_id}/work/{operation}")
def work(
    project_id: str,
    operation: str,
    request: Request,
    principal: Caller,
    arguments: Json = None,
    idempotency_key: Annotated[str | None, Header()] = None,
    x_agent_session: Annotated[str | None, Header()] = None,
):
    store = request.app.state.store
    return call(
        store, principal, project_id, operation, arguments or {}, idempotency_key, x_agent_session
    )


@router.get("/projects/{project_id}/changes")
def changes(project_id: str, request: Request, principal: Caller, cursor: int = 0, limit: int = 40):
    authorize(principal, project_id, OPERATIONS["work_read"][0])
    return Work(request.app.state.store, project_id).changes(principal.id, cursor, limit)


@router.get("/projects/{project_id}/records/{record_id}")
def record(project_id: str, record_id: str, request: Request, principal: Caller):
    authorize(principal, project_id, OPERATIONS["work_read"][0])
    work = Work(request.app.state.store, project_id)
    found = work.record(principal.id, record_id) or work.knowledge_record(principal.id, record_id)
    if found is None:
        raise Denied(404, "not found")
    return found


def _post_operation(project_id, operation, request, principal, arguments, idempotency_key):
    return call(
        request.app.state.store, principal, project_id, operation, arguments or {}, idempotency_key
    )


def _timed_search(project_id, operation, request, response, principal, arguments):
    """Server-Timing splits queueing for the one search slot from the search itself."""
    result = _post_operation(project_id, operation, request, principal, arguments, None)
    if timing := retrieval.TIMING.get():
        queue, search = (round(s * 1000, 1) for s in timing)
        response.headers["Server-Timing"] = f"queue;dur={queue}, search;dur={search}"
    return result


@router.post("/projects/{project_id}/context")
def context_get(
    project_id: str, request: Request, response: Response, principal: Caller, arguments: Json = None
):
    return _timed_search(project_id, "context_get", request, response, principal, arguments)


@router.post("/projects/{project_id}/tshoot/context")
def tshoot_context(
    project_id: str, request: Request, response: Response, principal: Caller, arguments: Json = None
):
    return _timed_search(project_id, "tshoot_context", request, response, principal, arguments)


@router.post("/projects/{project_id}/attempts")
def attempt_record(
    project_id: str,
    request: Request,
    principal: Caller,
    arguments: Json = None,
    idempotency_key: Annotated[str | None, Header()] = None,
):
    return _post_operation(
        project_id, "attempt_record", request, principal, arguments, idempotency_key
    )


@router.post("/projects/{project_id}/solutions")
def solution_propose(
    project_id: str,
    request: Request,
    principal: Caller,
    arguments: Json = None,
    idempotency_key: Annotated[str | None, Header()] = None,
):
    return _post_operation(
        project_id, "solution_propose", request, principal, arguments, idempotency_key
    )


@router.post("/projects/{project_id}/outcomes")
def outcome_report(
    project_id: str,
    request: Request,
    principal: Caller,
    arguments: Json = None,
    idempotency_key: Annotated[str | None, Header()] = None,
):
    return _post_operation(
        project_id, "outcome_report", request, principal, arguments, idempotency_key
    )


@router.post("/projects/{project_id}/evidence")
def evidence_submit(
    project_id: str,
    request: Request,
    principal: Caller,
    arguments: Json = None,
    idempotency_key: Annotated[str | None, Header()] = None,
):
    return _post_operation(
        project_id, "evidence_submit", request, principal, arguments, idempotency_key
    )


@router.post("/projects/{project_id}/solutions/{solution_id}/decisions")
def solution_decide(
    project_id: str,
    solution_id: str,
    request: Request,
    principal: Caller,
    arguments: Json = None,
    idempotency_key: Annotated[str | None, Header()] = None,
):
    return _post_operation(
        project_id,
        "solution_decide",
        request,
        principal,
        {**(arguments or {}), "solution_id": solution_id},
        idempotency_key,
    )


def _admin(principal: Caller):
    if not principal.service_admin:
        raise Denied(403, "requires a service administrator")
    return principal


Admin = Annotated[identity.Principal, Depends(_admin)]


# Admin writes take no Idempotency-Key: a replay would store issued key secrets.
@router.post("/admin/projects")
def admin_project(request: Request, admin: Admin, body: Json = None):
    body = body or {}
    store = request.app.state.store
    return identity.create_project(store, admin.id, body.get("id"), body.get("name", ""))


@router.post("/admin/tshoot-library")
def admin_tshoot_library(request: Request, admin: Admin, body: Json = None):
    return library.configure(request.app.state.store, admin.id, (body or {}).get("project"))


@router.post("/admin/principals")
def admin_principal(request: Request, admin: Admin, body: Json = None):
    body = body or {}
    return identity.create_principal(
        request.app.state.store,
        admin.id,
        body.get("id"),
        body.get("kind"),
        bool(body.get("service_admin", False)),
        body.get("acts_for"),
    )


@router.post("/admin/principals/{principal_id}/owner")
def admin_bind(principal_id: str, request: Request, admin: Admin, body: Json = None):
    return identity.bind(request.app.state.store, admin.id, principal_id, (body or {}).get("human"))


@router.post("/admin/grants")
def admin_grant(request: Request, admin: Admin, body: Json = None):
    body = body or {}
    return identity.grant(
        request.app.state.store,
        admin.id,
        body.get("principal"),
        body.get("project"),
        body.get("role"),
        revoke=bool(body.get("revoke", False)),
    )


@router.post("/admin/keys")
def admin_key(request: Request, admin: Admin, body: Json = None):
    body = body or {}
    store = request.app.state.store
    return identity.issue_key(store, admin.id, body.get("principal"), body.get("days", 90))


@router.post("/admin/keys/{key_id}/rotate")
def admin_rotate(key_id: str, request: Request, admin: Admin, body: Json = None):
    body = body or {}
    store = request.app.state.store
    overlap, days = body.get("overlap_s", 0), body.get("days", 90)
    return identity.rotate_key(store, admin.id, key_id, overlap, days)


@router.post("/admin/keys/{key_id}/revoke")
def admin_revoke(key_id: str, request: Request, admin: Admin):
    return identity.revoke_key(request.app.state.store, admin.id, key_id)


@router.post("/admin/backups")
def admin_backup(request: Request, admin: Admin):
    store = request.app.state.store
    result = backup.create(store, os.environ.get("HUB_BACKUP_DIR", "/backups"))
    store.mutate(
        identity.SYSTEM,
        admin.id,
        lambda tx: tx.audit(
            "backup.create", result["backup"], {"schema": result["schema_version"]}
        ),
    )
    return result


@router.post("/admin/federation/peers")
def admin_peer(request: Request, admin: Admin, body: Json = None):
    body = body or {}
    return federation.peer(
        request.app.state.store,
        admin.id,
        body.get("project"),
        body.get("remote"),
        body.get("transport"),
    )


@router.post("/projects/{project_id}/shares")
def share_record(
    project_id: str,
    request: Request,
    principal: Caller,
    body: Json = None,
    idempotency_key: Annotated[str | None, Header()] = None,
):
    authorize(principal, project_id, CONTRIBUTE)
    body = body or {}
    return federation.share(
        request.app.state.store,
        project_id,
        principal.id,
        body.get("record_id"),
        body.get("remote"),
        idempotency_key,
    )


def _transport(store, principal, project, origin=None):
    authorize(principal, project, frozenset({"connector"}))
    if principal.kind != "connector":
        raise Denied(403, "transport connector required")
    row = store.read(
        lambda db: db.execute(
            "SELECT 1 FROM federation_peers WHERE project_id=? AND transport_id=? "
            + ("AND remote_project=? " if origin else "")
            + "AND enabled=1 LIMIT 1",
            [project, principal.id, *([origin] if origin else [])],
        ).fetchone()
    )
    if not row:
        raise Denied(403, "configured transport required")


@router.get("/projects/{project_id}/federation/outbox")
def federation_outbox(project_id: str, request: Request, principal: Caller):
    _transport(request.app.state.store, principal, project_id)
    return federation.outbox(request.app.state.store, project_id, principal.id)


@router.post("/projects/{project_id}/federation/incoming/{origin}")
def federation_incoming(
    project_id: str,
    origin: str,
    request: Request,
    principal: Caller,
    body: Json = None,
):
    _transport(request.app.state.store, principal, project_id, origin)
    return federation.incoming(
        request.app.state.store, project_id, origin, principal.id, body or {}
    )


@router.post("/projects/{project_id}/federation/receipts/{origin}")
def federation_receipt(
    project_id: str,
    origin: str,
    request: Request,
    principal: Caller,
    body: Json = None,
):
    _transport(request.app.state.store, principal, project_id, origin)
    return federation.receipt(
        request.app.state.store, project_id, origin, principal.id, (body or {}).get("applied")
    )


def _error(status, message, headers=None):
    return JSONResponse({"error": message}, status, headers=headers)


HANDLED = (Denied, Overloaded, Conflict, sqlite3.IntegrityError, ValueError)


def classify(error):
    """(status, message, headers) for an expected error; REST and MCP report the same."""
    if isinstance(error, Denied):
        return error.status, str(error), error.headers
    if isinstance(error, NotFound):
        return 404, "not found", None
    if isinstance(error, Overloaded):
        return 429, "write queue full", {"Retry-After": "1"}
    if isinstance(error, (Conflict, Stale)):
        return 409, str(error), None
    if isinstance(error, sqlite3.IntegrityError):
        return 409, "conflicts with existing state", None
    return 400, str(error), None


def install(app):
    app.include_router(router)
    for kind in HANDLED:
        app.add_exception_handler(kind, lambda request, error: _error(*classify(error)))
    app.add_middleware(BodyLimit)


class BodyLimit:
    """Buffers at most MAX_BODY request bytes, chunked or not; larger requests get 413."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        length = dict(scope["headers"]).get(b"content-length")
        if length and length.isdigit() and int(length) > MAX_BODY:
            return await _error(413, "request body exceeds 1 MiB")(scope, receive, send)
        body, more = b"", True
        while more:
            message = await receive()
            if message["type"] != "http.request":
                return
            body += message.get("body", b"")
            more = message.get("more_body", False)
            if len(body) > MAX_BODY:
                return await _error(413, "request body exceeds 1 MiB")(scope, receive, send)
        replayed = False

        async def replay():
            nonlocal replayed
            if replayed:
                return await receive()
            replayed = True
            return {"type": "http.request", "body": body, "more_body": False}

        return await self.app(scope, replay, send)
