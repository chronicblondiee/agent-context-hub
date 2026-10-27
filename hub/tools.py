"""MCP over Streamable HTTP at /mcp, sharing hub.api's authentication and operation policy.

Every HTTP request to /mcp re-authenticates its Bearer key before reaching the MCP session, so
a revoked or expired key stops an established session on its next message. Tools read the
principal from the request that carried the call. No administrative tools are exposed.
"""

import contextlib
import inspect

import anyio
from mcp.server import MCPServer
from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import StrictInt
from starlette.requests import Request

from hub import api, federation
from hub.work import Work

server = MCPServer(
    "agent-context-hub",
    instructions="Durable task, message and memory operations for one granted project. "
    "Writes need an idempotency_key; the authenticated key is always the actor.",
)


async def _run(ctx, fn):
    request = ctx.request_context.request
    principal, store = request.state.principal, request.app.state.store
    try:
        return await anyio.to_thread.run_sync(fn, store, principal)
    except api.HANDLED as error:
        status, message, _ = api.classify(error)
        raise ToolError(f"{status}: {message}") from None


def _signature(operation):
    """`operation(arg, arg=default)`, from the same signature api.call binds arguments against."""
    params = inspect.signature(getattr(Work, operation)).parameters.values()
    shown = [str(p) for p in params if p.name not in {"self", "actor", *api.SERVER_ARGS}]
    human = " (human principals only)" if operation in api.HUMAN_ONLY else ""
    return f"{operation}({', '.join(shown)}){human}"


@server.tool(
    description="Run a work or memory operation, passing its arguments as `arguments`. "
    "Writes need an idempotency_key. Operations:\n"
    # Troubleshooting stays out of default context; the explicit /tshoot skill documents it.
    + "\n".join(_signature(op) for op in api.OPERATIONS if not op.startswith("tshoot_"))
)
async def work(
    project_id: str,
    operation: str,
    ctx: Context,
    arguments: dict | None = None,
    idempotency_key: str | None = None,
) -> dict | list:
    return await _run(
        ctx,
        lambda store, p: api.call(
            store,
            p,
            project_id,
            operation,
            arguments or {},
            idempotency_key,
            # Modern (sessionless) MCP has no mcp-session-id; clients send their own instance ID.
            ctx.request_context.request.headers.get("x-agent-session")
            or ctx.request_context.request.headers.get("mcp-session-id"),
        ),
    )


@server.tool()
async def changes_get(project_id: str, ctx: Context, cursor: int = 0, limit: int = 40) -> dict:
    """A replayable page of changes visible to the caller, after `cursor`."""

    def fn(store, principal):
        api.authorize(principal, project_id, api.OPERATIONS["work_read"][0])
        return Work(store, project_id).changes(principal.id, cursor, limit)

    return await _run(ctx, fn)


@server.tool()
async def record_get(project_id: str, record_id: str, ctx: Context) -> dict:
    """A memory record, attempt or solution the caller may see, by ID. Superseded and revoked
    memory records stay readable."""

    def fn(store, principal):
        api.authorize(principal, project_id, api.OPERATIONS["work_read"][0])
        work = Work(store, project_id)
        found = work.record(principal.id, record_id) or work.knowledge_record(
            principal.id, record_id
        )
        if found is None:
            raise api.Denied(404, "not found")
        return found

    return await _run(ctx, fn)


@server.tool()
async def share_record(
    project_id: str, record_id: str, remote: str, idempotency_key: str, ctx: Context
) -> dict:
    """Explicitly share an owned project-visible memory record with a configured hub peer."""

    def fn(store, principal):
        api.authorize(principal, project_id, api.CONTRIBUTE)
        return federation.share(store, project_id, principal.id, record_id, remote, idempotency_key)

    return await _run(ctx, fn)


@server.tool()
async def context_get(
    project_id: str,
    query: str,
    ctx: Context,
    task_id: str | None = None,
    environment: dict | None = None,
    limit: int = 5,
    max_chars: int = 8000,
    max_bytes: StrictInt | None = None,
) -> dict:
    """Retrieve bounded permitted context, with trust and source reasons. limit is 1 to 5 and
    max_chars 1 to 8000. Optional max_bytes is an exact integer 1 to 65536 bounding
    the complete context object encoded by hub.store.encoded as UTF-8, including
    metadata and byte_omitted_matches. It omits whole ranked-tail matches; errors
    and HTTP/MCP wrappers are outside this budget. None preserves legacy output."""
    return await _run(
        ctx,
        lambda store, p: api.call(
            store,
            p,
            project_id,
            "context_get",
            dict(
                query=query,
                task_id=task_id,
                environment=environment,
                limit=limit,
                max_chars=max_chars,
                max_bytes=max_bytes,
            ),
        ),
    )


async def _knowledge(ctx, project_id, operation, arguments, idempotency_key):
    return await _run(
        ctx, lambda store, p: api.call(store, p, project_id, operation, arguments, idempotency_key)
    )


@server.tool(
    description="Record an approach, observed outcome, and evidence references. Arguments: "
    + _signature("attempt_record")
)
async def attempt_record(
    project_id: str, arguments: dict, idempotency_key: str, ctx: Context
) -> dict:
    return await _knowledge(ctx, project_id, "attempt_record", arguments, idempotency_key)


@server.tool(
    description="Propose an unverified solution or a new revision. Arguments: "
    + _signature("solution_propose")
)
async def solution_propose(
    project_id: str, arguments: dict, idempotency_key: str, ctx: Context
) -> dict:
    return await _knowledge(ctx, project_id, "solution_propose", arguments, idempotency_key)


@server.tool(
    description="Report observed reuse of a specific solution revision. Arguments: "
    + _signature("outcome_report")
)
async def outcome_report(
    project_id: str, arguments: dict, idempotency_key: str, ctx: Context
) -> dict:
    return await _knowledge(ctx, project_id, "outcome_report", arguments, idempotency_key)


@server.tool(
    description="Verifier-only evidence bound to the current solution revision. Arguments: "
    + _signature("evidence_submit")
)
async def evidence_submit(
    project_id: str, arguments: dict, idempotency_key: str, ctx: Context
) -> dict:
    return await _knowledge(ctx, project_id, "evidence_submit", arguments, idempotency_key)


@server.tool(
    description="Human maintainer approval, review, revocation, or supersession. Arguments: "
    + _signature("solution_decide")
)
async def solution_decide(
    project_id: str, arguments: dict, idempotency_key: str, ctx: Context
) -> dict:
    return await _knowledge(ctx, project_id, "solution_decide", arguments, idempotency_key)


class Endpoint:
    """Raw ASGI (a class, so Starlette does not wrap it as a request/response function):
    authenticate, then hand the request to the MCP session manager."""

    async def __call__(self, scope, receive, send):
        request = Request(scope)
        try:
            principal = await anyio.to_thread.run_sync(
                api.authenticate, request.app.state.store, request.headers.get("authorization")
            )
        except api.Denied as error:
            return await api._error(*api.classify(error))(scope, receive, send)
        scope.setdefault("state", {})["principal"] = principal
        await server.session_manager.handle_request(scope, receive, send)


@contextlib.asynccontextmanager
async def lifespan(app):
    # A fresh session manager per server start; one instance cannot be run twice.
    # Host checks guard unauthenticated localhost servers; every request here needs a key.
    server.streamable_http_app(host="0.0.0.0")
    from hub.embed import Worker
    from hub.retrieval import EMBEDDER

    # Some in-process tests attach a fresh store after server startup. The real
    # service attaches one before uvicorn enters lifespan.
    store = getattr(app.state, "store", None)
    worker = Worker(store, EMBEDDER) if store is not None else None
    if worker is not None:
        worker.start()
    try:
        async with server.session_manager.run():
            yield
    finally:
        if worker is not None:
            worker.stop()
