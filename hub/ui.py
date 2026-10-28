"""Operator web UI: server-rendered pages of the ongoing workflow and audit state.

Off by default. HUB_UI=1 (loopback only) needs no sign-in to view; HUB_UI=auth
(HTTPS) asks for a human principal's hub key first and keeps it in a Secure, HttpOnly,
SameSite=Strict cookie, checked on every request so revoking the key signs the viewer out.
Private memory appears only as counts. Every action form carries the operator's
own hub key and runs through hub.api.call, so it has exactly that key's authority (revoking needs
ownership or maintainer, solution decisions a human maintainer). Cross-site posts are refused.
"""

import datetime
import html
import json
import os
import string
import uuid
from pathlib import Path
from urllib.parse import quote, urlsplit

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from hub import api, identity
from hub.library import disclosable
from hub.store import now_us

COOKIE = "hub_ui_key"
DAY_US = 86_400_000_000
OPEN = ("/ui/login", "/ui/logout")


def viewer(request: Request):
    """In HUB_UI=auth, every page needs the cookie of a valid, unrevoked human key."""
    if os.environ.get("HUB_UI") != "auth" or request.url.path in OPEN:
        return
    principal = identity.authenticate(request.app.state.store, request.cookies.get(COOKIE, ""))
    if principal is None or principal.kind != "human":
        raise HTTPException(303, headers={"Location": "/ui/login"})


router = APIRouter(prefix="/ui", dependencies=[Depends(viewer)])
TEMPLATES = Path(__file__).parent / "templates"


def page(name, refresh=False, **values):
    """Fill a template; values are escaped unless already rendered HTML (wrapped in Raw).
    Status pages refresh themselves; pages with forms never do, so a typed key is not lost."""
    fill = {k: v if isinstance(v, Raw) else html.escape(str(v)) for k, v in values.items()}
    body = string.Template((TEMPLATES / f"{name}.html").read_text()).substitute(fill)
    base = string.Template((TEMPLATES / "base.html").read_text())
    return HTMLResponse(
        base.substitute(
            head='<meta http-equiv="refresh" content="15">\n' if refresh else "",
            title=html.escape(values.get("title", "hub")),
            body=body,
        ),
        headers={"Cache-Control": "no-store", "X-Frame-Options": "DENY"},
    )


class Raw(str):
    pass


def when(us):
    if not us:
        return ""
    return datetime.datetime.fromtimestamp(us / 1e6, datetime.UTC).strftime("%Y-%m-%d %H:%M:%S")


def table(headers, rows):
    head = "".join(f"<th>{html.escape(h)}</th>" for h in headers)
    body = "".join(
        "<tr>"
        + "".join(f"<td>{c if isinstance(c, Raw) else html.escape(str(c))}</td>" for c in r)
        + "</tr>"
        for r in rows
    )
    return Raw(f"<table><tr>{head}</tr>{body or '<tr><td>none</td></tr>'}</table>")


def link(href, text):
    return Raw(f'<a href="{html.escape(href)}">{html.escape(str(text))}</a>')


TABS = (
    ("", "Work"),
    ("/activity", "Activity"),
    ("/attempts", "Attempts"),
    ("/search", "Search"),
    ("/review", "Memory review"),
    ("/threads", "Investigations"),
    ("/proposals", "Library proposals"),
)


def tabs(project, current):
    """The project page navigation; the current tab is plain text."""
    items = (
        Raw(f"<b>{name}</b>") if name == current else link(f"/ui/p/{quote(project)}{path}", name)
        for path, name in TABS
    )
    return Raw(f'<nav class="tabs">{" · ".join(items)}</nav>')


def bars(rows):
    """(label, count) rows as a table whose last column is a proportional CSS bar."""
    top = max((n for _, n in rows), default=0) or 1
    return table(
        ["", "count", ""],
        [
            [label, n, Raw(f'<span class="bar" style="width:{100 * n // top}%"></span>')]
            for label, n in rows
        ],
    )


def clip(text, n=200):
    text = str(text)
    return text if len(text) <= n else text[: n - 1] + "…"


def read(request, fn):
    return request.app.state.store.read(fn)


@router.get("", response_class=HTMLResponse)
def overview(request: Request):
    def fn(db):
        rows = []
        for (p,) in db.execute("SELECT id FROM projects WHERE id <> '_system' ORDER BY id"):
            one = lambda sql, p=p: db.execute(sql, [p]).fetchone()[0]  # noqa: E731
            tasks = dict(
                db.execute(
                    "SELECT json_extract(body,'$.status'), count(*) FROM objects "
                    "WHERE project_id=? AND kind='task' GROUP BY 1",
                    [p],
                ).fetchall()
            )
            rows.append(
                [
                    link(f"/ui/p/{quote(p)}", p),
                    ", ".join(f"{k} {v}" for k, v in sorted(tasks.items())) or "none",
                    one(
                        "SELECT count(*) FROM objects WHERE project_id=? AND kind='session' "
                        "AND json_extract(body,'$.status')='active'"
                    ),
                    one(
                        "SELECT count(*) FROM memory_records WHERE project_id=? AND NOT revoked "
                        "AND superseded_by IS NULL AND visibility='project'"
                    ),
                    one(
                        "SELECT count(*) FROM memory_records "
                        "WHERE project_id=? AND visibility='private'"
                    ),
                    one(
                        "SELECT count(*) FROM embedding_jobs WHERE project_id=? AND state='pending'"
                    ),
                    one(
                        "SELECT count(*) FROM embedding_jobs WHERE project_id=? AND state='failed'"
                    ),
                    db.execute(
                        "SELECT count(*) FROM changes WHERE project_id=? AND created_us>?",
                        [p, now_us() - 7 * DAY_US],
                    ).fetchone()[0],
                    when(one("SELECT max(created_us) FROM audit WHERE project_id=?")),
                ]
            )
        outbox = db.execute(
            "SELECT project_id, remote_project, count(*) FROM federation_outbox "
            "WHERE applied=0 GROUP BY 1, 2"
        ).fetchall()
        return rows, outbox

    rows, outbox = read(request, fn)
    backups = []
    root = Path(os.environ.get("HUB_BACKUP_DIR", "/backups"))
    for d in sorted(root.glob("*/manifest.json"), reverse=True) if root.is_dir() else ():
        m = json.loads(d.read_text())
        backups.append(
            [
                d.parent.name,
                m.get("label") or "",
                when(m["created_us"]),
                m["schema_version"],
                len(m["files"]),
            ]
        )
    return page(
        "overview",
        refresh=True,
        title="Agent Context Hub",
        projects=table(
            [
                "project",
                "tasks",
                "active sessions",
                "active memory",
                "private (count only)",
                "embedding backlog",
                "failed embeddings",
                "changes (7d)",
                "last activity",
            ],
            rows,
        ),
        outbox=table(["project", "peer", "pending deliveries"], outbox),
        backups=table(["backup", "label", "created", "schema", "files"], backups),
    )


@router.get("/p/{project}", response_class=HTMLResponse)
def project_page(project: str, request: Request, flash: str = ""):
    def fn(db):
        if not db.execute(
            "SELECT 1 FROM projects WHERE id=? AND id <> '_system'", [project]
        ).fetchone():
            return None
        objects = lambda kind: [  # noqa: E731
            json.loads(r[0])
            for r in db.execute(
                "SELECT body FROM objects WHERE project_id=? AND kind=?", [project, kind]
            )
        ]
        checkpoints = {c["id"]: c for c in objects("checkpoint")}
        tasks = []
        for t in sorted(objects("task"), key=lambda t: t.get("deadline_us") or 0, reverse=True):
            cp = checkpoints.get(t.get("checkpoint", ""), {})
            session = t.get("last_session") or {}
            tasks.append(
                [
                    t["id"][:12],
                    t.get("goal", ""),
                    t.get("owner", ""),
                    t.get("agent") or "",
                    t.get("status", ""),
                    f"{t.get('turns', 0)}/{t.get('turn_limit', '')}",
                    session.get("status", ""),
                    cp.get("completed", ""),
                    cp.get("next_step", ""),
                ]
            )
        memory = [
            [
                link(f"/ui/p/{quote(project)}/r/{quote(r[0])}", r[0][:12]),
                r[1],
                r[2],
                r[3],
                "revoked" if r[4] else "superseded" if r[5] else "active",
                when(r[6]),
            ]
            for r in db.execute(
                "SELECT id, namespace, hook, owner || ' via ' || author, revoked, superseded_by, "
                "created_us "
                "FROM memory_records WHERE project_id=? AND visibility='project' "
                "ORDER BY created_us DESC LIMIT 100",
                [project],
            )
        ]
        solutions = [
            [link(f"/ui/p/{quote(project)}/s/{quote(r[0])}", r[0][:12]), r[1], r[2], r[3], r[4]]
            for r in db.execute(
                "SELECT s.id, s.problem_key, s.status, s.current_revision, s.author "
                "FROM solutions s WHERE s.project_id=? ORDER BY s.created_us DESC LIMIT 50",
                [project],
            )
        ]
        return tasks, memory, solutions

    found = read(request, fn)
    if found is None:
        return page("message", title="not found", message="No such project.")
    tasks, memory, solutions = found
    return page(
        "project",
        refresh=not flash,
        title=project,
        project=project,
        tabs=tabs(project, "Work"),
        flash=Raw(f'<p class="flash">{html.escape(flash)}</p>') if flash else "",
        tasks=table(
            [
                "task",
                "goal",
                "owner",
                "agent",
                "status",
                "turns",
                "session",
                "last completed",
                "next step",
            ],
            tasks,
        ),
        memory=table(
            ["record", "namespace", "hook", "owner via agent", "state", "created"], memory
        ),
        solutions=table(["solution", "problem", "status", "revision", "author"], solutions),
    )


def known(request, project):
    return read(
        request,
        lambda db: db.execute(
            "SELECT 1 FROM projects WHERE id=? AND id <> '_system'", [project]
        ).fetchone(),
    )


@router.get("/p/{project}/activity", response_class=HTMLResponse)
def activity_page(project: str, request: Request, actor: str = "", action: str = ""):
    """Telemetry from stored changes, jobs, incidents and messages; nothing new is logged."""
    now = now_us()

    def fn(db):
        q = lambda sql, *args: db.execute(sql, [project, *args]).fetchall()  # noqa: E731
        daily = q(
            "SELECT date(created_us/1000000,'unixepoch'), count(*) FROM changes "
            "WHERE project_id=? AND created_us>? GROUP BY 1 ORDER BY 1",
            now - 14 * DAY_US,
        )
        who = q(
            "SELECT actor, operation, count(*) FROM changes WHERE project_id=? AND created_us>? "
            "GROUP BY 1, 2 ORDER BY 3 DESC",
            now - 7 * DAY_US,
        )
        jobs = q(
            "SELECT state, count(*), min(created_us) FROM embedding_jobs WHERE project_id=? "
            "GROUP BY 1 ORDER BY 1"
        )
        failed = q(
            "SELECT kind, record_id, attempts, error FROM embedding_jobs "
            "WHERE project_id=? AND state='failed' ORDER BY created_us DESC LIMIT 50"
        )
        threads = q(
            "SELECT status, count(*) FROM troubleshooting_threads WHERE project_id=? GROUP BY 1"
        )
        actions = q(
            "SELECT status, count(*) FROM troubleshooting_actions WHERE project_id=? GROUP BY 1"
        )
        held = q(
            "SELECT id, resource, actor, status, expires_us, thread_id "
            "FROM troubleshooting_actions "
            "WHERE project_id=? AND (status='outcome-unknown' "
            "OR (status IN ('reserved','started') AND expires_us>?)) ORDER BY expires_us",
            now,
        )
        backlog = q(
            "SELECT recipient, count(*) FROM messages WHERE project_id=? AND NOT acknowledged "
            "GROUP BY 1 ORDER BY 2 DESC"
        )
        audit = q(
            # A private record's ID is private too: the feed names only that one exists.
            "SELECT a.seq, a.created_us, a.actor, a.action, a.object_id, "
            "m.visibility = 'private' FROM audit a LEFT JOIN memory_records m "
            "ON m.project_id = a.project_id AND m.id = a.object_id "
            "WHERE a.project_id=? AND (?='' OR a.actor=?) AND (?='' OR a.action=?) "
            "ORDER BY a.seq DESC LIMIT 100",
            actor,
            actor,
            action,
            action,
        )
        return daily, who, jobs, failed, threads, actions, held, backlog, audit

    if not known(request, project):
        return page("message", title="not found", message="No such project.")
    daily, who, jobs, failed, threads, actions, held, backlog, audit = read(request, fn)
    thread = lambda t: link(f"/ui/p/{quote(project)}/threads/{quote(t)}", t[:12])  # noqa: E731
    return page(
        "activity",
        refresh=True,
        title=f"{project} activity",
        project=project,
        tabs=tabs(project, "Activity"),
        actor=actor,
        action=action,
        daily=bars(daily),
        who=table(["actor", "operation", "changes"], who),
        jobs=table(["state", "jobs", "oldest"], [[s, n, when(oldest)] for s, n, oldest in jobs]),
        failed=table(
            ["kind", "record", "attempts", "error"],
            [[k, r[:12], a, clip(e, 120)] for k, r, a, e in failed],
        ),
        threads=table(["incident status", "count"], threads),
        actions=table(["action status", "count"], actions),
        held=table(
            ["action", "resource", "actor", "status", "expires in", "incident"],
            [
                [
                    i[:12],
                    res,
                    who_,
                    st,
                    "" if st == "outcome-unknown" else f"{(exp - now) // 1_000_000}s",
                    thread(t),
                ]
                for i, res, who_, st, exp, t in held
            ],
        ),
        backlog=table(["recipient", "unacknowledged"], backlog),
        audit=table(
            ["seq", "time", "actor", "action", "object"],
            [
                [r[0], when(r[1]), r[2], r[3], "(private record)" if r[5] else r[4][:40]]
                for r in audit
            ],
        ),
    )


@router.get("/p/{project}/attempts", response_class=HTMLResponse)
def attempts_page(project: str, request: Request):
    def fn(db):
        attempts = db.execute(
            "SELECT created_us, author, approach, outcome, evidence FROM attempts "
            "WHERE project_id=? ORDER BY created_us DESC LIMIT 100",
            [project],
        ).fetchall()
        outcomes = db.execute(
            "SELECT solution_id, sum(result='success'), sum(result='failure'), max(created_us) "
            "FROM outcomes WHERE project_id=? GROUP BY 1 ORDER BY 4 DESC",
            [project],
        ).fetchall()
        return attempts, outcomes

    if not known(request, project):
        return page("message", title="not found", message="No such project.")
    attempts, outcomes = read(request, fn)
    return page(
        "attempts",
        refresh=True,
        title=f"{project} attempts",
        project=project,
        tabs=tabs(project, "Attempts"),
        attempts=table(
            ["time", "author", "approach", "outcome", "evidence"],
            [
                [when(t), a, clip(ap), clip(o, 400), clip(", ".join(json.loads(e)), 160)]
                for t, a, ap, o, e in attempts
            ],
        ),
        outcomes=table(
            ["solution", "successes", "failures", "last report"],
            [
                [link(f"/ui/p/{quote(project)}/s/{quote(s)}", s[:12]), ok, bad, when(t)]
                for s, ok, bad, t in outcomes
            ],
        ),
    )


@router.get("/p/{project}/search", response_class=HTMLResponse)
def search_page(project: str, request: Request, q: str = ""):
    """The agents' own retrieval, run as the signed-in human so grants apply unchanged."""
    principal = thread_reader(request, project)
    found, note = None, ""
    if q.strip():
        try:
            found = api.call(
                request.app.state.store, principal, project, "context_get", {"query": q, "limit": 5}
            )
        except api.HANDLED as error:
            note = f"refused: {api.classify(error)[1]}"
    results = ""
    if found:

        def target(m):
            if m["kind"] == "memory":
                return link(f"/ui/p/{quote(project)}/r/{quote(m['id'])}", m["id"][:12])
            return m["id"][:12]

        degraded = (
            '<p class="flash">Semantic search is unavailable (embedder or vector index); '
            "only keyword matches are shown.</p>"
            if found["retrieval_mode"] == "keyword_only"
            else ""
        )
        results = Raw(
            degraded + f"<p>mode {html.escape(found['retrieval_mode'])} · corpus revision "
            f"{found['corpus_revision']} · {'truncated' if found['truncated'] else 'complete'}</p>"
            + table(
                ["kind", "id", "status", "provenance", "author", "reasons", "summary"],
                [
                    [
                        m["kind"],
                        target(m),
                        m["status"] + " / " + m.get("freshness", "current"),
                        m.get("provenance", ""),
                        m.get("author", ""),
                        ", ".join(m["reasons"]),
                        m["summary"],
                    ]
                    for m in found["matches"]
                ],
            )
        )
    return page(
        "search",
        title=f"{project} search",
        project=project,
        tabs=tabs(project, "Search"),
        q=q,
        flash=Raw(f'<p class="flash">{html.escape(note)}</p>') if note else "",
        results=results,
    )


@router.get("/p/{project}/r/{record_id}", response_class=HTMLResponse)
def record_page(project: str, record_id: str, request: Request):
    row = read(
        request,
        lambda db: (
            db.execute(
                "SELECT * FROM memory_records WHERE project_id=? AND id=? AND visibility='project'",
                [project, record_id],
            ).fetchone()
            if disclosable(db, project, record_id)
            else None
        ),
    )
    if row is None:
        return page("message", title="not found", message="No such project-visible record.")
    fields = [
        [k, row[k]]
        for k in (
            "id",
            "namespace",
            "kind",
            "provenance",
            "confidence",
            "owner",
            "author",
            "agent_session",
            "evidence",
            "revoked",
            "superseded_by",
        )
    ]
    fields.append(["created", when(row["created_us"])])
    from hub.freshness import details

    temporal = read(request, lambda db: details(db, project, record_id))
    fields.extend([[key, json.dumps(value)] for key, value in temporal.items()])
    return page(
        "record",
        title=record_id,
        project=project,
        record_id=record_id,
        body=row["body"],
        fields=table(["field", "value"], fields),
        action=f"/ui/p/{quote(project)}/r/{quote(record_id)}/revoke",
    )


@router.get("/p/{project}/s/{solution_id}", response_class=HTMLResponse)
def solution_page(project: str, solution_id: str, request: Request):
    def fn(db):
        s = db.execute(
            "SELECT * FROM solutions WHERE project_id=? AND id=?", [project, solution_id]
        ).fetchone()
        if s is None or not disclosable(db, project, solution_id, s["current_revision"]):
            return None
        rev = db.execute(
            "SELECT body, repository_commit, image_digest FROM solution_revisions "
            "WHERE project_id=? AND solution_id=? AND revision=?",
            [project, solution_id, s["current_revision"]],
        ).fetchone()
        evidence = db.execute(
            "SELECT verifier, result, created_us FROM evidence WHERE project_id=? AND "
            "solution_id=? AND revision=?",
            [project, solution_id, s["current_revision"]],
        ).fetchall()
        return s, rev, evidence

    found = read(request, fn)
    if found is None:
        return page("message", title="not found", message="No such solution.")
    s, rev, evidence = found
    return page(
        "solution",
        title=solution_id,
        project=project,
        solution_id=solution_id,
        status=s["status"],
        revision=s["current_revision"],
        author=s["author"],
        body=rev["body"],
        commit=rev["repository_commit"],
        image=rev["image_digest"],
        evidence=table(
            ["verifier", "result", "time"], [[e[0], e[1], when(e[2])] for e in evidence]
        ),
        action=f"/ui/p/{quote(project)}/s/{quote(solution_id)}/decide",
    )


def cross_site(request):
    origin = request.headers.get("origin")
    return bool(origin) and urlsplit(origin).netloc != request.headers.get("host")


@router.get("/login", response_class=HTMLResponse)
def login_form(flash: str = ""):
    note = Raw(f'<p class="flash">{html.escape(flash)}</p>') if flash else Raw("")
    return page("login", title="Sign in", flash=note)


@router.post("/login")
def login(request: Request, key: str = Form("")):
    key = key.strip()
    principal = identity.authenticate(request.app.state.store, key)
    if cross_site(request) or principal is None or principal.kind != "human":
        return RedirectResponse("/ui/login?flash=refused", status_code=303)
    response = RedirectResponse("/ui", status_code=303)
    response.set_cookie(
        COOKIE, key, max_age=12 * 3600, path="/ui", secure=True, httponly=True, samesite="strict"
    )
    return response


@router.get("/logout")
def logout():
    response = RedirectResponse("/ui/login", status_code=303)
    response.delete_cookie(COOKIE, path="/ui")
    return response


def act(request, project, key, operation, arguments):
    """Run one write as the principal whose key the form carried; returns a flash message."""
    if cross_site(request):
        return "refused: cross-site request"
    store = request.app.state.store
    principal = identity.authenticate(store, (key or "").strip())
    if principal is None:
        return "refused: that is not a valid hub key"
    try:
        api.call(store, principal, project, operation, arguments, f"ui-{uuid.uuid4()}")
    except api.HANDLED as error:
        return f"refused: {api.classify(error)[1]}"
    return f"done: {operation} as {principal.id}"


def back(project, message):
    return RedirectResponse(f"/ui/p/{quote(project)}?flash={quote(message)}", status_code=303)


@router.post("/p/{project}/r/{record_id}/revoke")
def revoke(project: str, record_id: str, request: Request, key: str = Form("")):
    return back(project, act(request, project, key, "revoke_memory", {"memory_id": record_id}))


@router.post("/p/{project}/s/{solution_id}/decide")
def decide(
    project: str,
    solution_id: str,
    request: Request,
    key: str = Form(""),
    action: str = Form(""),
    reason: str = Form(""),
    revision: int = Form(0),
):
    arguments = {
        "solution_id": solution_id,
        "revision": revision,
        "action": action,
        "reason": reason,
    }
    return back(project, act(request, project, key, "solution_decide", arguments))


@router.post("/p/{project}/proposals/{proposal_id}/decide")
def publication_decide(
    project: str,
    proposal_id: str,
    request: Request,
    key: str = Form(""),
    action: str = Form(""),
    reason: str = Form(""),
):
    arguments = {"proposal_id": proposal_id, "action": action, "reason": reason}
    return back(project, act(request, project, key, "tshoot_publication_decide", arguments))


def thread_reader(request, project):
    """Incident reads always require a project-granted human, including loopback UI."""
    principal = identity.authenticate(request.app.state.store, request.cookies.get(COOKIE, ""))
    if principal is None or principal.kind != "human":
        note = quote("sign in with a human hub key to search or read investigations")
        raise HTTPException(303, headers={"Location": f"/ui/login?flash={note}"})
    return principal


@router.get("/p/{project}/threads", response_class=HTMLResponse)
def thread_list(project: str, request: Request, cursor: int = 0):
    principal = thread_reader(request, project)
    rows = api.call(
        request.app.state.store, principal, project, "tshoot_list", {"cursor": cursor, "limit": 40}
    )
    body = table(
        ["incident", "target", "status", "predecessor"],
        [
            [
                link(f"/ui/p/{quote(project)}/threads/{quote(r['id'])}", r["id"]),
                r["target"],
                r["status"],
                r["predecessor"] or "",
            ]
            for r in rows
        ],
    )
    if len(rows) == 40:
        body = Raw(body + link(f"/ui/p/{quote(project)}/threads?cursor={cursor + 40}", "Next page"))
    content = Raw(tabs(project, "Investigations") + body)
    return page("timeline", title="Investigations", content=content)


@router.get("/p/{project}/threads/{thread_id}", response_class=HTMLResponse)
def thread_timeline(project: str, thread_id: str, request: Request, cursor: int = 0):
    principal = thread_reader(request, project)
    found = api.call(
        request.app.state.store,
        principal,
        project,
        "tshoot_read",
        {"thread_id": thread_id, "cursor": cursor, "limit": 40},
    )
    content = table(
        ["field", "value"],
        [
            ["target", found["thread"]["target"]],
            ["status", found["thread"]["status"]],
            ["participants", ", ".join(found["participants"])],
        ],
    )
    content += table(
        ["seq", "author", "kind", "body", "evidence", "corrects"],
        [
            [
                e["seq"],
                e["actor"],
                e["kind"],
                json.dumps(e["body"]),
                json.dumps(e["evidence"]),
                e["corrects"] or "",
            ]
            for e in found["events"]
        ],
    )
    content += table(
        ["action", "resource", "actor", "status"],
        [[a["id"], a["resource"], a["actor"], a["status"]] for a in found["actions"]],
    )
    if len(found["events"]) == 40:
        content += link(
            f"/ui/p/{quote(project)}/threads/{quote(thread_id)}?cursor={found['cursor']}",
            "Next page",
        )
    return page("timeline", title="Investigation " + thread_id, content=Raw(content))


@router.get("/p/{project}/proposals", response_class=HTMLResponse)
def proposals_page(project: str, request: Request, cursor: int = 0):
    """Library proposals and their governance history, for maintainers of this project."""
    principal = thread_reader(request, project)
    try:
        rows = api.call(
            request.app.state.store,
            principal,
            project,
            "tshoot_proposals",
            {"cursor": cursor, "limit": 40},
        )
    except api.HANDLED as error:
        return page("message", title="refused", message=api.classify(error)[1])

    def decide_form(r):
        if r["status"] != "proposed" or r["source_project"] != project:
            return r["reason"] or ""
        action = f"/ui/p/{quote(project)}/proposals/{quote(r['id'])}/decide"
        return Raw(
            f'<form method="post" action="{html.escape(action)}">'
            '<select name="action"><option>publish</option><option>reject</option></select> '
            '<input name="reason" placeholder="review reason" required> '
            '<input type="password" name="key" placeholder="your hub key" autocomplete="off" '
            "required> <button>Decide</button></form>"
        )

    content = table(
        ["proposal", "source", "library", "status", "body", "applicability", "evidence", "review"],
        [
            [
                r["id"][:12],
                f"{r['source_project']}/{r['source_kind']} {r['source_id'][:12]} "
                f"rev {r['source_revision']}",
                r["library_project"] + (f" {r['dest_id'][:12]}" if r["dest_id"] else ""),
                r["status"] + (f" by {r['reviewer']}" if r["reviewer"] else ""),
                Raw(f"<pre>{html.escape(r['body'])}</pre>"),
                json.dumps(r["applicability"]),
                json.dumps(r["evidence"]),
                decide_form(r),
            ]
            for r in rows
        ],
    )
    if len(rows) == 40:
        content = Raw(
            content + link(f"/ui/p/{quote(project)}/proposals?cursor={cursor + 40}", "Next page")
        )
    return page(
        "timeline",
        title="Library proposals",
        content=Raw(
            tabs(project, "Library proposals")
            + "<p>Publishing needs a human maintainer of this project and the library. "
            "Published memories are unverified leads; solution copies need their own "
            "evidence or approval.</p>" + content
        ),
    )


@router.get("/p/{project}/review", response_class=HTMLResponse)
def memory_review_page(project: str, request: Request, reason: str = "", after: str = ""):
    principal = thread_reader(request, project)
    records = api.call(
        request.app.state.store,
        principal,
        project,
        "memory_review_list",
        {"reason": reason or None, "after": after},
    )
    rows = []
    for record in records:
        ident = html.escape(record["id"])
        revision = record["freshness_revision"]
        selection = Raw(f'<input type="checkbox" name="selected" value="{ident}:{revision}">')
        rows.append(
            [
                selection,
                link(f"/ui/p/{quote(project)}/review/{ident}", record["hook"]),
                record["freshness"],
                ", ".join(record["review_reasons"]),
                when(record["observed_us"]),
                when(record["checked_us"]),
                when(record["review_due_us"]),
                when(record["reminder_us"]),
            ]
        )
    body = Raw(
        f'<form method="post" action="/ui/p/{quote(project)}/review/bulk">'
        + table(
            [
                "Select",
                "Claim",
                "Freshness",
                "Review reason",
                "Observed",
                "Confirmed",
                "Due",
                "Reminder",
            ],
            rows,
        )
        + '<select name="action"><option '
        'value="classify">Classify</option><option value="historical">Historical</option>'
        '<option value="defer">Defer</option></select> '
        "<select "
        'name="temporal_kind"><option>durable</option><option>historical</option>'
        "<option>unclassified</option></select> "
        '<input name="reminder_us" type="datetime-local" aria-label="Reminder (UTC)"> '
        "<button>Preview selected changes</button></form>"
    )
    if len(records) == 100:
        body += link(
            f"/ui/p/{quote(project)}/review?after={quote(records[-1]['id'])}&reason={quote(reason)}",
            "Next page",
        )
    return page(
        "review",
        title="Memory review",
        project=project,
        tabs=tabs(project, "Memory review"),
        body=body,
    )


@router.post("/p/{project}/review/bulk", response_class=HTMLResponse)
async def memory_review_bulk_page(project: str, request: Request):
    principal = thread_reader(request, project)
    if cross_site(request):
        raise HTTPException(403, "cross-site request")
    form = await request.form()
    try:
        if form.get("payload"):
            arguments = json.loads(form["payload"])
            arguments.update(preview=False, preview_token=form["preview_token"])
        else:
            records = []
            for value in form.getlist("selected"):
                ident, revision = value.rsplit(":", 1)
                records.append(dict(memory_id=ident, expected_revision=int(revision)))
            arguments = dict(
                records=records,
                action=form["action"],
                temporal_kind=form.get("temporal_kind"),
                reminder_us=review_date(form.get("reminder_us")),
                preview=True,
            )
        result = api.call(
            request.app.state.store,
            principal,
            project,
            "memory_review_bulk",
            arguments,
            form.get("idempotency_key") or f"ui-{uuid.uuid4()}",
        )
        body = table(
            ["Claim", "Revision", "Current freshness"],
            [[r["body"], r["freshness_revision"], r["freshness"]] for r in result["records"]],
        )
        if result["preview"]:
            body = Raw(
                f"<p>Proposed action: {html.escape(arguments['action'])}; classification: "
                f"{html.escape(str(arguments.get('temporal_kind')))}"
                f"; reminder: {arguments.get('reminder_us')}</p>"
                + body
                + '<form method="post"><input type="hidden" name="payload" value="'
                + html.escape(json.dumps(arguments), quote=True)
                + '"><input type="hidden" name="preview_token" value="'
                + result["preview_token"]
                + '"><input type="hidden" name="idempotency_key" value="'
                + str(uuid.uuid4())
                + '"><button>Apply previewed changes</button></form>'
            )
        else:
            body = Raw("<p>Changes applied.</p>" + body)
    except (ValueError, KeyError) as error:
        body = html.escape(str(error))
    return page(
        "review",
        title="Review preview",
        project=project,
        tabs=tabs(project, "Memory review"),
        body=body,
    )


@router.get("/p/{project}/review/{memory_id}", response_class=HTMLResponse)
def memory_review_detail(project: str, memory_id: str, request: Request):
    principal = thread_reader(request, project)
    api.authorize(principal, project, api.OPERATIONS["memory_review_list"][0])
    from hub.work import Work

    work = Work(request.app.state.store, project)
    record = work.record(principal.id, memory_id)
    if not record:
        raise HTTPException(404, "not found")

    def related(db):
        return (
            [
                dict(r)
                for r in db.execute(
                    "SELECT id,source,baseline,observed_fingerprint,state,failure,checked_us "
                    "FROM memory_source_checks WHERE project_id=? AND memory_id=?",
                    [project, memory_id],
                )
            ],
            [
                r[0]
                for r in db.execute(
                    "SELECT id FROM memory_records WHERE project_id=? AND superseded_by=?",
                    [project, memory_id],
                )
            ],
        )

    sources, previous = work.store.read(related)
    body = Raw(
        "<pre>"
        + html.escape(record["body"])
        + "</pre>"
        + table(
            ["Field", "Value"],
            [
                [k, json.dumps(v, ensure_ascii=False)]
                for k, v in record.items()
                if k not in ("body", "hook")
            ],
        )
        + "<h2>Sources</h2><pre>"
        + html.escape(json.dumps(sources, indent=2))
        + "</pre>"
        + "<h2>Replacement history</h2>"
        + " ".join(
            str(link(f"/ui/p/{quote(project)}/review/{quote(i)}", i))
            for i in previous + ([record["superseded_by"]] if record["superseded_by"] else [])
        )
    )

    def input_field(name, label, value="", kind="text"):
        return (
            f'<label>{html.escape(label)} <input name="{name}" type="{kind}" '
            f'value="{html.escape(str(value or ""), quote=True)}"></label><br>'
        )

    def utc_value(value):
        return (
            datetime.datetime.fromtimestamp(value / 1e6, datetime.UTC).strftime("%Y-%m-%dT%H:%M")
            if value
            else ""
        )

    hidden = input_field(
        "expected_revision", "", record["freshness_revision"], "hidden"
    ) + input_field("idempotency_key", "", str(uuid.uuid4()), "hidden")
    body += Raw(
        '<form method="post">' + hidden + '<label>Action <select name="action">'
        '<option value="confirm">Confirm with evidence</option>'
        '<option value="edit">Edit and supersede</option>'
        '<option value="classify">Classify</option>'
        '<option value="historical">Classify as historical</option>'
        '<option value="retire">Retire</option><option value="defer">Defer reminder</option>'
        '<option value="conflict">Flag conflicting evidence</option></select></label><br>'
        '<label>Classification <select name="temporal_kind">'
        + "".join(
            f'<option value="{key}" {"selected" if key == record["temporal_kind"] else ""}'
            f">{label}</option>"
            for key, label in [
                ("unclassified", "Unassessed"),
                ("durable", "Durable knowledge"),
                ("changing", "Changing state"),
                ("historical", "Historical observation"),
            ]
        )
        + "</select></label><br>"
        + input_field("claim_key", "Claim key (changing state)", record["claim_key"])
        + input_field(
            "observed", "Observed (UTC)", utc_value(record["observed_us"]), "datetime-local"
        )
        + input_field(
            "review_due",
            "Review deadline (UTC)",
            utc_value(record["review_due_us"]),
            "datetime-local",
        )
        + input_field(
            "reminder", "Reminder (UTC)", utc_value(record["reminder_us"]), "datetime-local"
        )
        + "<label>Evidence references, one per line"
        '<textarea name="evidence" rows="3" style="width:100%">'
        + html.escape("\n".join(record["evidence"]))
        + "</textarea></label>"
        + "<label>Corrected claim (edit) or proposed correction (conflict)"
        '<textarea name="body" rows="8" style="width:100%">'
        + html.escape(record["proposed_correction"] or record["body"])
        + "</textarea></label>"
        + "<button>Apply review</button></form>"
    )
    endpoints = json.loads(os.environ.get("HUB_CHECK_ENDPOINTS", "[]"))
    body += Raw(
        '<h2>Schedule a source check</h2><form method="post">'
        + hidden
        + '<input type="hidden" name="action" value="bind">'
        '<label>Configured endpoint <select name="endpoint">'
        + "".join(f"<option>{html.escape(e)}</option>" for e in endpoints)
        + "</select></label><br>"
        + input_field("repository", "Repository (owner/name)")
        + '<label>Source <select name="source_kind"><option value="file">Repository file</option>'
        '<option value="issue">Issue</option>'
        '<option value="pull">Pull request</option></select></label><br>'
        + input_field("ref", "Branch or tag", "main")
        + input_field("path", "File path")
        + input_field("number", "Issue or pull request number", kind="number")
        + input_field("baseline", "Baseline SHA-256 (optional; blank adopts the first check)")
        + "<button>Bind source and schedule</button></form>"
    )
    for source in sources:
        body += Raw(
            '<form method="post">'
            + hidden
            + input_field("action", "", "retry", "hidden")
            + input_field("job_id", "", source["id"], "hidden")
            + "<p>Retry source "
            + html.escape(source["id"])
            + "</p>"
            + input_field("baseline", "Replacement baseline (optional)")
            + "<button>Retry source check</button></form>"
        )
    return page(
        "review",
        title="Review claim",
        project=project,
        tabs=tabs(project, "Memory review"),
        body=body,
    )


def review_date(value):
    if not value:
        return None
    return int(
        datetime.datetime.fromisoformat(value).replace(tzinfo=datetime.UTC).timestamp() * 1e6
    )


@router.post("/p/{project}/review/{memory_id}", response_class=HTMLResponse)
async def memory_review_apply(project: str, memory_id: str, request: Request):
    principal = thread_reader(request, project)
    if cross_site(request):
        raise HTTPException(403, "cross-site request")
    form = await request.form()
    try:
        action = form["action"]
        args = dict(memory_id=memory_id, expected_revision=int(form["expected_revision"]))
        if action in ("bind", "retry"):
            if action == "bind":
                source = dict(
                    endpoint=form["endpoint"],
                    repository=form["repository"],
                    kind=form["source_kind"],
                )
                if source["kind"] == "file":
                    source.update(ref=form["ref"], path=form["path"])
                else:
                    source["number"] = int(form["number"])
                args.update(source=source, baseline=form.get("baseline") or None)
                operation = "memory_source_bind"
            else:
                args.pop("memory_id")
                args.update(job_id=form["job_id"], baseline=form.get("baseline") or None)
                operation = "memory_source_retry"
        else:
            args.update(
                temporal_kind=form.get("temporal_kind"),
                claim_key=form.get("claim_key") or None,
                observed_us=review_date(form.get("observed")),
                review_due_us=review_date(form.get("review_due")),
                evidence=[e.strip() for e in form.get("evidence", "").splitlines() if e.strip()],
            )
            if action == "edit":
                from hub.work import Work

                old = Work(request.app.state.store, project).record(principal.id, memory_id)
                if not old:
                    raise ValueError("record unavailable")
                args.update(
                    body=form["body"], provenance=old["provenance"], confidence=old["confidence"]
                )
                operation = "revise_memory"
            else:
                args.update(
                    action=action,
                    reminder_us=review_date(form.get("reminder")),
                    proposed_correction=form.get("body") if action == "conflict" else None,
                )
                operation = "memory_review"
        api.call(
            request.app.state.store, principal, project, operation, args, form["idempotency_key"]
        )
        body = Raw(
            "<p>Applied.</p>"
            + link(f"/ui/p/{quote(project)}/review/{quote(memory_id)}", "Read updated record")
        )
    except (*api.HANDLED, KeyError) as error:
        body = "Refused: " + (
            api.classify(error)[1] if not isinstance(error, KeyError) else "missing field"
        )
    return page(
        "review",
        title="Memory review",
        project=project,
        tabs=tabs(project, "Memory review"),
        body=body,
    )
