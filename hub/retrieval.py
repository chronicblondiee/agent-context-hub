"""Permission-scoped hybrid search. SQL applies ACLs before either top-k limit."""

import contextlib
import contextvars
import json
import re
import sqlite3
import struct
import threading
import time

from hub.embed import MODEL, MODEL_KEY, Embedder
from hub.store import encoded

EMBEDDER = Embedder()
CANDIDATES = 50
RRF_K = 60
# Relevance floors, tuned on tests/retrieval_corpus.json (docs/verification/): a keyword hit must
# cover a quarter of the query's non-stopword terms, a semantic hit must be this close. Without
# them every query, including one with no answer, fills all five slots.
MIN_COVERAGE = 0.25
MAX_DISTANCE = 0.6
# Concurrent searches on one CPU contend superlinearly (p95 30 ms alone, 3.6 s at 10 clients);
# queueing them keeps each one fast. ponytail: one global slot, raise it if the core gets more CPU.
SEARCHES = threading.BoundedSemaphore(1)
# (queue wait, search) seconds of this context's last search; the REST layer reports it.
TIMING = contextvars.ContextVar("search_timing", default=None)
STOPWORDS = frozenset(
    "a an and are as at be but by can do does for from has have how i in is it its me my not of "
    "on or our so that the this to was we what when where which who why will with you your".split()
)

ACL = """(
 (f.kind='memory' AND m.id IS NOT NULL AND m.revoked=0 AND m.superseded_by IS NULL
  AND (m.visibility='project' OR m.owner=?)
  AND (sr.record_id IS NULL OR (src.status='active' AND
       src.last_sync_us >= unixepoch('now')*1000000-300000000)))
 OR (f.kind='solution' AND s.id IS NOT NULL AND s.current_revision=f.revision
  AND s.status NOT IN ('revoked','superseded'))
 OR (f.kind='attempt' AND a.id IS NOT NULL)
) AND NOT EXISTS (SELECT 1 FROM publications p WHERE p.library_project=f.project_id
 AND p.dest_id=f.record_id AND (p.status<>'published' OR p.dest_revision<>f.revision))"""
# A library copy is disclosed only while its publication is current (hub/library.py).
JOINS = """
 LEFT JOIN memory_records m ON f.kind='memory' AND m.project_id=f.project_id AND m.id=f.record_id
 LEFT JOIN solutions s ON f.kind='solution' AND s.project_id=f.project_id AND s.id=f.record_id
 LEFT JOIN attempts a ON f.kind='attempt' AND a.project_id=f.project_id AND a.id=f.record_id
 LEFT JOIN source_rows sr ON f.kind='memory' AND sr.project_id=f.project_id
 AND sr.record_id=f.record_id
 LEFT JOIN sources src ON src.id=sr.source_id
 LEFT JOIN publications fp ON fp.library_project=f.project_id AND fp.dest_id=f.record_id
 AND fp.status='published'
 LEFT JOIN memory_freshness mf ON mf.project_id=coalesce(fp.source_project,m.project_id)
 AND mf.memory_id=coalesce(fp.source_id,m.id)
"""


# Selection priority is applied before both candidate limits, not just to merged results.
def freshness_order():
    from hub.freshness import eligibility

    current = eligibility("current").removeprefix(" AND ")
    return (
        "CASE WHEN " + current + " THEN CASE WHEN f.kind='memory' AND "
        "coalesce(mf.temporal_kind,'unclassified')='unclassified' THEN 1 ELSE 0 END "
        "ELSE 2 END"
    )


def _words(text):
    return re.findall(r"[^\W_]+", text.lower(), re.UNICODE)


def _lexical(con, project, owner, query, extra=""):
    tokens = list(dict.fromkeys(_words(query)))[:32]
    terms = [t for t in tokens if t not in STOPWORDS] or tokens
    if not terms:
        return []
    expression = " OR ".join('"' + term.replace('"', '""') + '"' for term in terms)
    rows = con.execute(
        "SELECT f.kind, f.record_id, f.revision, f.text, bm25(search_fts) AS score "
        "FROM search_fts f "
        + JOINS
        + " WHERE search_fts MATCH ? AND f.project_id=? AND "
        + ACL
        + extra
        + " ORDER BY "
        + freshness_order()
        + ", score LIMIT ?",
        [expression, project, owner, CANDIDATES],
    )
    return [
        (r[0], r[1], int(r[2]))
        for r in rows
        if len(set(_words(r[3])).intersection(terms)) >= MIN_COVERAGE * len(terms)
    ]


def _semantic(con, project, owner, vector, extra=""):
    blob = struct.pack(f"<{MODEL['dim']}f", *vector)
    rows = con.execute(
        "SELECT f.kind, f.record_id, f.revision, "
        "MIN(vec_distance_cosine(f.vector, ?)) AS distance "
        "FROM chunk_vectors f "
        + JOINS
        + " WHERE f.project_id=? AND f.model=? AND f.dim=? AND "
        + ACL
        + extra
        + " GROUP BY f.kind, f.record_id, f.revision "
        + "HAVING distance <= ? ORDER BY "
        + freshness_order()
        + ", distance LIMIT ?",
        [blob, project, MODEL_KEY, MODEL["dim"], owner, MAX_DISTANCE, CANDIDATES],
    )
    return [(r[0], r[1], int(r[2])) for r in rows]


def _conflicts(applicability, environment):
    return any(k in environment and environment[k] != v for k, v in applicability.items())


def _details(db, work, kind, ident, revision, environment):
    if kind == "memory":
        record = work._memory_row(db, ident)
        if not record:
            return None
        published = db.execute(
            "SELECT applicability FROM publications WHERE library_project=? AND dest_id=? "
            "AND status='published'",
            [work.project, ident],
        ).fetchone()
        applicability = json.loads(published[0]) if published else {}
        if _conflicts(applicability, environment):
            return None
        item = {
            "kind": kind,
            "id": ident,
            "revision": 1,
            "status": "unverified",
            "summary": record["body"],
            "hook": record["hook"],
            "provenance": record["provenance"],
            "author": record["author"],
            "owner": record["owner"],
            "agent_session": record["agent_session"],
            "evidence": record["evidence"],
            "applicability": applicability,
            "created_us": record["created_us"],
        }
        from hub.freshness import details

        item.update(details(db, work.project, ident))
        if applicability:  # general entries carry it as publication metadata
            item["applicability_missing"] = sorted(k for k in applicability if k not in environment)
        return item
    if kind == "attempt":
        row = db.execute(
            "SELECT * FROM attempts WHERE project_id=? AND id=?", [work.project, ident]
        ).fetchone()
        if not row:
            return None
        return {
            "kind": kind,
            "id": ident,
            "revision": 1,
            "status": "unverified",
            "summary": row["approach"] + " — " + row["outcome"],
            "provenance": "reported attempt",
            "freshness": "historical",
            "observed_us": row["created_us"],
            "author": row["author"],
            "evidence": json.loads(row["evidence"]),
            "applicability": {},
            "created_us": row["created_us"],
        }
    solution = work._solution(db, ident)
    rev = work._revision(db, ident, revision)
    if not solution or not rev or solution["current_revision"] != revision:
        return None
    applicability = rev["applicability"]
    if _conflicts(applicability, environment):
        return None
    refs = [
        r[0]
        for r in db.execute(
            "SELECT id FROM evidence WHERE project_id=? AND solution_id=? AND revision=? "
            "ORDER BY created_us",
            [work.project, ident, revision],
        )
    ]
    return {
        "kind": kind,
        "id": ident,
        "revision": revision,
        "status": solution["status"],
        "summary": rev["body"],
        "provenance": "solution proposal",
        "author": solution["author"],
        "evidence": refs,
        "applicability": applicability,
        # Constrained keys the caller did not supply: neither a match nor a conflict.
        "applicability_missing": sorted(k for k in applicability if k not in environment),
        "created_us": rev["created_us"],
    }


def fit_context_bytes(result, max_bytes):
    if max_bytes is None:
        return result
    result = {**result, "matches": list(result["matches"]), "byte_omitted_matches": 0}
    while len(encoded(result).encode("utf-8")) > max_bytes:
        if not result["matches"]:
            raise ValueError("max_bytes too small for context envelope")
        result["matches"].pop()
        result["byte_omitted_matches"] += 1
        result["truncated"] = True
    return result


def validate(query, limit, max_chars, max_bytes, environment):
    if not isinstance(query, str) or not query.strip() or len(query) > 2048:
        raise ValueError("query required, at most 2048 characters")
    if type(limit) is not int or not 1 <= limit <= 5:
        raise ValueError("limit must be 1 to 5")
    if type(max_chars) is not int or not 1 <= max_chars <= 8000:
        raise ValueError("max_chars must be 1 to 8000")
    if max_bytes is not None and (type(max_bytes) is not int or not 1 <= max_bytes <= 65536):
        raise ValueError("max_bytes must be 1 to 65536 or None")
    environment = {} if environment is None else environment
    if not isinstance(environment, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in environment.items()
    ):
        raise ValueError("environment must map strings to strings")
    if len(json.dumps(environment)) > 2048:
        raise ValueError("environment exceeds 2048 characters")
    return environment


def envelope(db, project, mode="memory_disabled"):
    generation = db.execute(
        "SELECT generation FROM search_generations WHERE project_id=?", [project]
    ).fetchone()
    return {
        "project_id": project,
        "corpus_revision": generation[0] if generation else 0,
        "retrieval_mode": mode,
        "truncated": False,
        "matches": [],
    }


def ranked(db, work, owner, query, query_vector, environment, extra="", view="all"):
    """Eligible scored matches, unordered, and whether semantic search ran."""
    from hub.freshness import eligibility

    extra += eligibility(view)
    lexical = _lexical(db, work.project, owner, query, extra)
    # The mode reports whether semantic search ran, not whether it found anything: an empty
    # result under the distance floor is normal, a missing embedder or vector index is not.
    semantic, ran = [], False
    if query_vector:
        try:
            semantic, ran = _semantic(db, work.project, owner, query_vector, extra), True
        except sqlite3.OperationalError:
            pass
    scores = {}
    for source, rows in (("keyword", lexical), ("semantic", semantic)):
        for rank, key in enumerate(rows, 1):
            item = scores.setdefault(key, {"score": 0.0, "best": rank, "reasons": []})
            item["score"] += 1 / (RRF_K + rank)
            item["best"] = min(item["best"], rank)
            item["reasons"].append(source)
    results = []
    for key, rank in scores.items():
        item = _details(db, work, *key, environment)
        if item is not None:
            item.update(rank)
            if item["status"] == "verified":
                item["reasons"].append("verified revision")
            if item.get("applicability_missing"):
                item["reasons"].append("applicability unknown")
            elif item["applicability"]:
                item["reasons"].append("applicability match")
            results.append(item)
    return results, ran


def order(item):
    """Trust, then applicability, then relevance."""
    return (
        {"current": 0, "freshness unknown": 1}.get(item.get("freshness", "current"), 2),
        item["status"] != "verified",
        -(len(item["applicability"]) - len(item.get("applicability_missing", ()))),
        -item["score"],
    )


def tiebreak(item):
    """Equal scores: the better rank in either list, then newer; the id only as a last resort."""
    return item["best"], -item["created_us"], item["id"]


def budget(items, max_chars, truncated):
    """Clip summaries to one shared character budget; returns (matches, truncated)."""
    matches, used = [], 0
    for item in items:
        remaining = max_chars - used
        if remaining <= 0:
            truncated = True
            break
        if len(item["summary"]) > remaining:
            item["summary"] = item["summary"][:remaining]
            truncated = True
        used += len(item["summary"])
        item.pop("score")
        item.pop("best")
        matches.append(item)
    return matches, truncated


@contextlib.contextmanager
def searching():
    """One search slot at a time; records how long this one queued and then ran."""
    start = time.perf_counter()
    with SEARCHES:
        acquired = time.perf_counter()
        try:
            yield
        finally:
            TIMING.set((acquired - start, time.perf_counter() - acquired))


def embedded(query):
    vector = EMBEDDER.embed([query])
    return vector[0] if vector else None


def context(
    work,
    actor,
    query,
    task_id=None,
    environment=None,
    limit=5,
    max_chars=8000,
    max_bytes=None,
    view="current",
):
    environment = validate(query, limit, max_chars, max_bytes, environment)
    from hub.freshness import eligibility

    eligibility(view)

    def search(db):
        if not work._memory_allowed(db, actor, task_id):
            return envelope(db, work.project)
        owner = work._owner(db, actor)  # private memory is visible to its human owner's agents
        results, ran = ranked(db, work, owner, query, query_vector, environment, view=view)
        results.sort(key=lambda r: (*order(r), *tiebreak(r)))
        matches, truncated = budget(results[:limit], max_chars, len(results) > limit)
        return {
            **envelope(db, work.project, "hybrid" if ran else "keyword_only"),
            "truncated": truncated,
            "matches": matches,
        }

    with searching():
        query_vector = embedded(query)
        return fit_context_bytes(work.store.read(search), max_bytes)
