"""SQLite operational store: one writer thread behind a bounded queue, per-thread readers.

Migrations run only through `python -m hub migrate` (operator image, core stopped); opening
a store whose schema differs from this code's migrations fails instead of upgrading it.
"""

import hashlib
import json
import logging
import queue
import sqlite3
import threading
import time
from concurrent.futures import Future
from pathlib import Path

MIGRATIONS = sorted((Path(__file__).parent / "migrations").glob("*.sql"))
SCHEMA_VERSION = len(MIGRATIONS)
MIN_SQLITE = (3, 51, 3)  # WAL-reset fix


class Overloaded(Exception):
    """The write queue is full; the caller should retry later (HTTP 429)."""


class Conflict(Exception):
    """An idempotency key was reused with a different request."""


class SchemaMismatch(RuntimeError):
    pass


def now_us() -> int:
    return time.time_ns() // 1000


def encoded(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def connect(path) -> sqlite3.Connection:
    if sqlite3.sqlite_version_info < MIN_SQLITE:
        raise RuntimeError(f"SQLite {sqlite3.sqlite_version} is older than 3.51.3")
    # Autocommit mode: every transaction below is an explicit BEGIN ... COMMIT.
    con = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA busy_timeout = 5000")
    con.execute("PRAGMA foreign_keys = ON")
    con.execute("PRAGMA journal_mode = WAL")
    # FULL: an acknowledged commit survives power loss, not only a process crash.
    con.execute("PRAGMA synchronous = FULL")
    try:
        import sqlite_vec

        con.enable_load_extension(True)
        sqlite_vec.load(con)
    except (ImportError, OSError, sqlite3.Error):
        logging.getLogger("hub.store").warning("sqlite-vec unavailable; keyword retrieval only")
    finally:
        con.enable_load_extension(False)
    return con


def schema_version(con) -> int:
    con.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations "
        "(version INTEGER PRIMARY KEY, applied_us INTEGER NOT NULL) STRICT"
    )
    return con.execute("SELECT coalesce(max(version), 0) FROM schema_migrations").fetchone()[0]


def migrate(path) -> int:
    """Apply pending migrations in order, each in its own transaction. Returns the version."""
    con = connect(path)
    try:
        current = schema_version(con)
        if current > SCHEMA_VERSION:
            raise SchemaMismatch(f"database is at {current}, newer than {SCHEMA_VERSION}")
        for version, script in enumerate(MIGRATIONS[current:], current + 1):
            try:
                con.executescript(
                    f"BEGIN IMMEDIATE;\n{script.read_text()}\n"
                    f"INSERT INTO schema_migrations VALUES ({version}, {now_us()});\nCOMMIT;"
                )
            except BaseException:
                if con.in_transaction:
                    con.execute("ROLLBACK")
                raise
        return SCHEMA_VERSION
    finally:
        con.close()


class Tx:
    """A write transaction for one project and actor; a job that writes must audit itself."""

    def __init__(self, con, project_id, actor):
        self.con, self.project_id, self.actor = con, project_id, actor
        self.audited = False

    def execute(self, sql, params=()):
        return self.con.execute(sql, params)

    def _append(self, table, column, name, object_id, detail):
        seq = self.con.execute(
            f"SELECT coalesce(max(seq), 0) + 1 FROM {table} WHERE project_id = ?",
            [self.project_id],
        ).fetchone()[0]
        self.con.execute(
            f"INSERT INTO {table} (project_id, seq, actor, {column}, object_id, detail, "
            "created_us) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [self.project_id, seq, self.actor, name, object_id, encoded(detail), now_us()],
        )
        return seq

    def audit(self, action, object_id, detail):
        self.audited = True
        return self._append("audit", "action", action, object_id, detail)

    def change(self, operation, object_id, detail):
        return self._append("changes", "operation", operation, object_id, detail)


class Store:
    def __init__(self, path, queue_size=256):
        self.path = str(path)
        writer = connect(self.path)
        version = schema_version(writer)
        if version != SCHEMA_VERSION:
            writer.close()
            raise SchemaMismatch(
                f"database schema {version}, code expects {SCHEMA_VERSION}; run hub migrate"
            )
        self._local, self._readers = threading.local(), []
        self._write_stats = {"wait_seconds": 0.0, "transaction_seconds": 0.0, "transactions": 0}
        self._jobs = queue.Queue(queue_size)
        self._writer = threading.Thread(
            target=self._run, args=(writer,), name="hub-writer", daemon=True
        )
        self._writer.start()

    def _run(self, con):
        while (job := self._jobs.get()) is not None:
            fn, future, queued = job
            started = time.monotonic()
            self._write_stats["wait_seconds"] += started - queued
            try:
                con.execute("BEGIN IMMEDIATE")
                result = fn(con)
                con.execute("COMMIT")
                self._write_stats["transaction_seconds"] += time.monotonic() - started
                self._write_stats["transactions"] += 1
                future.set_result(result)
            except BaseException as error:
                if con.in_transaction:
                    con.execute("ROLLBACK")
                future.set_exception(error)
        con.close()

    def write_metrics(self):
        return {**self._write_stats, "queue_depth": self._jobs.qsize()}

    def _submit(self, fn):
        if threading.current_thread() is self._writer:
            raise RuntimeError("nested write would deadlock the writer thread")
        future = Future()
        try:
            self._jobs.put_nowait((fn, future, time.monotonic()))
        except queue.Full:
            raise Overloaded("write queue full") from None
        return future.result()

    def read(self, fn):
        """Run fn(con) in one read transaction (a consistent snapshot) on this thread's reader."""
        con = getattr(self._local, "con", None)
        if con is None:
            con = self._local.con = connect(self.path)
            self._readers.append(con)
        con.execute("BEGIN")
        try:
            return fn(con)
        finally:
            con.execute("COMMIT")

    def mutate(self, project_id, actor, fn, idempotency_key=None, request=None):
        """Run fn(tx) atomically with its audit and change rows; replay a matching key."""
        digest = hashlib.sha256(encoded(request).encode()).hexdigest()

        def job(con):
            if idempotency_key is not None:
                row = con.execute(
                    "SELECT request_sha256, response FROM idempotency "
                    "WHERE project_id = ? AND actor = ? AND key = ?",
                    [project_id, actor, idempotency_key],
                ).fetchone()
                if row:
                    if row["request_sha256"] != digest:
                        raise Conflict("idempotency key reused with a different request")
                    return json.loads(row["response"])
            tx = Tx(con, project_id, actor)
            before = con.total_changes
            result = fn(tx)
            if con.total_changes != before and not tx.audited:
                raise RuntimeError("mutation recorded no audit entry")
            if idempotency_key is not None:
                con.execute(
                    "INSERT INTO idempotency VALUES (?, ?, ?, ?, ?, ?)",
                    [project_id, actor, idempotency_key, digest, encoded(result), now_us()],
                )
            return result

        return self._submit(job)

    def create_project(self, project_id, name, actor):
        def fn(tx):
            tx.execute("INSERT INTO projects VALUES (?, ?, ?)", [project_id, name, now_us()])
            tx.audit("project.create", project_id, {"name": name})
            tx.change("project.create", project_id, {})
            return {"id": project_id, "name": name}

        return self.mutate(project_id, actor, fn)

    def close(self):
        self._jobs.put(None)
        self._writer.join()
        for con in self._readers:
            con.close()
