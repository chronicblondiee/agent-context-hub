"""Store contracts: pragmas, schema gate, atomic audit/changes, idempotency, overload, crash."""

import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from hub import store
from hub.store import Conflict, Overloaded, SchemaMismatch, Store, migrate


def put(tx, ident, body="{}"):
    tx.execute("INSERT INTO objects VALUES (?, 'task', ?, ?)", [tx.project_id, ident, body])
    tx.audit("task.create", ident, {})
    tx.change("task.create", ident, {})
    return {"id": ident}


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "hub.sqlite3")
        migrate(self.path)
        self.s = Store(self.path)
        self.s.create_project("p1", "one", "operator")
        self.s.create_project("p2", "two", "operator")

    def tearDown(self):
        self.s.close()
        self.tmp.cleanup()

    def rows(self, sql, params=()):
        return [tuple(r) for r in self.s.read(lambda con: con.execute(sql, params).fetchall())]

    def test_pragmas(self):
        con = store.connect(self.path)
        self.assertEqual(con.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        self.assertEqual(con.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        self.assertEqual(con.execute("PRAGMA synchronous").fetchone()[0], 2)
        con.close()

    def test_schema_gate(self):
        fresh = os.path.join(self.tmp.name, "fresh.sqlite3")
        with self.assertRaises(SchemaMismatch):
            Store(fresh)
        self.assertEqual(migrate(fresh), store.SCHEMA_VERSION)
        self.assertEqual(migrate(fresh), store.SCHEMA_VERSION)  # idempotent
        con = store.connect(fresh)
        con.execute("INSERT INTO schema_migrations VALUES (999, 0)")
        con.close()
        with self.assertRaises(SchemaMismatch):
            migrate(fresh)  # never downgrade a newer database

    def test_mutation_audit_and_change_roll_back_together(self):
        def fail(tx):
            put(tx, "t1")
            raise ValueError("boom")

        with self.assertRaises(ValueError):
            self.s.mutate("p1", "agent", fail)
        self.assertEqual(self.rows("SELECT id FROM objects"), [])
        self.assertEqual(self.rows("SELECT seq FROM changes WHERE object_id = 't1'"), [])
        self.assertEqual(self.rows("SELECT seq FROM audit WHERE object_id = 't1'"), [])

    def test_unaudited_mutation_is_rejected(self):
        def silent(tx):
            tx.execute("INSERT INTO objects VALUES ('p1', 'task', 't1', '{}')")

        with self.assertRaises(RuntimeError):
            self.s.mutate("p1", "agent", silent)
        self.assertEqual(self.rows("SELECT id FROM objects"), [])
        # A job that only reads (a replayed finish, a rejected request) needs no audit row.
        self.assertEqual(self.s.mutate("p1", "agent", lambda tx: "read only"), "read only")

    def test_idempotency_replays_and_conflicts(self):
        calls = []

        def once(tx):
            calls.append(1)
            return put(tx, f"t{len(calls)}")

        first = self.s.mutate("p1", "a", once, idempotency_key="k", request={"goal": "x"})
        again = self.s.mutate("p1", "a", once, idempotency_key="k", request={"goal": "x"})
        self.assertEqual((first, again, len(calls)), ({"id": "t1"}, {"id": "t1"}, 1))
        with self.assertRaises(Conflict):
            self.s.mutate("p1", "a", once, idempotency_key="k", request={"goal": "y"})
        # Another actor's key is independent and never sees the first actor's response.
        self.assertEqual(self.s.mutate("p1", "b", once, idempotency_key="k"), {"id": "t2"})

    def test_equal_ids_and_sequences_are_per_project(self):
        self.s.mutate("p1", "a", lambda tx: put(tx, "same"))
        self.s.mutate("p2", "a", lambda tx: put(tx, "same"))
        self.assertEqual(
            self.rows("SELECT project_id, seq, object_id FROM changes ORDER BY project_id, seq"),
            [("p1", 1, "p1"), ("p1", 2, "same"), ("p2", 1, "p2"), ("p2", 2, "same")],
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.s.mutate("p1", "a", lambda tx: put(tx, "same"))
        with self.assertRaises(sqlite3.IntegrityError):  # unknown project: foreign key
            self.s.mutate("nope", "a", lambda tx: put(tx, "x"))

    def test_full_queue_raises_overloaded(self):
        small = Store(self.path, queue_size=1)
        started, release = threading.Event(), threading.Event()

        def block(tx):
            started.set()
            release.wait()
            return put(tx, "blocker")

        threads = [threading.Thread(target=small.mutate, args=("p1", "a", block))]
        threads[0].start()
        started.wait()
        threads.append(
            threading.Thread(target=small.mutate, args=("p1", "a", lambda tx: put(tx, "q")))
        )
        threads[1].start()
        while small._jobs.qsize() < 1:
            time.sleep(0.01)
        with self.assertRaises(Overloaded):
            small.mutate("p1", "a", lambda tx: put(tx, "rejected"))
        release.set()
        for t in threads:
            t.join()
        small.close()
        self.assertEqual(self.rows("SELECT id FROM objects ORDER BY id"), [("blocker",), ("q",)])

    def test_timestamps_are_utc_integer_microseconds(self):
        (created,) = self.rows("SELECT created_us FROM projects WHERE id = 'p1'")[0]
        self.assertIsInstance(created, int)
        self.assertLess(abs(created - time.time() * 1_000_000), 60_000_000)

    def test_sigkill_loses_no_acknowledged_write(self):
        child = subprocess.Popen(
            [sys.executable, "-c", CHILD, self.path],
            stdout=subprocess.PIPE,
            text=True,
            cwd=Path(__file__).resolve().parents[1],
        )
        acked = [child.stdout.readline().strip() for _ in range(50)]
        child.send_signal(signal.SIGKILL)
        child.wait()
        con = store.connect(self.path)
        self.assertEqual(con.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        stored = {r[0] for r in con.execute("SELECT id FROM objects WHERE project_id = 'p1'")}
        con.close()
        self.assertLessEqual(set(acked), stored)

    def test_core_never_imports_duckdb(self):
        subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys, hub, hub.store; assert 'duckdb' not in sys.modules",
            ],
            check=True,
            cwd=Path(__file__).resolve().parents[1],
        )


# Writes until killed, printing each id only after its commit returned.
CHILD = """
import sys
from hub.store import Store
s = Store(sys.argv[1])
i = 0
while True:
    i += 1
    def fn(tx, ident=f"k{i}"):
        tx.execute("INSERT INTO objects VALUES ('p1', 'task', ?, '{}')", [ident])
        tx.audit("task.create", ident, {})
        return ident
    print(s.mutate("p1", "writer", fn), flush=True)
"""


if __name__ == "__main__":
    unittest.main()
