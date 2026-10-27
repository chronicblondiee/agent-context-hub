"""Backups: consistent copy with artifacts, verified restore that revokes every key, retention."""

import datetime
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from hub import backup, identity, store
from hub.store import SchemaMismatch, Store, migrate
from hub.work import Work


class BackupTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.path = root / "data" / "hub.sqlite3"
        self.path.parent.mkdir()
        self.root = root / "backups"
        migrate(self.path)
        self.s = Store(self.path)
        identity.bootstrap(self.s, "root")
        identity.create_project(self.s, "root", "p1", "one")
        identity.create_principal(self.s, "root", "worker", "agent")
        identity.grant(self.s, "root", "worker", "p1", "contributor")
        identity.create_principal(self.s, "root", "boss", "human")
        identity.grant(self.s, "root", "boss", "p1", "maintainer")
        identity.bind(self.s, "root", "worker", "boss")
        self.key = identity.issue_key(self.s, "root", "worker")
        self.memory = Work(self.s, "p1").remember(
            "worker", "ops", "fact", "restore me", "tested", 1.0, ["test:1"]
        )["id"]
        blob = b"artifact bytes"
        art = self.path.parent / "artifacts" / "p1" / "worker" / "a1"
        art.parent.mkdir(parents=True)
        art.write_bytes(blob)

        def put(tx):
            tx.execute(
                "INSERT INTO artifacts VALUES (?, ?, ?, ?, ?, ?)",
                ["p1", "worker", "a1", hashlib.sha256(blob).hexdigest(), len(blob), 0],
            )
            tx.audit("artifact.put", "a1", {})

        self.s.mutate("p1", "root", put)

    def tearDown(self):
        self.s.close()
        self.tmp.cleanup()

    def target(self, name="restored"):
        d = Path(self.tmp.name) / name
        d.mkdir()
        return d / "hub.sqlite3"

    def test_round_trip_restores_data_and_revokes_every_key(self):
        made = backup.create(self.s, self.root)
        self.assertEqual((made["artifacts"], made["schema_version"]), (1, store.SCHEMA_VERSION))
        target = self.target()
        result = backup.restore(self.root / made["backup"], target)
        self.assertEqual(result["restored"], made["backup"])  # the backup's name, not its path
        self.assertGreaterEqual(result["keys_revoked"], 2)
        restored = Store(target)
        try:
            self.assertEqual(
                Work(restored, "p1").record("worker", self.memory)["body"], "restore me"
            )
            self.assertEqual(
                (target.parent / "artifacts/p1/worker/a1").read_bytes(), b"artifact bytes"
            )
            # A key valid when the backup was taken never authenticates after a restore.
            self.assertIsNone(identity.authenticate(restored, self.key["key"]))
            with self.assertRaisesRegex(ValueError, "not a service administrator"):
                identity.recover_admin(restored, "worker")
            admin = identity.recover_admin(restored, "root")
            self.assertTrue(identity.authenticate(restored, admin["key"]).service_admin)
        finally:
            restored.close()

    def test_incident_history_and_uncertain_reservation_survive_restore(self):
        work = Work(self.s, "p1")
        thread = work.tshoot_open("worker", "synthetic:restore")["id"]
        work.tshoot_append("worker", thread, "finding", "observed", ["synthetic:source"])
        task = work.create_task("worker", "synthetic incident", [])
        session = work.resume("worker", task["id"])["session"]
        fence = {k: session[k] for k in ("session_id", "generation")}
        action = work.tshoot_action_reserve(
            "worker", thread, "ct:synthetic", intent="check", **fence
        )
        work.tshoot_action_start("worker", action["id"], **fence)
        made = backup.create(self.s, self.root)
        target = self.target()
        backup.restore(self.root / made["backup"], target)
        restored = Store(target)
        try:
            found = Work(restored, "p1").tshoot_read("worker", thread)
            self.assertEqual(found["participants"], ["worker"])
            self.assertEqual(found["events"][1]["body"], "observed")
            self.assertEqual(found["actions"][0]["id"], action["id"])
            with self.assertRaisesRegex(ValueError, "uncertain"):
                Work(restored, "p1").tshoot_close("worker", thread, "done", ["synthetic:source"])
        finally:
            restored.close()

    def test_damaged_foreign_or_occupied_targets_are_refused(self):
        made = self.root / backup.create(self.s, self.root)["backup"]
        with self.assertRaisesRegex(ValueError, "empty data directory"):
            backup.restore(made, self.path)
        art = made / "artifacts/p1/worker/a1"
        art.write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "does not match its hash"):
            backup.restore(made, self.target("a"))
        art.unlink()
        with self.assertRaisesRegex(ValueError, "do not match its manifest"):
            backup.restore(made, self.target("b"))
        other = self.root / backup.create(self.s, self.root)["backup"]
        manifest = json.loads((other / "manifest.json").read_text())
        manifest["schema_version"] = 999
        (other / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaises(SchemaMismatch):
            backup.restore(other, self.target("c"))

    def test_retention_keeps_seven_days_and_four_weeks(self):
        self.root.mkdir()
        start = datetime.datetime(2026, 10, 25, 3, tzinfo=datetime.UTC)
        for hours in range(0, 60 * 24, 12):  # two backups a day for 60 days
            when = start - datetime.timedelta(hours=hours)
            d = self.root / when.strftime("%Y%m%dT%H")
            d.mkdir()
            (d / "manifest.json").write_text(json.dumps({"created_us": when.timestamp() * 1e6}))
        (self.root / ".partial.tmp").mkdir()  # an unfinished backup is never touched
        labelled = self.root / "20250101T00"
        labelled.mkdir()  # a pre-upgrade backup, far older than any retention window
        (labelled / "manifest.json").write_text(
            json.dumps({"created_us": 0, "label": "pre-upgrade"})
        )
        kept = backup.prune(self.root)
        days = {k[:8] for k in kept}
        self.assertEqual(len([k for k in kept if k[:8] >= "20261019"]), 7)
        self.assertLessEqual(len(kept), 7 + 4)
        self.assertIn("20261025T03", kept)  # the newest backup always survives
        self.assertEqual(len(days), len(kept))  # at most one per day
        self.assertTrue((self.root / ".partial.tmp").exists())
        self.assertTrue(labelled.exists())  # labelled backups are outside retention
        self.assertNotIn("20250101T00", kept)


if __name__ == "__main__":
    unittest.main()
