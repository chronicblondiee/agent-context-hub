"""Optional peer delivery contracts: explicit share, dedup, receipts and privacy."""

import os
import tempfile
import unittest

from hub import federation, identity
from hub.store import Conflict, Store, migrate
from hub.work import Work


class FederationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.stores = {}
        for name, remote in (("site-a", "site-b"), ("site-b", "site-a")):
            path = os.path.join(self.temp.name, name + ".sqlite3")
            migrate(path)
            store = self.stores[name] = Store(path)
            identity.create_project(store, "admin", name, name)
            identity.create_principal(store, "admin", "bridge", "connector")
            identity.grant(store, "admin", "bridge", name, "connector")
            federation.peer(store, "admin", name, remote, "bridge")
        self.a, self.b = self.stores["site-a"], self.stores["site-b"]

    def tearDown(self):
        for store in self.stores.values():
            store.close()
        self.temp.cleanup()

    def _remember(self, visibility="project"):
        return Work(self.a, "site-a").remember(
            "writer",
            "ops",
            "fact",
            "docker service repair",
            "tested",
            0.9,
            ["test:one"],
            visibility=visibility,
        )["id"]

    def _deliver(self):
        delivery = federation.outbox(self.a, "site-a", "bridge")[0]
        result = federation.incoming(self.b, "site-b", "site-a", "bridge", delivery["event"])
        return delivery, result

    def test_share_apply_receipt_and_duplicate(self):
        ident = self._remember()
        first = federation.share(self.a, "site-a", "writer", ident, "site-b", "request-1")
        self.assertEqual(
            federation.share(self.a, "site-a", "writer", ident, "site-b", "request-1"),
            first,
        )
        delivery, result = self._deliver()
        self.assertFalse(result["duplicate"])
        self.assertTrue(
            federation.incoming(self.b, "site-b", "site-a", "bridge", delivery["event"])[
                "duplicate"
            ]
        )
        altered = {**delivery["event"], "record": {**delivery["event"]["record"], "body": "forged"}}
        with self.assertRaisesRegex(Conflict, "changed payload"):
            federation.incoming(self.b, "site-b", "site-a", "bridge", altered)
        received = federation._incoming_record_id("site-a", ident)
        self.assertEqual(
            Work(self.b, "site-b").record("reader", received)["body"], "docker service repair"
        )
        federation.receipt(self.a, "site-a", "site-b", "bridge", first["id"])
        self.assertEqual(federation.outbox(self.a, "site-a", "bridge"), [])

    def test_private_and_received_records_cannot_be_forwarded(self):
        private = self._remember("private")
        with self.assertRaisesRegex(ValueError, "project record"):
            federation.share(self.a, "site-a", "writer", private, "site-b", "private")
        ident = self._remember()
        federation.share(self.a, "site-a", "writer", ident, "site-b", "shared")
        delivery, _ = self._deliver()
        received = federation._incoming_record_id("site-a", ident)
        with self.assertRaisesRegex(ValueError, "owned project record"):
            federation.share(self.b, "site-b", "writer", received, "site-a", "forward")
        self.assertEqual(delivery["event"]["record"]["visibility"], "project")

    def test_revocation_queues_update_and_receiver_deindexes(self):
        ident = self._remember()
        federation.share(self.a, "site-a", "writer", ident, "site-b", "share")
        delivery, _ = self._deliver()
        federation.receipt(self.a, "site-a", "site-b", "bridge", delivery["event"]["id"])
        Work(self.a, "site-a").revoke_memory("writer", ident)
        update, _ = self._deliver()
        received = federation._incoming_record_id("site-a", ident)
        self.assertTrue(Work(self.b, "site-b").record("reader", received)["revoked"])
        self.assertTrue(update["event"]["record"]["revoked"])
        delayed = {**delivery["event"], "id": "delayed-old-event"}
        federation.incoming(self.b, "site-b", "site-a", "bridge", delayed)
        self.assertTrue(Work(self.b, "site-b").record("reader", received)["revoked"])


if __name__ == "__main__":
    unittest.main()
