"""Identity contracts: single-use bootstrap, digest-only keys, expiry, rotation, revocation."""

import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hub import identity
from hub.store import Store, migrate


class IdentityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "hub.sqlite3")
        migrate(self.path)
        self.s = Store(self.path)
        self.admin = identity.bootstrap(self.s, "root")
        identity.create_project(self.s, "root", "p1", "one")
        identity.create_principal(self.s, "root", "worker", "agent")
        self.key = identity.issue_key(self.s, "root", "worker")

    def tearDown(self):
        self.s.close()
        self.tmp.cleanup()

    def auth(self, key):
        return identity.authenticate(self.s, key["key"] if isinstance(key, dict) else key)

    def test_bootstrap_is_single_use_and_grants_no_content(self):
        with self.assertRaisesRegex(ValueError, "already bootstrapped"):
            identity.bootstrap(self.s, "second")
        root = self.auth(self.admin)
        self.assertTrue(root.service_admin)
        self.assertEqual(root.grants, {})

    def test_bootstrap_cli_prints_only_the_key(self):
        fresh = os.path.join(self.tmp.name, "fresh.sqlite3")
        migrate(fresh)
        run = [sys.executable, "-m", "hub", "bootstrap", "admin"]
        env = {**os.environ, "HUB_DB": fresh}
        root = Path(__file__).resolve().parents[1]
        out = subprocess.run(run, env=env, cwd=root, capture_output=True, text=True, check=True)
        self.assertRegex(out.stdout, r"^hub_[0-9a-f]{16}_[A-Za-z0-9_-]{43}\n$")
        again = subprocess.run(run, env=env, cwd=root, capture_output=True, text=True)
        self.assertNotEqual(again.returncode, 0)
        self.assertEqual(again.stdout, "")

    def test_only_the_digest_is_stored(self):
        secret = self.key["key"].split("_", 2)[2]  # base64url secrets may contain "_"
        with open(self.path, "rb") as f:
            raw = f.read()
        for suffix in ("-wal", ""):
            if os.path.exists(self.path + suffix):
                with open(self.path + suffix, "rb") as f:
                    raw += f.read()
        self.assertNotIn(secret.encode(), raw)
        self.assertNotIn(self.key["key"].encode(), raw)
        self.assertEqual(self.auth(self.key).id, "worker")

    def test_malformed_tampered_and_unknown_keys_fail(self):
        key = self.key["key"]
        tampered = key[:-1] + ("A" if key[-1] != "A" else "B")
        # Same decoded bytes, different spelling: flip the spare low bits of the last character.
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        spare = key[:-1] + alphabet[alphabet.index(key[-1]) ^ 1]
        for key in (
            "",
            None,
            "Bearer x",
            "hub_zz_x",
            tampered,
            spare,
            "hub_" + "0" * 16 + "_" + "A" * 43,
        ):
            self.assertIsNone(identity.authenticate(self.s, key), key)

    def test_expired_and_revoked_keys_fail_on_the_next_call(self):
        self.assertTrue(self.auth(self.key))
        identity.revoke_key(self.s, "root", self.key["id"])
        self.assertIsNone(self.auth(self.key))
        short = identity.issue_key(self.s, "root", "worker", days=1)
        later = identity.now_us() + identity.DAY_US + 1
        with patch("hub.identity.now_us", return_value=later):
            self.assertIsNone(self.auth(short))
        with self.assertRaisesRegex(ValueError, "lifetime"):
            identity.issue_key(self.s, "root", "worker", days=366)

    def test_rotation_overlap_is_capped_and_never_extends(self):
        with self.assertRaisesRegex(ValueError, "overlap"):
            identity.rotate_key(self.s, "root", self.key["id"], overlap_s=86_401)
        new = identity.rotate_key(self.s, "root", self.key["id"], overlap_s=3600)
        self.assertTrue(self.auth(self.key))  # inside the overlap
        self.assertEqual(self.auth(new).id, "worker")
        with patch("hub.identity.now_us", return_value=new["previous_expires_us"]):
            self.assertIsNone(self.auth(self.key))
        # A nearly expired key keeps its expiry: rotation never lengthens the old key's life.
        short = identity.issue_key(self.s, "root", "worker", days=1)
        rotated = identity.rotate_key(self.s, "root", short["id"], overlap_s=86_400)
        self.assertLessEqual(rotated["previous_expires_us"], short["expires_us"])
        immediate = identity.rotate_key(self.s, "root", new["id"])
        self.assertIsNone(self.auth(new))
        self.assertTrue(self.auth(immediate))

    def test_grants_are_additive_and_revocable(self):
        identity.grant(self.s, "root", "worker", "p1", "reader")
        identity.grant(self.s, "root", "worker", "p1", "contributor")
        identity.grant(self.s, "root", "worker", "p1", "contributor")  # repeat is a no-op
        self.assertEqual(self.auth(self.key).roles("p1"), {"reader", "contributor"})
        identity.grant(self.s, "root", "worker", "p1", "reader", revoke=True)
        self.assertEqual(self.auth(self.key).roles("p1"), {"contributor"})
        with self.assertRaisesRegex(ValueError, "invalid project"):
            identity.grant(self.s, "root", "worker", "_system", "reader")
        with self.assertRaises(sqlite3.IntegrityError):
            identity.grant(self.s, "root", "worker", "nope", "reader")
        with self.assertRaisesRegex(ValueError, "role"):
            identity.grant(self.s, "root", "worker", "p1", "owner")

    def test_admin_actions_are_audited_without_secrets(self):
        rows = self.s.read(
            lambda con: con.execute(
                "SELECT action, detail FROM audit WHERE project_id = '_system'"
            ).fetchall()
        )
        actions = [r[0] for r in rows]
        self.assertIn("bootstrap", actions)
        self.assertIn("principal.create", actions)
        self.assertEqual(actions.count("key.issue"), 2)
        self.assertFalse(any(self.key["key"].split("_", 2)[2] in r[1] for r in rows))


if __name__ == "__main__":
    unittest.main()
