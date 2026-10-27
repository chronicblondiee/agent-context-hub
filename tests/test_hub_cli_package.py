"""Standard-library package smoke checks, also run in the Python 3.11 image."""

import hashlib
import json
import os
import subprocess
import tarfile
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SOURCE = Path("/source")
REVISION = "a" * 40


def package(output):
    subprocess.run(
        ["sh", str(SOURCE / "scripts/package_hub_cli.sh"), str(output), REVISION],
        check=True,
        capture_output=True,
    )
    return output / f"hub-cli-{REVISION}.tar.gz"


class CliPackageTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.archive = package(self.directory / "output")
        self.extracted = self.directory / "extracted"
        self.extracted.mkdir()
        with tarfile.open(self.archive) as archive:
            archive.extractall(self.extracted, filter="data")
        self.env = {
            k: v for k, v in os.environ.items() if not k.startswith(("HUB_", "CODEX_", "XDG_"))
        }
        self.env.update(
            HOME=str(self.directory),
            XDG_CONFIG_HOME=str(self.directory / "config"),
            XDG_STATE_HOME=str(self.directory / "state"),
        )

    def cli(self, *args):
        return subprocess.run(
            [str(self.extracted / "hub"), *args],
            cwd=self.directory,
            env=self.env,
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_reproducible_allowlisted_archive_and_help(self):
        other = package(self.directory / "other")
        self.assertEqual(self.archive.read_bytes(), other.read_bytes())
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.assertEqual(
            self.archive.with_suffix(".gz.sha256").read_text(),
            f"{digest}  {self.archive.name}\n",
        )
        with tarfile.open(self.archive) as archive:
            self.assertEqual(set(archive.getnames()), {"hub", "README.md", "LICENSE", "REVISION"})
            for member in archive.getmembers():
                self.assertTrue(member.isfile())
                self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 0))
                self.assertEqual(member.mode, 0o755 if member.name == "hub" else 0o644)
        self.assertEqual((self.extracted / "REVISION").read_text(), REVISION + "\n")
        self.assertEqual(
            (self.extracted / "hub").read_bytes(), (SOURCE / "plugins/hub/bin/hub").read_bytes()
        )
        result = self.cli("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--human", result.stdout)
        invalid = subprocess.run(
            ["sh", str(SOURCE / "scripts/package_hub_cli.sh"), str(other.parent), "../bad"],
            capture_output=True,
        )
        self.assertNotEqual(invalid.returncode, 0)

    def test_human_setup_and_status_without_server_dependencies(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(
                    json.dumps(
                        dict(
                            id="human",
                            kind="human",
                            workflow_version=1,
                            grants={"p1": ["contributor"]},
                            capabilities=["tshoot_open"],
                        )
                    ).encode()
                )

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            self.env["HUB_MCP_KEY"] = "synthetic-key"
            result = self.cli(
                "--human",
                "setup",
                "--endpoint",
                f"http://127.0.0.1:{server.server_port}",
                "--project",
                "p1",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            config = self.directory / "config/hub/config.json"
            self.assertFalse(json.loads(config.read_text())["automatic_context"])
            self.assertNotIn("synthetic-key", config.read_text())
            result = self.cli("status")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["identity"], "human")
            self.assertNotIn("codex_mcp", result.stdout)
            self.env["CODEX_THREAD_ID"] = "must-not-inherit"
            result = self.cli("leave")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("session ID missing", result.stderr)
            self.assertEqual(self.cli("--session", "human-check", "leave").returncode, 0)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
