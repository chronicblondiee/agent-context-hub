"""Operator UI: off by default, renders state without private content, and every action carries
its own key through the shared authorization."""

import http.cookiejar
import os
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from unittest.mock import patch

import uvicorn
from fastapi import FastAPI

from hub import api, app, identity, ui
from hub.store import Store, migrate
from hub.work import Work


class UiTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        path = os.path.join(self.tmp.name, "hub.sqlite3")
        migrate(path)
        self.s = Store(path)
        api._buckets.clear()
        identity.bootstrap(self.s, "root")
        identity.create_project(self.s, "root", "p1", "one")
        self.keys = {}
        for name, kind, roles in (
            ("worker", "agent", ("contributor", "maintainer")),
            ("other", "agent", ("contributor",)),
            ("boss", "human", ("maintainer",)),
            ("lead", "human", ("maintainer",)),
        ):
            identity.create_principal(self.s, "root", name, kind)
            for role in roles:
                identity.grant(self.s, "root", name, "p1", role)
            self.keys[name] = identity.issue_key(self.s, "root", name)["key"]
        identity.bind(self.s, "root", "worker", "lead")  # boss is another human: no private view
        w = Work(self.s, "p1")
        self.shared = w.remember(
            "worker", "ops", "fact", "shared socket fix", "tested", 1.0, ["t"]
        )["id"]
        self.private = w.remember(
            "worker",
            "ops",
            "fact",
            "private secret note",
            "tested",
            1.0,
            ["t"],
            visibility="private",
        )["id"]
        w.create_task("worker", "visible workflow goal", [])
        site = FastAPI()
        site.state.store = self.s
        api.install(site)
        site.include_router(ui.router)
        self.server = uvicorn.Server(
            uvicorn.Config(site, host="127.0.0.1", port=0, log_level="critical")
        )
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()
        while not self.server.started:
            time.sleep(0.01)
        self.base = f"http://127.0.0.1:{self.server.servers[0].sockets[0].getsockname()[1]}"

    def tearDown(self):
        self.server.should_exit = True
        self.thread.join()
        self.s.close()
        self.tmp.cleanup()

    def get(self, path):
        with urllib.request.urlopen(self.base + path) as response:
            return response.read().decode()

    def post(self, path, form, origin=None):
        headers = {"Origin": origin} if origin else {}
        request = urllib.request.Request(
            self.base + path, urllib.parse.urlencode(form).encode(), headers, method="POST"
        )
        with urllib.request.urlopen(request) as response:  # follows the 303 back to the project
            return response.read().decode()

    def revoked(self):
        return self.s.read(
            lambda db: db.execute(
                "SELECT revoked FROM memory_records WHERE id = ?", [self.shared]
            ).fetchone()[0]
        )

    def test_off_unless_declared(self):
        self.assertFalse(any(getattr(r, "path", "").startswith("/ui") for r in app.routes))

    def test_pages_show_workflow_but_never_private_content(self):
        overview = self.get("/ui")
        self.assertIn("p1", overview)
        self.assertIn('http-equiv="refresh"', overview)
        project = self.get("/ui/p/p1")
        self.assertIn("visible workflow goal", project)
        self.assertIn("shared socket fix", project)
        activity = self.get("/ui/p/p1/activity")
        self.assertIn("project.create", activity)  # audit feed
        self.assertIn("(private record)", activity)
        for page in (overview, project, activity, self.get(f"/ui/p/p1/r/{self.private}")):
            self.assertNotIn("private secret note", page)
            self.assertNotIn(self.private, page.replace(f"/ui/p/p1/r/{self.private}", ""))
        self.assertIn("No such project-visible record", self.get(f"/ui/p/p1/r/{self.private}"))
        self.assertIn("&lt;", ui.table(["h"], [["<script>"]]))  # values are escaped

    def test_activity_and_attempts_show_stored_telemetry(self):
        w = Work(self.s, "p1")
        task = w.create_task("worker", "reserve something", [])["id"]
        session = w.resume("worker", task)["session"]
        thread = w.tshoot_open("worker", "ct:122")["id"]
        fence = dict(session_id=session["session_id"], generation=session["generation"])
        w.tshoot_action_reserve("worker", **fence, thread_id=thread, resource="ct:122", intent="t")
        w.attempt_record("worker", "restart the socket", "worked after restart", ["log:1"])
        activity = self.get("/ui/p/p1/activity")
        self.assertIn('class="bar"', activity)  # changes per day
        self.assertIn("ct:122", activity)  # held reservation
        self.assertIn("reserved", activity)
        filtered = self.get("/ui/p/p1/activity?actor=nobody")
        self.assertNotIn("project.create", filtered.split("Audit")[-1])

        def lose_outcome(tx):
            tx.execute("UPDATE troubleshooting_actions SET status='outcome-unknown'")
            tx.audit("test.lose_outcome", thread, {})

        self.s.mutate("p1", "test", lose_outcome)
        self.assertIn("outcome-unknown", self.get("/ui/p/p1/activity"))
        attempts = self.get("/ui/p/p1/attempts")
        self.assertIn("restart the socket", attempts)
        self.assertIn("log:1", attempts)
        self.assertIn("No such project", self.get("/ui/p/nope/activity"))

    def test_search_runs_retrieval_as_the_signed_in_human(self):
        for path in ("/ui/p/p1/search?q=socket", "/ui/p/p1/threads"):  # unsigned: sent to sign in
            self.assertIn("sign in with a human hub key", self.get(path))
        opener = urllib.request.build_opener()
        opener.addheaders = [("Cookie", f"{ui.COOKIE}={self.keys['boss']}")]

        def search(project, q):
            path = f"/ui/p/{project}/search?q={urllib.parse.quote(q)}"
            with opener.open(self.base + path) as response:
                return response.read().decode()

        with patch("hub.retrieval.EMBEDDER.embed", return_value=None):  # semantic search down
            found = search("p1", "socket fix")
        self.assertIn(f"/ui/p/p1/r/{self.shared}", found)
        self.assertIn("corpus revision", found)
        self.assertIn("Semantic search is unavailable", found)
        self.assertNotIn(self.private, search("p1", "private secret note"))  # private to worker
        identity.create_project(self.s, "root", "p2", "two")
        self.assertIn("refused", search("p2", "socket"))

    def test_actions_need_a_key_with_the_authority(self):
        path = f"/ui/p/p1/r/{self.shared}/revoke"
        self.assertIn("refused: that is not a valid hub key", self.post(path, {"key": "nope"}))
        self.assertIn("refused", self.post(path, {"key": self.keys["other"]}))
        self.assertIn(
            "cross-site", self.post(path, {"key": self.keys["worker"]}, "http://evil.example")
        )
        self.assertFalse(self.revoked())
        self.assertIn(
            "done: revoke_memory as worker", self.post(path, {"key": self.keys["worker"]})
        )
        self.assertTrue(self.revoked())

    def test_solution_decisions_need_a_human_maintainer(self):
        created = Work(self.s, "p1").solution_propose(
            "worker",
            body="Restart the Docker service",
            problem_key="docker-restart",
            repository_commit="a" * 40,
            image_digest="sha256:" + "b" * 64,
            checks_sha256="c" * 64,
        )
        path = f"/ui/p/p1/s/{created['id']}/decide"
        form = {"action": "review", "reason": "check it", "revision": 1}
        self.assertIn("Restart the Docker service", self.get(f"/ui/p/p1/s/{created['id']}"))
        self.assertIn("requires a human", self.post(path, {**form, "key": self.keys["worker"]}))
        self.assertIn(
            "done: solution_decide as boss", self.post(path, {**form, "key": self.keys["boss"]})
        )

    def test_library_proposals_publish_through_the_form_and_gate_records(self):
        from hub import library

        identity.create_project(self.s, "root", "lib", "library")
        identity.grant(self.s, "root", "lead", "lib", "maintainer")
        library.configure(self.s, "root", "lib")
        w = Work(self.s, "p1")
        proposal = w.tshoot_propose(
            "worker", self.shared, "sanitized socket fix", ["https://example.test/check"]
        )["id"]
        self.assertIn("sign in with a human hub key", self.get("/ui/p/p1/proposals"))
        opener = urllib.request.build_opener()
        opener.addheaders = [("Cookie", f"{ui.COOKIE}={self.keys['lead']}")]
        with opener.open(self.base + "/ui/p/p1/proposals") as response:
            listed = response.read().decode()
        self.assertIn("sanitized socket fix", listed)
        self.assertIn(f"/ui/p/p1/proposals/{proposal}/decide", listed)
        path = f"/ui/p/p1/proposals/{proposal}/decide"
        form = {"action": "publish", "reason": "reviewed"}
        self.assertIn("requires a human", self.post(path, {**form, "key": self.keys["worker"]}))
        # boss maintains p1 but not the library.
        self.assertIn("maintainer authority", self.post(path, {**form, "key": self.keys["boss"]}))
        self.assertIn(
            "done: tshoot_publication_decide as lead",
            self.post(path, {**form, "key": self.keys["lead"]}),
        )
        dest = self.s.read(lambda db: db.execute("SELECT dest_id FROM publications").fetchone()[0])
        self.assertIn("sanitized socket fix", self.get(f"/ui/p/lib/r/{dest}"))
        w.revoke_memory("worker", self.shared)  # withdraws the publication
        self.assertIn("No such project-visible record", self.get(f"/ui/p/lib/r/{dest}"))

    def test_auth_mode_needs_a_human_key_and_honours_revocation(self):
        class Plain(http.cookiejar.DefaultCookiePolicy):  # the test server is plain HTTP
            def return_ok_secure(self, cookie, request):
                return True

        cookies = http.cookiejar.CookieJar(Plain())
        jar = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))

        def fetch(path, form=None, origin=None):
            data = urllib.parse.urlencode(form).encode() if form is not None else None
            headers = {"Origin": origin} if origin else {}
            with jar.open(urllib.request.Request(self.base + path, data, headers)) as response:
                return response.read().decode()

        with patch.dict(os.environ, {"HUB_UI": "auth"}):
            self.assertIn("Sign in", fetch("/ui"))  # redirected to the login page
            self.assertIn("refused", fetch("/ui/login", {"key": self.keys["worker"]}))  # agent
            self.assertIn("refused", fetch("/ui/login", {"key": "nope"}))
            self.assertIn(
                "refused", fetch("/ui/login", {"key": self.keys["boss"]}, "http://evil.example")
            )
            self.assertIn("Sign in", fetch("/ui/p/p1"))
            self.assertIn("p1", fetch("/ui/login", {"key": self.keys["boss"]}))  # lands on /ui
            self.assertIn("visible workflow goal", fetch("/ui/p/p1"))
            identity.revoke_key(self.s, "root", self.keys["boss"].split("_")[1])
            self.assertIn("Sign in", fetch("/ui/p/p1"))
            self.assertIn("Sign in", fetch("/ui/logout"))
        self.assertIn("p1", self.get("/ui"))  # HUB_UI=1 stays open


if __name__ == "__main__":
    unittest.main()

    def test_review_inbox_form_and_bulk_preview(self):
        identity.grant(self.s, "root", "lead", "p1", "contributor")
        opener = urllib.request.build_opener()
        opener.addheaders = [("Cookie", f"{ui.COOKIE}={self.keys['lead']}")]
        with opener.open(self.base + "/ui/p/p1/review") as response:
            text = response.read().decode()
        self.assertIn("shared socket fix", text)
        with opener.open(self.base + f"/ui/p/p1/review/{self.shared}") as response:
            text = response.read().decode()
        self.assertIn("Confirm with evidence", text)
        form = dict(action="historical", expected_revision="1", idempotency_key="ui-review-test")
        req = urllib.request.Request(
            self.base + f"/ui/p/p1/review/{self.shared}",
            urllib.parse.urlencode(form).encode(),
            method="POST",
        )
        with opener.open(req) as response:
            self.assertIn("Applied", response.read().decode())
        self.assertEqual(Work(self.s, "p1").record("lead", self.shared)["freshness"], "historical")
        form = dict(action="historical", selected=self.private + ":1", temporal_kind="durable")
        req = urllib.request.Request(
            self.base + "/ui/p/p1/review/bulk", urllib.parse.urlencode(form).encode(), method="POST"
        )
        with opener.open(req) as response:
            self.assertIn("Apply previewed changes", response.read().decode())
        self.assertEqual(
            Work(self.s, "p1").record("lead", self.private)["freshness"], "freshness unknown"
        )
