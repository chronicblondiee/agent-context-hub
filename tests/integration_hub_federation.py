"""Real JetStream and HTTP exercise for the optional API-only transport."""

import asyncio
import os
import tempfile
import threading
import time

import uvicorn
from fastapi import FastAPI
from nats.js.api import ConsumerConfig, StreamConfig

from hub import api, federation, federation_transport, identity
from hub.store import Store, migrate
from hub.work import Work


def service(directory, project, remote):
    path = os.path.join(directory, project + ".sqlite3")
    migrate(path)
    store = Store(path)
    identity.create_project(store, "root", project, project)
    identity.create_principal(store, "root", "bridge", "connector")
    identity.grant(store, "root", "bridge", project, "connector")
    federation.peer(store, "root", project, remote, "bridge")
    bridge = identity.issue_key(store, "root", "bridge")["key"]
    app = FastAPI()
    app.state.store = store
    api.install(app)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="critical"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.01)
    port = server.servers[0].sockets[0].getsockname()[1]
    return store, bridge, f"http://127.0.0.1:{port}", server, thread


async def main():
    with tempfile.TemporaryDirectory() as directory:
        a = service(directory, "site-a", "site-b")
        b = service(directory, "site-b", "site-a")
        connection = None
        try:
            for _ in range(30):
                try:
                    connection = await federation_transport._connect(
                        {"servers": ["nats://broker:4222"]}
                    )
                    break
                except OSError:
                    await asyncio.sleep(0.2)
            assert connection is not None, "broker unavailable"
            js = connection.jetstream()
            consumers = {}
            for project in ("site-a", "site-b"):
                await js.add_stream(
                    config=StreamConfig(
                        name="HUB_" + project.replace("-", "_").upper(),
                        subjects=[f"hub.{project}.incoming.*", f"hub.{project}.receipts.*"],
                    )
                )
                incoming = await js.pull_subscribe(
                    f"hub.{project}.incoming.*",
                    durable="events-" + project,
                    config=ConsumerConfig(ack_wait=30),
                )
                receipts = await js.pull_subscribe(
                    f"hub.{project}.receipts.*",
                    durable="receipts-" + project,
                    config=ConsumerConfig(ack_wait=30),
                )
                consumers[project] = incoming, receipts

            ident = Work(a[0], "site-a").remember(
                "writer",
                "ops",
                "fact",
                "real nats repair",
                "tested",
                0.9,
                ["test:broker"],
            )["id"]
            federation.share(a[0], "site-a", "writer", ident, "site-b", "share-once")

            async def pump(project, instance):
                await federation_transport.pump_once(
                    js, project, instance[2], instance[1], *consumers[project]
                )

            await pump("site-a", a)
            await pump("site-b", b)
            await pump("site-a", a)
            received = federation._incoming_record_id("site-a", ident)
            assert Work(b[0], "site-b").record("reader", received)["body"] == "real nats repair"
            assert federation.outbox(a[0], "site-a", "bridge") == []

            Work(a[0], "site-a").revoke_memory("writer", ident)
            # A crash after the local write cannot lose the pending delivery.
            a[0].close()
            reopened = Store(os.path.join(directory, "site-a.sqlite3"))
            a[3].config.app.state.store = reopened
            a = reopened, a[1], a[2], a[3], a[4]
            assert len(federation.outbox(reopened, "site-a", "bridge")) == 1
            await pump("site-a", a)
            await pump("site-b", b)
            await pump("site-a", a)
            assert Work(b[0], "site-b").record("reader", received)["revoked"]
            assert federation.outbox(reopened, "site-a", "bridge") == []
            print("hub federation HTTP/JetStream: delivery, receipt, restore, revocation ok")
        finally:
            if connection:
                await connection.close()
            for instance in (a, b):
                instance[3].should_exit = True
                instance[4].join()
                instance[0].close()


if __name__ == "__main__":
    asyncio.run(main())
