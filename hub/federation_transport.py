"""Optional JetStream pump. It uses authenticated hub APIs, never SQLite."""

import asyncio
import json
import os
import ssl
import urllib.error
import urllib.request

import nats
from nats.js.api import ConsumerConfig, DiscardPolicy, StorageType, StreamConfig
from nats.js.errors import NotFoundError

from hub.store import encoded


class HubError(RuntimeError):
    def __init__(self, status):
        super().__init__(f"hub HTTP {status}")
        self.status = status


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def api_request(base, key, method, path, body=None):
    request = urllib.request.Request(
        base.rstrip("/") + path,
        data=encoded(body).encode() if body is not None else None,
        method=method,
        headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"},
    )
    try:
        with _OPENER.open(request, timeout=10) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        # Never log payloads or error bodies: either may contain project memory.
        raise HubError(error.code) from None


async def _api(base, key, method, path, body=None):
    return await asyncio.to_thread(api_request, base, key, method, path, body)


async def _connect(config):
    servers = config["servers"]
    if (
        not isinstance(servers, list)
        or not servers
        or not all(
            isinstance(server, str)
            and (server == "nats://broker:4222" or server.startswith("tls://"))
            for server in servers
        )
    ):
        raise ValueError("NATS servers must use TLS outside the local broker")
    options = {
        "servers": servers,
        "connect_timeout": 3,
        "max_reconnect_attempts": 3,
    }
    if "user" in config and "password" in config:
        options["user"], options["password"] = config["user"], config["password"]
    elif os.environ.get("HUB_NATS_TEST_MODE") != "1":
        raise ValueError("NATS credentials required")
    if any(server.startswith("tls://") for server in servers):
        options["tls"] = ssl.create_default_context(cafile=config.get("ca_file"))
    return await nats.connect(**options)


async def pump_once(js, project, base, key, events, receipts):
    prefix = f"/v2/projects/{project}/federation"
    pending = await _api(base, key, "GET", prefix + "/outbox")
    for delivery in pending:
        event = delivery["event"]
        await js.publish(
            f"hub.{delivery['remote']}.incoming.{project}",
            encoded(event).encode(),
            headers={"Nats-Msg-Id": event["id"]},
        )
    for kind, consumer in (("incoming", events), ("receipts", receipts)):
        try:
            batch = await consumer.fetch(20, timeout=0.2)
        except TimeoutError:
            continue
        for message in batch:
            origin = message.subject.rsplit(".", 1)[-1]
            try:
                payload = json.loads(message.data)
                if kind == "incoming":
                    result = await _api(base, key, "POST", prefix + "/incoming/" + origin, payload)
                    await js.publish(
                        f"hub.{origin}.receipts.{project}",
                        encoded({"applied": result["applied"]}).encode(),
                    )
                else:
                    await _api(base, key, "POST", prefix + "/receipts/" + origin, payload)
                await message.ack_sync()
            except (ValueError, KeyError, HubError) as error:
                if isinstance(error, HubError) and error.status >= 500:
                    continue  # retry after core recovery
                await message.term()  # poisoned or unauthorized; do not retry forever


async def run(project, base, key, config):
    connection = await _connect(config)
    try:
        js = connection.jetstream()
        stream = "HUB_" + project.replace("-", "_").upper()
        try:
            await js.stream_info(stream)
        except NotFoundError:
            await js.add_stream(
                config=StreamConfig(
                    name=stream,
                    subjects=[f"hub.{project}.incoming.*", f"hub.{project}.receipts.*"],
                    storage=StorageType.FILE,
                    max_bytes=64 * 1024 * 1024,
                    discard=DiscardPolicy.NEW,
                )
            )
        events = await js.pull_subscribe(
            f"hub.{project}.incoming.*",
            durable="events-" + project,
            config=ConsumerConfig(ack_wait=30),
        )
        receipts = await js.pull_subscribe(
            f"hub.{project}.receipts.*",
            durable="receipts-" + project,
            config=ConsumerConfig(ack_wait=30),
        )
        while True:
            await pump_once(js, project, base, key, events, receipts)
            await asyncio.sleep(1)
    finally:
        await connection.close()


def main():
    project = os.environ["HUB_FEDERATION_PROJECT"]
    base = os.environ["HUB_URL"]
    with open(os.environ["HUB_KEY_FILE"]) as file:
        key = file.read().strip()
    with open(os.environ["HUB_NATS_CONFIG_FILE"]) as file:
        config = json.load(file)
    while True:
        try:
            asyncio.run(run(project, base, key, config))
        except (OSError, ValueError, HubError, TimeoutError, nats.errors.Error) as error:
            print(f"federation reconnecting: {type(error).__name__}", flush=True)
            import time

            time.sleep(2)


if __name__ == "__main__":
    main()
