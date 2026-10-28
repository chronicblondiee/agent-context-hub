"""Optional sequential Gitea-API checker. API only; no database or memory body access."""

import base64
import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

MAX_BYTES = 4 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(url, token, payload=None, timeout=10, key=None):
    headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
    if key:
        headers["Idempotency-Key"] = key
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode() if payload is not None else None, headers=headers
    )
    with urllib.request.build_opener(NoRedirect).open(req, timeout=timeout) as response:
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("response too large")
    return json.loads(data)


def source_fingerprint(source, config):
    endpoint = config[source["endpoint"]]
    origin = endpoint["url"].rstrip("/")
    parsed = urllib.parse.urlsplit(origin)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.netloc
        or parsed.username
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("invalid configured endpoint")
    token = Path(endpoint["token_file"]).read_text().strip()
    base = origin + "/api/v1/repos/" + source["repository"]
    quote = lambda s: urllib.parse.quote(s, safe="")  # noqa: E731
    if source["kind"] == "file":
        url = base + "/contents/" + quote(source["path"]) + "?ref=" + quote(source["ref"])
        result = request(url, token)
        data = base64.b64decode(result["content"], validate=False)
    else:
        route = "issues" if source["kind"] == "issue" else "pulls"
        result = request(base + "/" + route + "/" + str(source["number"]), token)
        # Activity timestamps, comment counts and unrelated commits are not claim evidence.
        fields = ("title", "body", "state", "labels", "milestone", "assignees")
        relevant = {k: result.get(k) for k in fields}
        relevant["labels"] = sorted(x["name"] for x in result.get("labels") or [])
        relevant["assignees"] = sorted(x["login"] for x in result.get("assignees") or [])
        milestone = result.get("milestone")
        relevant["milestone"] = (
            {k: milestone.get(k) for k in ("title", "state")} if milestone else None
        )
        if source["kind"] == "pull":
            relevant.update(
                merged=result.get("merged"),
                merge_commit_sha=result.get("merge_commit_sha"),
                head_sha=(result.get("head") or {}).get("sha"),
                base_ref=(result.get("base") or {}).get("ref"),
            )
        data = json.dumps(
            relevant, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    return hashlib.sha256(data).hexdigest()


def main():
    origin = os.environ["HUB_ENDPOINT"].rstrip("/")
    project = urllib.parse.quote(os.environ["HUB_PROJECT"], safe="")
    token = Path(os.environ["HUB_KEY_FILE"]).read_text().strip()
    config = json.loads(Path(os.environ["HUB_CHECK_CONFIG"]).read_text())

    def call(operation, arguments, key):
        return request(
            origin + "/v2/projects/" + project + "/work/" + operation, token, arguments, key=key
        )

    while True:
        try:
            claimed = call("source_check_claim", {}, str(uuid.uuid4()))
            job = claimed.get("job")
            if not job:
                time.sleep(5)
                continue
            args = dict(
                job_id=job["id"],
                generation=job["generation"],
                target_revision=job["target_revision"],
            )
            try:
                args["observed_fingerprint"] = source_fingerprint(job["source"], config)
            except urllib.error.HTTPError as error:
                args["failure"] = "overloaded" if error.code in (429, 503) else "unavailable"
                delay = error.headers.get("Retry-After", "")
                if delay.isdigit():
                    args["retry_after_seconds"] = min(86400, int(delay))
            except (TimeoutError, OSError):
                args["failure"] = "timeout"
            except (ValueError, KeyError, TypeError):
                args["failure"] = "invalid response"
            key = str(uuid.uuid4())
            for attempt in range(5):
                try:
                    call("source_check_complete", args, key)
                    break
                except urllib.error.HTTPError as error:
                    if error.code in (400, 403, 404, 409):
                        break
                    time.sleep(min(2**attempt, 8))
                except OSError:
                    time.sleep(min(2**attempt, 8))
        except (OSError, ValueError, KeyError):
            # Do not print credentials, URLs, response bodies or private source material.
            print("source checker unavailable; retrying", flush=True)
            time.sleep(15)


if __name__ == "__main__":
    main()
