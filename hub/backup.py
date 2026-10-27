"""Consistent backups, retention and restore (container-operations.md, Backup and recovery).

A backup is a directory: hub.sqlite3 (an SQLite online-backup copy of one read snapshot), every
artifact that snapshot references, and manifest.json with the schema, model and sha256 of every
file. The live core makes it through POST /v2/admin/backups; the operator makes the same backup
with the core stopped. Restore goes into an empty data directory and revokes every key, so an old
backup can never reactivate a key revoked after it was taken.
"""

import datetime
import hashlib
import json
import os
import shutil
import sqlite3
from pathlib import Path

from hub import embed, identity, store

DAILY, WEEKLY = 7, 4


def _sha256(path):
    with open(path, "rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def create(s, root, label=None):
    """Back up the store s into a new directory under root. Returns the manifest. A labelled
    backup (e.g. pre-upgrade) is kept until removed by hand; retention never prunes it."""
    root = Path(root)
    data = Path(s.path).parent
    stamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%S%fZ")
    final, tmp = root / stamp, root / f".{stamp}.tmp"
    tmp.mkdir(parents=True)
    try:

        def snapshot(con):
            # The copy and the artifact list come from the same read transaction.
            dest = sqlite3.connect(tmp / "hub.sqlite3")
            try:
                con.backup(dest)
            finally:
                dest.close()
            return con.execute(
                "SELECT project_id, owner, id, sha256 FROM artifacts ORDER BY 1, 2, 3"
            ).fetchall()

        artifacts = s.read(snapshot)
        check = sqlite3.connect(tmp / "hub.sqlite3")
        try:
            if check.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("backup copy failed its integrity check")
            schema = store.schema_version(check)
        finally:
            check.close()
        for project, owner, ident, digest in artifacts:
            rel = Path("artifacts", project, owner, ident)
            (tmp / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(data / rel, tmp / rel)
            if _sha256(tmp / rel) != digest:
                raise ValueError(f"artifact {project}/{owner}/{ident} does not match its hash")
        files = {str(p.relative_to(tmp)): _sha256(p) for p in sorted(tmp.rglob("*")) if p.is_file()}
        manifest = {
            "name": final.name,
            "label": label,
            "created_us": store.now_us(),
            "schema_version": schema,
            "model": embed.MODEL_KEY,
            "source_revision": os.environ.get("HUB_SOURCE_REVISION", "unknown"),
            "artifacts": len(artifacts),
            "files": files,
        }
        (tmp / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
        os.rename(tmp, final)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    return {"backup": final.name, **{k: v for k, v in manifest.items() if k != "files"}}


def _backups(root):
    out = []
    for d in Path(root).iterdir():
        try:
            manifest = json.loads((d / "manifest.json").read_text())
            created = manifest["created_us"]
        except (OSError, ValueError, KeyError):
            continue  # not a backup (an in-progress .tmp, or something else): never touched
        if not manifest.get("label"):
            out.append((created, d))
    return sorted(out, reverse=True)


def prune(root):
    """Keep the newest backup of each of the 7 newest days and of the 4 newest ISO weeks.
    Labelled backups are outside retention and always kept."""
    keep, days, weeks = set(), set(), set()
    for created, d in _backups(root):
        when = datetime.datetime.fromtimestamp(created / 1e6, datetime.UTC)
        day, week = when.date(), when.isocalendar()[:2]
        if day not in days and len(days) < DAILY:
            days.add(day)
            keep.add(d)
        if week not in weeks and len(weeks) < WEEKLY:
            weeks.add(week)
            keep.add(d)
        if d not in keep:
            shutil.rmtree(d)
    return sorted(d.name for d in keep)


def restore(backup, path):
    """Restore a verified backup into the empty data directory of database path, then revoke
    every key. Returns a summary; refuses a damaged, foreign-schema or non-empty target."""
    backup, data = Path(backup), Path(path).parent
    if Path(path).exists() or (data / "artifacts").exists():
        raise ValueError("restore needs an empty data directory")
    manifest = json.loads((backup / "manifest.json").read_text())
    present = {
        str(p.relative_to(backup))
        for p in backup.rglob("*")
        if p.is_file() and p.name != "manifest.json"
    }
    if present != set(manifest["files"]):
        raise ValueError("backup files do not match its manifest")
    for rel, digest in manifest["files"].items():
        if _sha256(backup / rel) != digest:
            raise ValueError(f"backup file {rel} does not match its hash")
    name = manifest.get("name", backup.name)  # the mount point is not the backup's name
    if manifest["schema_version"] != store.SCHEMA_VERSION:
        raise store.SchemaMismatch(
            f"backup schema {manifest['schema_version']}, code expects {store.SCHEMA_VERSION}"
        )
    shutil.copyfile(backup / "hub.sqlite3", path)
    if (backup / "artifacts").exists():
        shutil.copytree(backup / "artifacts", data / "artifacts")
    con = store.connect(path)
    try:
        ok = con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        version = store.schema_version(con)
    finally:
        con.close()
    if not ok or version != store.SCHEMA_VERSION:
        raise ValueError("restored database failed its integrity or schema check")
    s = store.Store(path)
    try:

        def revoke(tx):
            now = store.now_us()
            n = tx.execute(
                "UPDATE keys SET revoked_us = ? WHERE revoked_us IS NULL", [now]
            ).rowcount
            tx.audit("restore.revoke_keys", name, {"revoked": n})
            return n

        revoked = s.mutate(identity.SYSTEM, "operator", revoke)
    finally:
        s.close()
    return {"restored": name, "keys_revoked": revoked, "artifacts": manifest["artifacts"]}
