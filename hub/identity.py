"""Principals, additive project grants and managed keys.

A key is `hub_<16 hex id>_<base64url secret>`. Only the SHA-256 of the 32 random secret bytes
is stored; the full key is returned once, by the call that issues it. Every request
re-authenticates against the database, so expiry and revocation apply on the next call.
"""

import base64
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass

from hub.store import Overloaded, now_us

SYSTEM = "_system"  # admin actions audit here; the ID rule below keeps it ungrantable
KINDS = ("human", "agent", "verifier", "connector")
ROLES = ("reader", "contributor", "maintainer", "verifier", "connector")
IDENT = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
KEY = re.compile(r"^hub_([0-9a-f]{16})_([A-Za-z0-9_-]{43})$")
DAY_US = 86_400_000_000
MAX_DAYS = 365
MAX_OVERLAP_S = 86_400
# ponytail: hourly last-use granularity keeps reads off the writer; finer needs an in-memory flush.
LAST_USE_US = 3_600_000_000
_UNUSED = hashlib.sha256(b"unused").hexdigest()


@dataclass(frozen=True)
class Principal:
    id: str
    kind: str
    service_admin: bool
    key_id: str
    grants: dict  # project_id -> frozenset of roles
    acts_for: str | None = None  # the human owner of an agent's memory

    def roles(self, project_id):
        return self.grants.get(project_id, frozenset())


def _digest(secret: bytes) -> str:
    return hashlib.sha256(secret).hexdigest()


def _ident(value, what):
    if not isinstance(value, str) or not IDENT.match(value):
        raise ValueError(f"invalid {what}: lowercase letters, digits and '-', at most 63")
    return value


def _issue(tx, principal_id, days):
    if not isinstance(days, int) or not 1 <= days <= MAX_DAYS:
        raise ValueError(f"key lifetime must be 1 to {MAX_DAYS} days")
    if not tx.execute("SELECT 1 FROM principals WHERE id = ?", [principal_id]).fetchone():
        raise ValueError("unknown principal")
    key_id, secret, now = secrets.token_hex(8), secrets.token_bytes(32), now_us()
    expires = now + days * DAY_US
    tx.execute(
        "INSERT INTO keys (id, principal_id, digest, created_us, expires_us) "
        "VALUES (?, ?, ?, ?, ?)",
        [key_id, principal_id, _digest(secret), now, expires],
    )
    tx.audit("key.issue", key_id, {"principal": principal_id, "expires_us": expires})
    token = base64.urlsafe_b64encode(secret).rstrip(b"=").decode()
    return {"id": key_id, "key": f"hub_{key_id}_{token}", "expires_us": expires}


def bootstrap(store, name):
    """First service administrator, once, from the offline operator container."""
    _ident(name, "principal")

    def job(tx):
        # Imported AIC agents may already exist; a service administrator may not.
        if tx.execute("SELECT 1 FROM principals WHERE service_admin = 1").fetchone():
            raise ValueError("already bootstrapped; administer through the API")
        tx.execute(
            "INSERT INTO principals (id, kind, service_admin, created_us) "
            "VALUES (?, 'human', 1, ?)",
            [name, now_us()],
        )
        tx.audit("bootstrap", name, {})
        return _issue(tx, name, 90)

    return store.mutate(SYSTEM, name, job)


def recover_admin(store, name):
    """Offline, audited recovery: a new key for an existing service administrator (after a
    restore revoked every key). Never creates an administrator."""

    def job(tx):
        row = tx.execute("SELECT service_admin FROM principals WHERE id = ?", [name]).fetchone()
        if not row or not row[0]:
            raise ValueError("not a service administrator")
        tx.audit("admin.recover", name, {})
        return _issue(tx, name, 90)

    return store.mutate(SYSTEM, name, job)


def create_project(store, actor, project_id, name):
    return store.create_project(_ident(project_id, "project"), name, actor)


def create_principal(store, actor, principal_id, kind, service_admin=False, acts_for=None):
    _ident(principal_id, "principal")
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {', '.join(KINDS)}")

    def job(tx):
        tx.execute(
            "INSERT INTO principals (id, kind, service_admin, created_us) VALUES (?, ?, ?, ?)",
            [principal_id, kind, int(bool(service_admin)), now_us()],
        )
        tx.audit("principal.create", principal_id, {"kind": kind, "admin": bool(service_admin)})
        if acts_for is not None:
            _bind(tx, principal_id, acts_for)
        return {
            "id": principal_id,
            "kind": kind,
            "service_admin": bool(service_admin),
            "acts_for": acts_for,
        }

    return store.mutate(SYSTEM, actor, job)


def _bind(tx, principal_id, human_id):
    kinds = dict(
        tx.execute(
            "SELECT id, kind FROM principals WHERE id IN (?, ?)", [principal_id, human_id]
        ).fetchall()
    )
    if kinds.get(principal_id) != "agent" or kinds.get(human_id) != "human":
        raise ValueError("only an agent principal can act for a human principal")
    tx.execute("UPDATE principals SET acts_for = ? WHERE id = ?", [human_id, principal_id])
    # Records the agent owned before any binding pass to its human; owned records stay put.
    moved = tx.execute(
        "UPDATE memory_records SET owner = ? WHERE owner = ?", [human_id, principal_id]
    ).rowcount
    tx.audit("principal.bind", principal_id, {"human": human_id, "records": moved})
    return {"id": principal_id, "acts_for": human_id, "records": moved}


def bind(store, actor, principal_id, human_id):
    """Make a human the owner of an agent's memory writes. Service administrators only."""
    return store.mutate(SYSTEM, actor, lambda tx: _bind(tx, principal_id, human_id))


def grant(store, actor, principal_id, project_id, role, revoke=False):
    if role not in ROLES:
        raise ValueError(f"role must be one of {', '.join(ROLES)}")
    _ident(project_id, "project")

    def job(tx):
        if revoke:
            tx.execute(
                "DELETE FROM grants WHERE principal_id = ? AND project_id = ? AND role = ?",
                [principal_id, project_id, role],
            )
            if role == "connector":
                tx.execute(
                    "UPDATE sources SET status='disabled' WHERE connector_id=? AND project_id=?",
                    [principal_id, project_id],
                )
        else:
            tx.execute(
                "INSERT INTO grants VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING",
                [principal_id, project_id, role, now_us()],
            )
        action = "grant.revoke" if revoke else "grant.add"
        tx.audit(action, principal_id, {"project": project_id, "role": role})
        return {
            "principal": principal_id,
            "project": project_id,
            "role": role,
            "granted": not revoke,
        }

    return store.mutate(SYSTEM, actor, job)


def issue_key(store, actor, principal_id, days=90):
    return store.mutate(SYSTEM, actor, lambda tx: _issue(tx, principal_id, days))


def _active_key(tx, key_id):
    row = tx.execute(
        "SELECT principal_id, expires_us FROM keys WHERE id = ? AND revoked_us IS NULL",
        [key_id],
    ).fetchone()
    if not row or row[1] <= now_us():
        raise ValueError("unknown, expired or revoked key")
    return row


def rotate_key(store, actor, key_id, overlap_s=0, days=90):
    """A replacement key; the old one lives at most overlap_s longer, never past its expiry."""
    if not isinstance(overlap_s, int) or not 0 <= overlap_s <= MAX_OVERLAP_S:
        raise ValueError(f"overlap must be 0 to {MAX_OVERLAP_S} seconds")

    def job(tx):
        principal_id, expires = _active_key(tx, key_id)
        new = _issue(tx, principal_id, days)
        old_expires = min(expires, now_us() + overlap_s * 1_000_000)
        tx.execute("UPDATE keys SET expires_us = ? WHERE id = ?", [old_expires, key_id])
        tx.audit("key.rotate", key_id, {"replacement": new["id"], "expires_us": old_expires})
        return {**new, "previous_expires_us": old_expires}

    return store.mutate(SYSTEM, actor, job)


def revoke_key(store, actor, key_id):
    def job(tx):
        principal_id, _ = _active_key(tx, key_id)
        tx.execute("UPDATE keys SET revoked_us = ? WHERE id = ?", [now_us(), key_id])
        remaining = tx.execute(
            "SELECT 1 FROM keys WHERE principal_id=? AND revoked_us IS NULL "
            "AND expires_us>? LIMIT 1",
            [principal_id, now_us()],
        ).fetchone()
        if not remaining:
            tx.execute("UPDATE sources SET status='error' WHERE connector_id=?", [principal_id])
        tx.audit("key.revoke", key_id, {})
        return {"id": key_id, "revoked": True}

    return store.mutate(SYSTEM, actor, job)


def authenticate(store, credential):
    """The principal for a presented key, or None. Never raises on malformed input."""
    match = KEY.match(credential or "")
    key_id, token = match.groups() if match else ("", "")

    def fn(con):
        row = con.execute(
            "SELECT k.principal_id, k.digest, k.expires_us, k.revoked_us, k.last_used_us, "
            "p.kind, p.service_admin, p.acts_for "
            "FROM keys k JOIN principals p ON p.id = k.principal_id WHERE k.id = ?",
            [key_id],
        ).fetchone()
        grants = {}
        if row:
            for project, role in con.execute(
                "SELECT project_id, role FROM grants WHERE principal_id = ?", [row[0]]
            ):
                grants.setdefault(project, set()).add(role)
        return row, grants

    row, grants = store.read(fn)
    try:
        secret = base64.urlsafe_b64decode(token + "=")
    except ValueError:
        secret = b""
    # 43 characters carry 2 spare bits; accept only the canonical spelling of each secret.
    if base64.urlsafe_b64encode(secret).rstrip(b"=").decode() != token:
        secret = b""
    # Compare even for unknown IDs so response timing does not reveal which IDs exist.
    valid = hmac.compare_digest(_digest(secret), row[1] if row else _UNUSED)
    now = now_us()
    if not (match and row and valid and row[3] is None and row[2] > now):
        return None
    if row[4] is None or now - row[4] > LAST_USE_US:

        def touch(tx):
            tx.execute("UPDATE keys SET last_used_us = ? WHERE id = ?", [now, key_id])
            tx.audit("key.use", key_id, {})

        try:
            store.mutate(SYSTEM, row[0], touch)
        except Overloaded:
            pass  # last-use metadata never blocks an authenticated request
    return Principal(
        id=row[0],
        kind=row[5],
        service_admin=bool(row[6]),
        key_id=key_id,
        grants={p: frozenset(r) for p, r in grants.items()},
        acts_for=row[7],
    )
