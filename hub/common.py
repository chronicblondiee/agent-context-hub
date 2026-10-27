"""Small shared domain helpers."""

import uuid

from hub.store import encoded


def uid():
    return str(uuid.uuid4())


def bounded(value, name, maximum=2048):
    if len(encoded(value).encode()) > maximum:
        raise ValueError(f"{name} exceeds {maximum} bytes; use artifact references")
    return value


def references(evidence):
    return isinstance(evidence, list) and all(isinstance(e, str) and e.strip() for e in evidence)


class Stale(ValueError):
    """A fenced write from a superseded or expired session (HTTP 409)."""


class NotFound(ValueError):
    """A record ID is absent from the caller's granted project (HTTP 404)."""
