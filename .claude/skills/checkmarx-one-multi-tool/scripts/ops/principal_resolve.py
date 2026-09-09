"""
Principal (user / group / role) UUID -> human-readable name.

Lifted out of `audit.py`, where it lived as a private class and was therefore
unreachable from any other verb. Anything that surfaces an actor id needs this:
project provenance, inventory, audit. Keeping it private meant the next caller
either shipped raw UUIDs or hand-built the IAM URL again — and hand-building it
is easy to get wrong, because the IAM base already carries the realm path. The
correct call is `users/<uuid>` with `use_iam=True`; prefixing it with
`iam/admin/realms/<tenant>/` duplicates the realm and 404s.

Resolution is a display nicety, never a hard dependency: a miss (deleted
principal, permission gap, offline) returns the raw UUID rather than raising, so
a lookup failure can never fail the query that needed the name.
"""

from __future__ import annotations

import re
import logging
from typing import Any

logger = logging.getLogger("cxone.principal")

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)

# Field names whose values are user ids, keyed by how the audit payload spells them.
_USER_KEYS = ("actionUserId", "userId")
_ROLE_KEYS = ("roleId", "assignedRoles", "unassignedRoles")


def is_uuid(value: Any) -> bool:
    return bool(value) and bool(_UUID_RE.match(str(value)))


class PrincipalResolver:
    """Best-effort UUID -> name, cached per instance."""

    def __init__(self, api):
        self.api = api
        self._cache: dict[str, str] = {}
        self._people: dict[str, dict] = {}
        self._groups_by_id: dict[str, str] | None = None

    # ------------------------------------------------------------------ users
    def user(self, uid: str) -> dict | None:
        """The raw IAM user record, or None. Cached (including negative hits)."""
        if uid in self._people:
            return self._people[uid] or None
        data = None
        try:
            data = self.api.get(f"users/{uid}", use_iam=True)
        except Exception as exc:                                  # noqa: BLE001
            logger.debug("user lookup failed for %s: %s", uid, exc)
        self._people[uid] = data or {}
        return data or None

    def full_name(self, uid: str, *, fallback: str | None = None) -> str:
        """"First Last" when both are known, else the username, else the UUID.

        Distinct from `resolve()`, which appends the username in parentheses for
        audit display. Callers building a table column want the bare name.
        """
        data = self.user(uid)
        if not data:
            return fallback or uid
        full = f"{data.get('firstName', '')} {data.get('lastName', '')}".strip()
        return full or data.get("username") or fallback or uid

    def by_username(self, username: str) -> str:
        """Resolve a login/email to "First Last"; echoes the input on a miss.

        Scan records identify the actor by username, audit records by UUID, so a
        view that joins the two needs both directions.
        """
        if not username:
            return username
        key = f"username:{username}"
        if key in self._cache:
            return self._cache[key]
        name = username
        try:
            hits = self.api.get("users", use_iam=True,
                                params={"username": username, "exact": "true"}) or []
            if isinstance(hits, dict):
                hits = hits.get("users") or []
            if hits:
                d = hits[0]
                full = f"{d.get('firstName', '')} {d.get('lastName', '')}".strip()
                name = full or d.get("username") or username
        except Exception as exc:                                  # noqa: BLE001
            logger.debug("username lookup failed for %s: %s", username, exc)
        self._cache[key] = name
        return name

    # ----------------------------------------------------------------- groups
    def _load_groups(self) -> dict[str, str]:
        if self._groups_by_id is None:
            try:
                groups = self.api.get("groups", use_iam=True) or []
            except Exception:                                     # noqa: BLE001
                groups = []
            self._groups_by_id = {g["id"]: g.get("name", g["id"])
                                  for g in groups if g.get("id")}
        return self._groups_by_id

    # ---------------------------------------------------------------- generic
    def resolve(self, uid: str, kind: str) -> str:
        """Audit-display form: "First Last (username)" for users, name otherwise."""
        if uid in self._cache:
            return self._cache[uid]
        name = uid
        try:
            if kind in _USER_KEYS:
                data = self.user(uid)
                if data:
                    full = f"{data.get('firstName', '')} {data.get('lastName', '')}".strip()
                    username = data.get("username", uid)
                    name = f"{full} ({username})" if full else username
            elif kind in _ROLE_KEYS:
                data = self.api.get(f"roles-by-id/{uid}", use_iam=True)
                if data:
                    name = data.get("name", uid)
            elif kind == "groupId":
                name = self._load_groups().get(uid, uid)
        except Exception as exc:                                  # noqa: BLE001
            logger.debug("UUID resolution failed for %s (%s): %s", uid, kind, exc)
        self._cache[uid] = name
        return name

    def resolve_in_place(self, obj: Any) -> None:
        """Rewrite every UUID-looking value in a nested structure, in place."""
        if isinstance(obj, dict):
            for key, value in list(obj.items()):
                if isinstance(value, (dict, list)):
                    self.resolve_in_place(value)
                elif isinstance(value, str) and is_uuid(value):
                    obj[key] = self.resolve(value, key)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if isinstance(item, (dict, list)):
                    self.resolve_in_place(item)
                elif is_uuid(item):
                    obj[i] = self.resolve(str(item), "roleId")
