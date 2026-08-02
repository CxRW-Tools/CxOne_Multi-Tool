"""
IAM (Identity & Access Management) operations for Checkmarx One.

Checkmarx One's IAM is Keycloak. Everything here uses the Keycloak admin API
under  {iam}/auth/admin/realms/{tenant}/...  via ApiClient(use_iam=True).

Capabilities:
  Groups      list / get / create / delete            (ported from v1)
  Users       list / get / create / set-password /     (NET NEW — the real gap)
              delete
  Membership  add user to group / remove               (NET NEW)
  Roles       list realm roles / assign to user        (NET NEW)

Design notes for demo realism:
  - Created users get a temporary password and `emailVerified: true` so they
    can be handed out in a demo without an email round-trip.
  - Group membership is how Checkmarx One scopes project/application access, so
    in most demos you add users to groups rather than assigning roles directly.
  - All mutating calls honor cfg.dry_run: they log the intended action and the
    resolved payload, and make no API call.
"""

from __future__ import annotations

import sys
import json
import logging
import argparse
from typing import Any

from cxone import CxConfig, ApiClient, TOOL_MARKER

logger = logging.getLogger("cxone.iam")


class IamManager:
    def __init__(self, api: ApiClient):
        self.api = api
        self.cfg = api.config
        self._group_index: dict[str, str] | None = None  # name -> id
        self._ast_client_uuid_cache: str | None = None   # ast-app client UUID

    # ------------------------------------------------------------- groups
    def list_groups(self) -> list[dict]:
        return self.api.get("groups", use_iam=True) or []

    def _groups_by_name(self, refresh: bool = False) -> dict[str, str]:
        if self._group_index is None or refresh:
            self._group_index = {g["name"]: g["id"] for g in self.list_groups()}
        return self._group_index

    def get_group_id(self, name: str) -> str | None:
        return self._groups_by_name().get(name)

    def create_group(self, name: str) -> str | None:
        """POST /groups (Keycloak). Idempotent: returns existing id if present."""
        existing = self.get_group_id(name)
        if existing:
            logger.info("Group '%s' already exists (%s)", name, existing)
            return existing
        if self.cfg.dry_run:
            logger.info("[dry-run] would create group '%s'", name)
            return None
        self.api.post("groups",
                      {"name": name, "attributes": {TOOL_MARKER: ["true"]}},
                      use_iam=True)  # attribute = scoped-purge marker
        self._groups_by_name(refresh=True)
        gid = self.get_group_id(name)
        logger.info("Created group '%s' (%s)", name, gid)
        return gid

    def delete_group(self, name: str) -> None:
        gid = self.get_group_id(name)
        if not gid:
            logger.warning("Group '%s' not found; nothing to delete", name)
            return
        if self.cfg.dry_run:
            logger.info("[dry-run] would delete group '%s' (%s)", name, gid)
            return
        self.api.delete(f"groups/{gid}", use_iam=True)
        self._groups_by_name(refresh=True)
        logger.info("Deleted group '%s'", name)

    # -------------------------------------------------------------- users
    def find_user(self, username: str) -> dict | None:
        # Keycloak supports ?username=&exact=true
        results = self.api.get(
            "users", params={"username": username, "exact": "true"}, use_iam=True
        ) or []
        return results[0] if results else None

    def create_user(
        self,
        username: str,
        email: str,
        first_name: str = "",
        last_name: str = "",
        password: str | None = None,
        temporary_password: bool = False,
        groups: list[str] | None = None,
        roles: list[str] | None = None,
        enabled: bool = True,
    ) -> str | None:
        """
        Create a Keycloak user (POST /users) and optionally set a password, add to
        groups, and assign realm roles. Idempotent on username.

        `groups` is a list of group NAMES; they are resolved to ids and the user
        is added to each (creating membership). Groups must already exist.
        `roles` is a list of realm-role names (e.g. ast-scanner); without at least
        a viewer role a demo user can sign in but see nothing.
        """
        existing = self.find_user(username)
        created = existing is None
        if existing:
            logger.info("User '%s' already exists (%s)", username, existing.get("id"))
            uid = existing["id"]
        else:
            payload: dict[str, Any] = {
                "username": username,
                "email": email,
                "firstName": first_name,
                "lastName": last_name,
                "enabled": enabled,
                "emailVerified": True,
                # Scoped-purge marker: lets the default `purge` distinguish
                # tool-created demo users from real tenant users.
                "attributes": {TOOL_MARKER: ["true"]},
            }
            if self.cfg.dry_run:
                logger.info("[dry-run] would create user '%s': %s",
                            username, json.dumps(payload))
                if password:
                    logger.info("[dry-run] would set password for '%s' (temporary=%s)",
                                username, temporary_password)
                for g in groups or []:
                    logger.info("[dry-run] would add '%s' to group '%s'", username, g)
                for r in roles or []:
                    logger.info("[dry-run] would assign role '%s' to '%s'", r, username)
                return None
            resp = self.api.post("users", payload, use_iam=True)
            uid = _id_from_location(resp) or (self.find_user(username) or {}).get("id")
            logger.info("Created user '%s' (%s)", username, uid)

        # Group membership first: it's the access-control intent and must not be lost
        # if the (independent) password step fails. Password reset can 403 on tenants
        # where the API key lacks password-management or the realm uses SSO — that
        # shouldn't strand the user outside their groups.
        if uid and groups and not self.cfg.dry_run:
            for g in groups:
                self.add_user_to_group(uid, g)
        if uid and roles and not self.cfg.dry_run:
            for r in roles:
                self.assign_role(uid, r)
        # Password applies to NEWLY created users only. "Idempotent on username"
        # must not mean "re-running the create silently resets an existing user's
        # password" — that's a surprise mutation. To change an existing user's
        # password deliberately, use `iam set-password`.
        if uid and password and not created:
            logger.info("User '%s' already existed — NOT resetting their password. "
                        "Use `iam set-password --username %s` to change it "
                        "deliberately.", username, username)
        if uid and password and created and not self.cfg.dry_run:
            try:
                self.set_password(uid, password, temporary_password)
            except Exception as exc:
                # Silent by design: tenants commonly disable API password-set and
                # instead send the new user an email invite to set their own
                # password. The user and group/role membership are already created,
                # so this is a non-event — log at debug only.
                logger.debug("Password not set via API for '%s' (%s); user will set "
                             "it via email invite.", username, exc)
        return uid

    # Keycloak built-in realm roles that every user carries implicitly; excluded
    # from exports because re-assigning them is meaningless noise in a blueprint.
    _BUILTIN_REALM_ROLES = {"offline_access", "uma_authorization"}

    def list_user_groups(self, user_id: str) -> list[str]:
        """Group NAMES the user belongs to (GET /users/{id}/groups). Read-only."""
        groups = self.api.get(f"users/{user_id}/groups", use_iam=True) or []
        return [g.get("name") for g in groups if g.get("name")]

    def list_user_role_names(self, user_id: str) -> list[str]:
        """Effective assigned role names for a user: ast-app client roles first
        (the ones that grant CxOne access), then non-builtin realm roles.
        Read-only; mirrors what assign_role() would need to reproduce them."""
        names: list[str] = []
        cid = self._ast_client_uuid()
        if cid:
            client = self.api.get(f"users/{user_id}/role-mappings/clients/{cid}",
                                  use_iam=True) or []
            names += [r.get("name") for r in client if r.get("name")]
        realm = self.api.get(f"users/{user_id}/role-mappings/realm", use_iam=True) or []
        for r in realm:
            n = r.get("name")
            if n and n not in self._BUILTIN_REALM_ROLES \
                    and not n.startswith("default-roles-"):
                names.append(n)
        return names

    def set_password(self, user_id: str, password: str, temporary: bool = False) -> None:
        """PUT /users/{id}/reset-password."""
        if self.cfg.dry_run:
            logger.info("[dry-run] would set password for user %s", user_id)
            return
        self.api.put(
            f"users/{user_id}/reset-password",
            {"type": "password", "value": password, "temporary": temporary},
            use_iam=True,
        )
        logger.info("Set password for user %s (temporary=%s)", user_id, temporary)

    def delete_user(self, username: str) -> None:
        user = self.find_user(username)
        if not user:
            logger.warning("User '%s' not found; nothing to delete", username)
            return
        if self.cfg.dry_run:
            logger.info("[dry-run] would delete user '%s' (%s)", username, user["id"])
            return
        self.api.delete(f"users/{user['id']}", use_iam=True)
        logger.info("Deleted user '%s'", username)

    # ---------------------------------------------------------- membership
    def add_user_to_group(self, user_id: str, group_name: str) -> None:
        """PUT /users/{userId}/groups/{groupId}."""
        gid = self.get_group_id(group_name)
        if not gid:
            logger.warning("Group '%s' not found; cannot add membership", group_name)
            return
        if self.cfg.dry_run:
            logger.info("[dry-run] would add user %s to group '%s'", user_id, group_name)
            return
        self.api.put(f"users/{user_id}/groups/{gid}", {}, use_iam=True)
        logger.info("Added user %s to group '%s'", user_id, group_name)

    # --------------------------------------------------------------- roles
    def list_realm_roles(self) -> list[dict]:
        return self.api.get("roles", use_iam=True) or []

    def assign_realm_role(self, user_id: str, role_name: str) -> None:
        """POST /users/{id}/role-mappings/realm with [{id,name}]."""
        role = next((r for r in self.list_realm_roles() if r.get("name") == role_name), None)
        if not role:
            logger.warning("Realm role '%s' not found; skipping", role_name)
            return
        if self.cfg.dry_run:
            logger.info("[dry-run] would assign role '%s' to user %s", role_name, user_id)
            return
        self.api.post(
            f"users/{user_id}/role-mappings/realm",
            [{"id": role["id"], "name": role["name"]}],
            use_iam=True,
        )
        logger.info("Assigned realm role '%s' to user %s", role_name, user_id)

    # ----------------------------------------------------- client roles (AST)
    # The CxOne permissions that matter for demo personas — ast-viewer, ast-scanner,
    # ast-admin, view-scans, manage-application, … — are CLIENT roles under the
    # `ast-app` Keycloak client, NOT realm roles. We resolve that client once and
    # assign client roles by name, falling back to realm roles for IAM-level roles.
    AST_CLIENT_ID = "ast-app"

    def _ast_client_uuid(self) -> str | None:
        if getattr(self, "_ast_client_uuid_cache", None) is None:
            clients = self.api.get("clients", params={"clientId": self.AST_CLIENT_ID},
                                   use_iam=True) or []
            self._ast_client_uuid_cache = clients[0]["id"] if clients else ""
        return self._ast_client_uuid_cache or None

    def list_client_roles(self) -> list[dict]:
        cid = self._ast_client_uuid()
        if not cid:
            return []
        return self.api.get(f"clients/{cid}/roles", use_iam=True) or []

    def assign_client_role(self, user_id: str, role_name: str) -> bool:
        """POST /users/{id}/role-mappings/clients/{clientUuid}. Returns True if the
        role existed and was assigned, False if not found (so callers can fall back)."""
        cid = self._ast_client_uuid()
        if not cid:
            return False
        role = next((r for r in self.list_client_roles() if r.get("name") == role_name), None)
        if not role:
            return False
        if self.cfg.dry_run:
            logger.info("[dry-run] would assign client role '%s' to user %s", role_name, user_id)
            return True
        self.api.post(
            f"users/{user_id}/role-mappings/clients/{cid}",
            [{"id": role["id"], "name": role["name"]}],
            use_iam=True,
        )
        logger.info("Assigned %s client role '%s' to user %s",
                    self.AST_CLIENT_ID, role_name, user_id)
        return True

    def assign_role(self, user_id: str, role_name: str) -> None:
        """Assign a role by name, trying the ast-app client first (where the demo
        personas live) and falling back to realm roles for IAM-level role names."""
        if self.assign_client_role(user_id, role_name):
            return
        # Not an ast-app client role — try realm roles (e.g. manage-users, iam-admin).
        self.assign_realm_role(user_id, role_name)

    def assign_roles_to_user(self, username: str, role_names: list[str]) -> bool:
        """Resolve a username and assign each role (client role preferred, realm
        fallback). Returns False if the user isn't found."""
        user = self.find_user(username)
        if not user:
            logger.error("User '%s' not found", username)
            return False
        for r in role_names:
            self.assign_role(user["id"], r)
        return True


def _id_from_location(resp: Any) -> str | None:
    """Keycloak returns the new resource id as the last path segment of Location."""
    if isinstance(resp, dict):
        loc = resp.get("_location") or ""
        if loc:
            return loc.rstrip("/").rsplit("/", 1)[-1]
        if resp.get("id"):
            return resp["id"]
    return None


# --------------------------------------------------------------------- CLI
def _build_cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="iam", description="Checkmarx One IAM operations")
    p.add_argument("--env", default=None)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--debug", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list-groups")
    g = sub.add_parser("create-group"); g.add_argument("name")
    g = sub.add_parser("delete-group"); g.add_argument("name")
    sub.add_parser("list-users")

    u = sub.add_parser("create-user")
    u.add_argument("--username", required=True)
    u.add_argument("--email", required=True)
    u.add_argument("--first-name", default="")
    u.add_argument("--last-name", default="")
    u.add_argument("--password", default=None)
    u.add_argument("--temporary-password", action="store_true")
    u.add_argument("--groups", default="", help="comma-separated group names")
    u.add_argument("--roles", default="", help="comma-separated realm-role names "
                   "(e.g. ast-scanner,manage-reports)")

    sp = sub.add_parser("set-password", help="deliberately (re)set an existing user's password")
    sp.add_argument("--username", required=True)
    sp.add_argument("--password", required=True)
    sp.add_argument("--temporary", action="store_true",
                    help="force the user to change it at next login")

    u = sub.add_parser("delete-user"); u.add_argument("username")

    lr = sub.add_parser("list-roles", help="list assignable roles (ast-app client + realm)")
    lr.add_argument("--filter", default=None, help="substring filter on role name")
    ar = sub.add_parser("assign-role", help="assign role(s) to an existing user "
                        "(ast-app client role preferred, realm fallback)")
    ar.add_argument("--username", required=True)
    ar.add_argument("--roles", required=True,
                    help="comma-separated role names, e.g. ast-viewer,view-applications")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_cli().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    cfg = CxConfig.from_env(args.env)
    if args.dry_run:
        cfg.dry_run = True
    if args.debug:
        cfg.debug = True
    iam = IamManager(ApiClient(cfg))

    if args.cmd == "list-groups":
        for grp in iam.list_groups():
            print(f"{grp.get('id')}  {grp.get('name')}")
    elif args.cmd == "create-group":
        iam.create_group(args.name)
    elif args.cmd == "delete-group":
        iam.delete_group(args.name)
    elif args.cmd == "list-users":
        for usr in iam.api.get("users", params={"max": 1000}, use_iam=True) or []:
            print(f"{usr.get('id')}  {usr.get('username')}  {usr.get('email')}")
    elif args.cmd == "create-user":
        iam.create_user(
            username=args.username, email=args.email,
            first_name=args.first_name, last_name=args.last_name,
            password=args.password, temporary_password=args.temporary_password,
            groups=[g.strip() for g in args.groups.split(",") if g.strip()],
            roles=[r.strip() for r in args.roles.split(",") if r.strip()],
        )
    elif args.cmd == "set-password":
        user = iam.find_user(args.username)
        if not user:
            logger.error("User '%s' not found", args.username)
            return 1
        iam.set_password(user["id"], args.password, args.temporary)
    elif args.cmd == "delete-user":
        iam.delete_user(args.username)
    elif args.cmd == "list-roles":
        flt = (getattr(args, "filter", None) or "").lower()
        rows = [("ast-app", r) for r in iam.list_client_roles()]
        rows += [("realm", r) for r in iam.list_realm_roles()]
        for scope, role in sorted(rows, key=lambda x: (x[0], x[1].get("name", ""))):
            name = role.get("name", "")
            if flt and flt not in name.lower():
                continue
            desc = role.get("description") or ""
            print(f"[{scope}] {name}{'  — ' + desc if desc else ''}")
    elif args.cmd == "assign-role":
        ok = iam.assign_roles_to_user(
            args.username, [r.strip() for r in args.roles.split(",") if r.strip()])
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
