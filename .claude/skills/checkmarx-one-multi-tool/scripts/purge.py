"""
Tenant teardown for Checkmarx One.

Deletes resources in dependency order: projects -> applications -> groups
(optionally users). Irreversible — always dry-run, show the concrete plan, and
require explicit confirmation before a real run.

SCOPING (v3): by default, purge deletes ONLY resources this tool created —
projects carrying the tool origin or the `cxone-multitool` marker tag,
applications with the marker tag, and Keycloak groups/users with the marker
attribute. `--all` restores the old delete-everything behavior for full tenant
resets (including tenants built by pre-3.0 versions, whose resources are
unstamped). In BOTH modes the user account behind the configured API key is
never deleted: purging your own credentials mid-purge strands the run and locks
you out of the tenant.
"""

from __future__ import annotations

import sys
import time
import logging
import argparse

from cxone import CxConfig, ApiClient, TOOL_MARKER
from config_setup import decode_jwt_payload
from iam import IamManager
from applications import ApplicationManager
from onboard import OnboardManager, DEFAULT_ORIGIN

logger = logging.getLogger("cxone.purge")

MAX_RETRIES = 3
RETRY_DELAY = 2.0


def _has_marker_tag(resource: dict) -> bool:
    tags = resource.get("tags") or {}
    if isinstance(tags, dict):
        return TOOL_MARKER in tags
    if isinstance(tags, list):  # some list endpoints return [{key,value}] shapes
        return any((t.get("key") if isinstance(t, dict) else t) == TOOL_MARKER
                   for t in tags)
    return False


def _has_marker_attr(resource: dict) -> bool:
    return TOOL_MARKER in (resource.get("attributes") or {})


class TenantPurger:
    def __init__(self, api: ApiClient, scope_all: bool = False):
        self.api = api
        self.cfg = api.config
        self.scope_all = scope_all
        self.iam = IamManager(api)
        self.apps = ApplicationManager(api)
        self.onboard = OnboardManager(api, self.iam)

    # ------------------------------------------------------------- scoping
    def _protected_user_ids(self) -> set[str]:
        """User ids that are NEVER deleted, in either scope: the primary API
        key's user PLUS every user behind a registered secondary identity —
        purging a persona whose key is still in the pool would strand it."""
        ids: set[str] = set()
        try:
            sub = decode_jwt_payload(self.cfg.api_key).get("sub")
            if sub:
                ids.add(sub)
        except Exception:
            pass
        try:
            from cxone.identity_pool import IdentityPool
            ids |= IdentityPool(self.cfg).user_ids()
        except Exception as exc:
            logger.debug("Identity pool unavailable for purge protection: %s", exc)
        return ids

    def _is_mine_project(self, p: dict) -> bool:
        return p.get("origin") == DEFAULT_ORIGIN or _has_marker_tag(p)

    def collect(self, include_users: bool = False) -> dict[str, list[dict]]:
        """Resolve the CONCRETE deletion set under the active scope. plan() and
        purge() both use this, so the confirmed counts are exactly what deletes.
        Keycloak group/user list items can omit `attributes`; when scoping, we
        fetch the full record before deciding (reads only)."""
        projects = self.onboard.list_projects()
        apps = self.apps.list_applications()
        groups = self.iam.list_groups()
        users = (self.api.get("users", params={"max": 1000}, use_iam=True) or []) \
            if include_users else []

        if not self.scope_all:
            projects = [p for p in projects if self._is_mine_project(p)]
            apps = [a for a in apps if _has_marker_tag(a)]
            groups = [g for g in groups if _has_marker_attr(
                g if "attributes" in g
                else (self.api.get(f"groups/{g['id']}", use_iam=True) or g))]
            users = [u for u in users if _has_marker_attr(
                u if "attributes" in u
                else (self.api.get(f"users/{u['id']}", use_iam=True) or u))]

        protected_ids = self._protected_user_ids()
        protected = [u for u in users if u.get("id") in protected_ids]
        if protected:
            logger.info("Protecting %d identity-linked user account(s) — never "
                        "deleted: %s", len(protected),
                        ", ".join(u.get("username", u.get("id", "?")) for u in protected))
            users = [u for u in users if u.get("id") not in protected_ids]
        return {"projects": projects, "applications": apps,
                "groups": groups, "users": users}

    def plan(self, include_users: bool = False) -> dict[str, int]:
        return {k: len(v) for k, v in self.collect(include_users).items()
                if k != "users" or include_users}

    # ------------------------------------------------------------- deletion
    def _delete_with_retry(self, endpoint: str, use_iam: bool, label: str) -> bool:
        for attempt in range(MAX_RETRIES):
            try:
                self.api.delete(endpoint, use_iam=use_iam)
                return True
            except Exception as exc:
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY * (attempt + 1))
                else:
                    logger.warning("Failed to delete %s: %s", label, exc)
                    return False
        return False

    def purge(self, include_users: bool = False) -> None:
        scope = "ALL tenant resources" if self.scope_all else \
            f"tool-created resources only (origin/{TOOL_MARKER} marker)"
        sets = self.collect(include_users)
        counts = {k: len(v) for k, v in sets.items()}
        logger.info("Purge plan [%s]: %s", scope, counts)
        if self.cfg.dry_run:
            for kind in ("projects", "applications", "groups", "users"):
                for r in sets[kind]:
                    logger.info("[dry-run] would delete %s '%s'",
                                kind[:-1], r.get("name") or r.get("username"))
            logger.info("[dry-run] no deletions performed")
            return

        logger.info("Deleting projects...")
        for p in sets["projects"]:
            self._delete_with_retry(f"projects/{p['id']}", False, f"project {p.get('name')}")
            time.sleep(0.2)
        logger.info("Deleting applications...")
        for a in sets["applications"]:
            self._delete_with_retry(f"applications/{a['id']}", False, f"application {a.get('name')}")
            time.sleep(0.2)
        logger.info("Deleting groups...")
        for g in sets["groups"]:
            self._delete_with_retry(f"groups/{g['id']}", True, f"group {g.get('name')}")
            time.sleep(0.2)
        if include_users:
            logger.info("Deleting users...")
            for u in sets["users"]:
                self._delete_with_retry(f"users/{u['id']}", True, f"user {u.get('username')}")
                time.sleep(0.2)
        logger.info("Purge complete.")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="purge", description="Tear down a CxOne tenant")
    p.add_argument("--env", default=None); p.add_argument("--dry-run", action="store_true")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--all", action="store_true",
                   help="delete EVERYTHING in the tenant, not just tool-created "
                        "resources (needed to reset tenants built by pre-3.0 "
                        "versions, whose resources carry no marker)")
    p.add_argument("--include-users", action="store_true")
    p.add_argument("--yes", action="store_true", help="skip interactive confirmation")
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = CxConfig.from_env(args.env)
    cfg.dry_run = cfg.dry_run or args.dry_run
    purger = TenantPurger(ApiClient(cfg), scope_all=args.all)

    if not cfg.dry_run and not args.yes:
        # Same contract as `env init`: a non-TTY cannot confirm interactively and
        # must refuse (previously this hit input() and crashed with EOFError).
        # Checked before plan() so refusal doesn't cost pointless API calls.
        if not sys.stdin.isatty():
            print("Refused: purge requires confirmation, but this shell is "
                  "non-interactive.\nDry-run first, list the deletions to the "
                  "user, get an explicit yes, then re-run with --yes.")
            return 2
        counts = purger.plan(args.include_users)
        scope = "ALL tenant resources" if args.all else "tool-created resources only"
        print(f"About to PERMANENTLY delete from tenant '{cfg.tenant_name}' "
              f"[{scope}]: {counts}")
        if input("Type the tenant name to confirm: ").strip() != cfg.tenant_name:
            print("Confirmation failed; aborting.")
            return 1
    purger.purge(include_users=args.include_users)
    return 0


if __name__ == "__main__":
    sys.exit(main())
