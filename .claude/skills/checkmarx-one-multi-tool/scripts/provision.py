"""
Apply a tenant blueprint: stand up groups, users, applications, projects, and
scan config in dependency order. Idempotent where the CxOne APIs allow.

All modules are present and wired. Scans and triage are intentionally NOT run by
the blueprint apply (they are separate verbs in the Multi-Tool); after applying a
blueprint, run `multitool.py scan` then `multitool.py triage` to populate and
realistically triage results.
"""

from __future__ import annotations

import sys
import logging
import argparse
from pathlib import Path

import yaml

from cxone import CxConfig, ApiClient
from iam import IamManager
from applications import ApplicationManager
from onboard import OnboardManager
from scanconfig import ScanConfigManager

logger = logging.getLogger("cxone.provision")


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def apply_blueprint(bp: dict, api: ApiClient) -> None:
    iam = IamManager(api)

    groups = bp.get("groups", [])
    logger.info("== Groups (%d) ==", len(groups))
    for name in groups:
        iam.create_group(name)

    users = bp.get("users", [])
    logger.info("== Users (%d) ==", len(users))
    for u in users:
        iam.create_user(
            username=u["username"], email=u["email"],
            first_name=u.get("first_name", ""), last_name=u.get("last_name", ""),
            password=u.get("password"), temporary_password=u.get("temporary_password", False),
            groups=u.get("groups", []), roles=u.get("roles", []),
        )

    apps = bp.get("applications", [])
    if apps:
        logger.info("== Applications (%d) ==", len(apps))
        mgr = ApplicationManager(api)
        for a in apps:
            mgr.create_application(a)

    projects = bp.get("projects", [])
    if projects:
        logger.info("== Projects / onboarding (%d) ==", len(projects))
        OnboardManager(api, iam).create_projects(projects)

    sc = bp.get("scan_config")
    if sc:
        logger.info("== Scan configuration ==")
        ScanConfigManager(api).apply(sc, projects)

    logger.info("Blueprint application complete%s.",
                " (dry-run)" if api.config.dry_run else "")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="provision", description="Apply a CxOne tenant blueprint")
    p.add_argument("--blueprint", required=True)
    p.add_argument("--env", default=None)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--debug", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if not Path(args.blueprint).is_file():
        logger.error("Blueprint not found: %s", args.blueprint)
        return 1

    cfg = CxConfig.from_env(args.env)
    cfg.dry_run = cfg.dry_run or args.dry_run
    cfg.debug = cfg.debug or args.debug

    bp = _load(args.blueprint)
    logger.info("Applying blueprint '%s' to tenant '%s'%s",
                bp.get("tenant", {}).get("name", "(unnamed)"),
                cfg.tenant_name, " [DRY-RUN]" if cfg.dry_run else "")
    apply_blueprint(bp, ApiClient(cfg))
    return 0


if __name__ == "__main__":
    sys.exit(main())
