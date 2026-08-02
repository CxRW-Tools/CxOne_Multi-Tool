"""
Application operations for Checkmarx One (AST plane).

Applications are logical groupings of projects, associated by tag rules:
a project tagged with a key the application rule matches is auto-included.
Endpoints: POST/GET/PATCH/DELETE /api/applications.
"""

from __future__ import annotations

import sys
import json
import logging
import argparse
from typing import Any

from cxone import CxConfig, ApiClient, TOOL_MARKER

logger = logging.getLogger("cxone.applications")


class ApplicationManager:
    def __init__(self, api: ApiClient):
        self.api = api
        self.cfg = api.config

    def list_applications(self) -> list[dict]:
        return self.api.paginate("applications", results_key="applications")

    def find(self, name: str) -> dict | None:
        for a in self.list_applications():
            if a.get("name") == name:
                return a
        return None

    def create_application(self, app: dict) -> str | None:
        """
        Create an application. `app` keys:
          name (str), description (str), criticality (int 1-5),
          project_tag (str)  -> becomes a project.tag.key.exists rule,
          rules (list[dict])  -> explicit rules (optional, overrides project_tag),
          tags (dict|list)    -> application tags.
        Idempotent on name.
        """
        name = app["name"]
        existing = self.find(name)
        if existing:
            logger.info("Application '%s' already exists (%s)", name, existing.get("id"))
            return existing.get("id")

        rules = app.get("rules")
        if not rules and app.get("project_tag"):
            rules = [{"type": "project.tag.key.exists", "value": app["project_tag"]}]
        tags = app.get("tags", {})
        if isinstance(tags, list):
            tags = {t: "" for t in tags}
        tags.setdefault(TOOL_MARKER, "")  # scoped-purge marker: "created by this tool"

        payload: dict[str, Any] = {
            "name": name,
            "description": app.get("description", ""),
            "criticality": app.get("criticality", 3),
            "rules": rules or [],
            "tags": tags,
        }
        if self.cfg.dry_run:
            logger.info("[dry-run] would create application '%s': %s", name, json.dumps(payload))
            return None
        resp = self.api.post("applications", payload)
        app_id = resp.get("id") if isinstance(resp, dict) else None
        logger.info("Created application '%s' (%s)", name, app_id)
        return app_id

    def delete_application(self, name: str) -> None:
        app = self.find(name)
        if not app:
            logger.warning("Application '%s' not found", name)
            return
        if self.cfg.dry_run:
            logger.info("[dry-run] would delete application '%s' (%s)", name, app["id"])
            return
        self.api.delete(f"applications/{app['id']}")
        logger.info("Deleted application '%s'", name)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="applications")
    p.add_argument("--env", default=None); p.add_argument("--dry-run", action="store_true")
    p.add_argument("--debug", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    c = sub.add_parser("create")
    c.add_argument("--name", required=True); c.add_argument("--description", default="")
    c.add_argument("--criticality", type=int, default=3)
    c.add_argument("--project-tag", default=None)
    d = sub.add_parser("delete"); d.add_argument("name")
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = CxConfig.from_env(args.env)
    cfg.dry_run = cfg.dry_run or args.dry_run
    mgr = ApplicationManager(ApiClient(cfg))
    if args.cmd == "list":
        for a in mgr.list_applications():
            print(f"{a.get('id')}  {a.get('name')}  crit={a.get('criticality')}")
    elif args.cmd == "create":
        mgr.create_application({"name": args.name, "description": args.description,
                                "criticality": args.criticality, "project_tag": args.project_tag})
    elif args.cmd == "delete":
        mgr.delete_application(args.name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
