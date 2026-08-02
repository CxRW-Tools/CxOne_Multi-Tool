"""
Scan configuration for Checkmarx One projects (AST plane).

Reads/sets project-level scan settings via /api/configuration/project. The keys
that matter most for demos are the SAST preset and incremental flag; the engine
list is controlled at scan time (see scans.py).

  scan.config.sast.presetName   e.g. "ASA Premium", "Checkmarx Default"
  scan.config.sast.incremental  "true" / "false"
"""

from __future__ import annotations

import sys
import logging
import argparse

from cxone import CxConfig, ApiClient

logger = logging.getLogger("cxone.scanconfig")

PRESET_KEY = "scan.config.sast.presetName"
INCREMENTAL_KEY = "scan.config.sast.incremental"


class ScanConfigManager:
    def __init__(self, api: ApiClient):
        self.api = api
        self.cfg = api.config

    def get(self, project_id: str) -> dict:
        raw = self.api.get_project_configuration(project_id)
        return {item.get("key"): item.get("value") for item in raw if isinstance(item, dict)}

    def set_preset(self, project_id: str, preset: str | None = None,
                   incremental: bool | None = None) -> None:
        raw = self.api.get_project_configuration(project_id)
        updates = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            key = item.get("key")
            if key == PRESET_KEY and preset is not None:
                up = dict(item); up["value"] = preset; up["originLevel"] = "Project"
                updates.append(up)
            elif key == INCREMENTAL_KEY and incremental is not None:
                up = dict(item); up["value"] = "true" if incremental else "false"
                up["originLevel"] = "Project"
                updates.append(up)
        if not updates:
            logger.info("Nothing to change for project %s", project_id)
            return
        if self.cfg.dry_run:
            logger.info("[dry-run] would PATCH config for %s: %s", project_id,
                        {u["key"]: u["value"] for u in updates})
            return
        self.api.patch_project_configuration(project_id, updates)
        logger.info("Updated scan config for %s: %s", project_id,
                    {u["key"]: u["value"] for u in updates})

    def apply(self, scan_config: dict, projects: list[dict]) -> None:
        """Apply blueprint scan_config.default to created projects.

        Manual entries carry `name`; SCM entries carry organization/repository
        and the import derives the project name — so try the plausible names
        ("Org/Repo", then bare "Repo") instead of a literal `name` lookup that
        SCM entries can never satisfy (they'd all skip with "Project 'None'
        not found", which is exactly what used to happen)."""
        default = (scan_config or {}).get("default", {})
        if not default:
            return
        preset = default.get("sast_preset")
        incremental = default.get("incremental")
        from onboard import OnboardManager
        om = OnboardManager(self.api)
        for p in projects:
            candidates = [p.get("name")]
            if p.get("repository"):
                org = p.get("organization")
                if org:
                    candidates.append(f"{org}/{p['repository']}")
                candidates.append(p["repository"])
            proj = None
            for c in candidates:
                if c:
                    proj = om.find(c)
                    if proj:
                        break
            if not proj:
                label = next((c for c in candidates if c), "?")
                logger.warning("Project '%s' not found; skipping scan config", label)
                continue
            self.set_preset(proj["id"], preset, incremental)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="scanconfig")
    p.add_argument("--env", default=None); p.add_argument("--dry-run", action="store_true")
    p.add_argument("--debug", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("get"); g.add_argument("project_id")
    s = sub.add_parser("set"); s.add_argument("project_id")
    s.add_argument("--preset", default=None)
    s.add_argument("--incremental", choices=["true", "false"], default=None)
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = CxConfig.from_env(args.env)
    cfg.dry_run = cfg.dry_run or args.dry_run
    mgr = ScanConfigManager(ApiClient(cfg))
    if args.cmd == "get":
        for k, v in mgr.get(args.project_id).items():
            print(f"{k} = {v}")
    elif args.cmd == "set":
        inc = None if args.incremental is None else args.incremental == "true"
        mgr.set_preset(args.project_id, args.preset, inc)
    return 0


if __name__ == "__main__":
    sys.exit(main())
