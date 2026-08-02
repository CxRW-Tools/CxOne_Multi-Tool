"""
Export a live Checkmarx One tenant's configuration to a blueprint YAML — the
inverse of `provision` (apply). The output is written in the exact schema
`provision --blueprint` consumes, so a captured tenant can be re-created on a
fresh one: groups, users (with group membership and roles), applications (with
tag rules), projects (manual and SCM), and scan config.

READ-ONLY: this module never mutates the tenant, so there is no dry-run mode.

Round-trip caveats (also stamped into the exported file's header):
  * Passwords are not retrievable from Keycloak — exported users get a
    CHANGE-ME placeholder that MUST be edited before applying.
  * The blueprint schema supports one scan_config.default; when projects
    disagree, the most common preset/incremental combo becomes the default and
    the outliers are listed in a comment (re-apply them with `scanconfig set`).
  * SCM entries currently apply for GitHub only; projects on other hosts (or
    with an unparseable repo URL) are exported as manual projects with their
    repo noted in a comment.
  * Applying SCM entries needs the matching SCM token in the environment.
"""

from __future__ import annotations

import sys
import logging
import argparse
from collections import Counter
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from cxone import CxConfig, ApiClient, TOOL_MARKER, get_version
from iam import IamManager
from applications import ApplicationManager
from onboard import OnboardManager, DEFAULT_ORIGIN
from scanconfig import ScanConfigManager, PRESET_KEY, INCREMENTAL_KEY

logger = logging.getLogger("cxone.export")

# Keycloak service accounts and similar plumbing users are not demo users.
_SKIP_USER_PREFIXES = ("service-account-",)


def _clean_tags(tags) -> dict:
    """Normalize tags to the blueprint's dict form, dropping the tool's own
    scoped-purge marker (apply re-stamps it; exporting it is noise)."""
    if isinstance(tags, list):
        tags = {t: "" for t in tags}
    return {k: v for k, v in (tags or {}).items() if k != TOOL_MARKER}


def _parse_repo_url(url: str) -> tuple[str, str, str] | None:
    """(scm_type, organization, repository) from a repo URL, or None.
    Only hosts the apply path supports get an SCM entry; everything else is
    exported as manual with the URL in a comment."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    segs = [s for s in (parts.path or "").split("/") if s]
    if host in ("github.com", "www.github.com") and len(segs) >= 2:
        repo = segs[1][:-4] if segs[1].endswith(".git") else segs[1]
        return "github", segs[0], repo
    return None


class TenantExporter:
    def __init__(self, api: ApiClient, only_mine: bool = False,
                 include_scan_config: bool = True):
        self.api = api
        self.cfg = api.config
        self.only_mine = only_mine
        self.include_scan_config = include_scan_config
        self.iam = IamManager(api)
        self.apps = ApplicationManager(api)
        self.onboard = OnboardManager(api, self.iam)
        self.scanconf = ScanConfigManager(api)
        # Notes accumulated during export; emitted as comments in the header so
        # nothing lossy happens silently.
        self.notes: list[str] = []

    # ---------------------------------------------------------------- scoping
    def _has_marker_tag(self, resource: dict) -> bool:
        tags = resource.get("tags") or {}
        if isinstance(tags, dict):
            return TOOL_MARKER in tags
        if isinstance(tags, list):
            return any((t.get("key") if isinstance(t, dict) else t) == TOOL_MARKER
                       for t in tags)
        return False

    def _group_attrs(self, group: dict) -> dict:
        if "attributes" in group:
            return group.get("attributes") or {}
        full = self.api.get(f"groups/{group['id']}", use_iam=True) or {}
        return full.get("attributes") or {}

    # ---------------------------------------------------------------- pieces
    def export_groups(self) -> tuple[list[str], dict[str, str]]:
        """(group names, id->name map). Scoped by marker attribute when
        --only-mine (mirrors purge scoping)."""
        groups = self.iam.list_groups()
        id_to_name = {g["id"]: g.get("name") for g in groups if g.get("id")}
        if self.only_mine:
            groups = [g for g in groups if TOOL_MARKER in self._group_attrs(g)]
        return sorted(n for n in (g.get("name") for g in groups) if n), id_to_name

    def export_users(self) -> list[dict]:
        users = self.api.get("users", params={"max": 1000}, use_iam=True) or []
        out = []
        for u in users:
            username = u.get("username") or ""
            if not username or username.startswith(_SKIP_USER_PREFIXES):
                continue
            if self.only_mine and TOOL_MARKER not in (u.get("attributes") or {}):
                continue
            uid = u["id"]
            entry = {
                "username": username,
                "email": u.get("email", ""),
                "first_name": u.get("firstName", ""),
                "last_name": u.get("lastName", ""),
                # Keycloak never returns credentials; a blueprint without a
                # password would create sign-in-less users, so make the gap
                # impossible to miss rather than inventing a default.
                "password": "CHANGE-ME",
                "temporary_password": False,
                "groups": self.iam.list_user_groups(uid),
                "roles": self.iam.list_user_role_names(uid),
            }
            out.append(entry)
        if out:
            self.notes.append(
                "Passwords are NOT exportable — every user below has password: "
                "CHANGE-ME. Edit them before applying, or users can't sign in.")
        return sorted(out, key=lambda e: e["username"])

    def export_applications(self) -> list[dict]:
        out = []
        for a in self.apps.list_applications():
            if self.only_mine and not self._has_marker_tag(a):
                continue
            entry: dict = {"name": a.get("name", "")}
            if a.get("description"):
                entry["description"] = a["description"]
            entry["criticality"] = a.get("criticality", 3)
            rules = a.get("rules") or []
            # Reverse the blueprint sugar: exactly one tag-key rule -> project_tag;
            # anything richer is exported as explicit rules, verbatim.
            if len(rules) == 1 and rules[0].get("type") == "project.tag.key.exists":
                entry["project_tag"] = rules[0].get("value")
            elif rules:
                entry["rules"] = [{"type": r.get("type"), "value": r.get("value")}
                                  for r in rules]
            tags = _clean_tags(a.get("tags"))
            if tags:
                entry["tags"] = tags
            out.append(entry)
        return sorted(out, key=lambda e: e["name"])

    def export_projects(self, projects_raw: list[dict],
                        id_to_group: dict[str, str]) -> list[dict]:
        out = []
        for p in projects_raw:
            name = p.get("name", "")
            group_names = []
            for gid in p.get("groups") or []:
                gname = id_to_group.get(gid)
                if gname:
                    group_names.append(gname)
                else:
                    logger.warning("Project '%s': group id %s has no matching "
                                   "group; omitted from export.", name, gid)
            common: dict = {}
            if group_names:
                common["groups"] = sorted(group_names)
            common["criticality"] = p.get("criticality", 3)
            tags = _clean_tags(p.get("tags"))
            if tags:
                common["tags"] = tags

            repo_url = p.get("repoUrl") or ""
            parsed = _parse_repo_url(repo_url) if repo_url else None
            if parsed:
                scm_type, org, repo = parsed
                entry = {"type": "scm", "scm_type": scm_type, "organization": org,
                         "repository": repo}
                if p.get("mainBranch"):
                    entry["main_branch"] = p["mainBranch"]
                entry.update(common)
                # SCM onboarding derives the project name from the repo; if the
                # live name differs, record it so the operator knows the round
                # trip renames it.
                if name and name.split("/")[-1] != repo and name != repo:
                    self.notes.append(
                        f"Project '{name}' re-onboards from {org}/{repo}; the "
                        "SCM import derives its own project name.")
            else:
                entry = {"type": "manual", "name": name}
                entry.update(common)
                if repo_url:
                    self.notes.append(
                        f"Project '{name}' has repo {repo_url}, which the apply "
                        "path can't onboard (non-GitHub or unparseable) — "
                        "exported as manual; attach the repo with "
                        "`project update` after applying.")
            out.append(entry)
        return sorted(out, key=lambda e: (e["type"], e.get("name") or e.get("repository", "")))

    def export_scan_config(self, projects_raw: list[dict]) -> dict | None:
        """One scan_config.default for the blueprint: the modal
        (preset, incremental) combo across projects; outliers become notes."""
        if not self.include_scan_config or not projects_raw:
            return None
        combos: Counter = Counter()
        per_project: dict[str, tuple] = {}
        for p in projects_raw:
            try:
                conf = self.scanconf.get(p["id"])
            except Exception as exc:
                logger.warning("Could not read scan config for '%s': %s",
                               p.get("name"), exc)
                continue
            preset = conf.get(PRESET_KEY)
            inc_raw = conf.get(INCREMENTAL_KEY)
            inc = None if inc_raw is None else str(inc_raw).lower() == "true"
            if preset is None and inc is None:
                continue
            combo = (preset, inc)
            combos[combo] += 1
            per_project[p.get("name", p["id"])] = combo
        if not combos:
            return None
        (preset, inc), _count = combos.most_common(1)[0]
        default: dict = {}
        if preset is not None:
            default["sast_preset"] = preset
        if inc is not None:
            default["incremental"] = inc
        outliers = {n: c for n, c in per_project.items() if c != (preset, inc)}
        for n, (op, oi) in sorted(outliers.items()):
            self.notes.append(
                f"scan_config: '{n}' differs from the default "
                f"(preset={op!r}, incremental={oi}) — the blueprint schema has "
                "one default; re-apply per-project with `scanconfig set`.")
        return {"default": default} if default else None

    # ---------------------------------------------------------------- driver
    def export(self) -> tuple[dict, list[str]]:
        scope = "tool-created resources only" if self.only_mine else "all resources"
        logger.info("Exporting tenant '%s' (%s)...", self.cfg.tenant_name, scope)
        group_names, id_to_name = self.export_groups()
        users = self.export_users()
        applications = self.export_applications()
        # Projects are needed twice (blueprint entries + scan-config reads);
        # fetch and scope-filter ONCE, reuse everywhere.
        projects_raw = [
            p for p in self.onboard.list_projects()
            if not self.only_mine or p.get("origin") == DEFAULT_ORIGIN
            or self._has_marker_tag(p)
        ]
        projects = self.export_projects(projects_raw, id_to_name)
        scan_config = self.export_scan_config(projects_raw)

        bp: dict = {"tenant": {"name": self.cfg.tenant_name}}
        if group_names:
            bp["groups"] = group_names
        if users:
            bp["users"] = users
        if applications:
            bp["applications"] = applications
        if projects:
            bp["projects"] = projects
        if scan_config:
            bp["scan_config"] = scan_config
        logger.info("Exported: %d group(s), %d user(s), %d application(s), "
                    "%d project(s)%s.", len(group_names), len(users),
                    len(applications), len(projects),
                    ", scan_config" if scan_config else "")
        return bp, self.notes


def render_yaml(bp: dict, notes: list[str], cfg: CxConfig,
                only_mine: bool) -> str:
    header = [
        f"# Blueprint exported from tenant '{cfg.tenant_name}' "
        f"on {datetime.now().strftime('%Y-%m-%d %H:%M')} "
        f"by Checkmarx One Multi-Tool v{get_version()}",
        f"# Scope: {'tool-created resources only (--only-mine)' if only_mine else 'all tenant resources'}",
        "# Apply with:  python run.py provision --blueprint <this-file> --dry-run",
        "#",
        "# BEFORE APPLYING:",
    ]
    for n in notes or ["(no caveats recorded)"]:
        header.append(f"#  - {n}")
    body = yaml.safe_dump(bp, sort_keys=False, allow_unicode=True,
                          default_flow_style=False, width=100)
    return "\n".join(header) + "\n\n" + body


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="export",
        description="Export the live tenant's configuration to a blueprint YAML "
                    "(read-only; the inverse of `provision`)")
    p.add_argument("--env", default=None)
    p.add_argument("--out", default=None,
                   help="write to this file (default: print to stdout)")
    p.add_argument("--only-mine", action="store_true",
                   help="export only tool-created resources (same scoping as "
                        "the default purge)")
    p.add_argument("--no-scan-config", action="store_true",
                   help="skip per-project scan config reads (faster on big tenants)")
    p.add_argument("--debug", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
                        stream=sys.stderr)  # keep stdout clean for the YAML

    cfg = CxConfig.from_env(args.env)
    exporter = TenantExporter(ApiClient(cfg), only_mine=args.only_mine,
                              include_scan_config=not args.no_scan_config)
    bp, notes = exporter.export()
    text = render_yaml(bp, notes, cfg, args.only_mine)

    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        logger.info("Blueprint written to %s", out.resolve())
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
