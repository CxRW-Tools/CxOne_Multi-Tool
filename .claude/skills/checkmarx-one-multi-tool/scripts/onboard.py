"""
Project and repository-onboarding operations for Checkmarx One (AST plane).

- Manual projects:  POST /api/projects
- GitHub onboarding: POST /api/repos-manager/scm-projects  (bulk, per-org, async)
- List/get/delete:  GET/DELETE /api/projects

GitHub import is asynchronous: the initiate call returns a processId and a status
URL embedded in its message; we poll that URL until currentPhase == DONE, then read
result.status (OK/PARTIAL/failed) with successful/failed project lists.

GitLab / Azure DevOps / Bitbucket follow the same shape with a different scm.type
and org identity. They are stubbed with the exact extension points documented; see
references/cxone-api.md and references/extending.md. Build the user's primary SCM
first and validate against a live tenant.
"""

from __future__ import annotations

import sys
import time
import json
import logging
import argparse
from collections import defaultdict

from cxone import CxConfig, ApiClient, TOOL_MARKER
from iam import IamManager

logger = logging.getLogger("cxone.onboard")

DEFAULT_ORIGIN = "Checkmarx One Multi-Tool"
SUPPORTED_SCM = {"github"}  # gitlab/azure/bitbucket: see extension points below


def _name_from_repo(repo_url: str) -> str:
    """Derive a project name from a repo URL's last path segment (sans .git)."""
    tail = (repo_url or "").rstrip("/").rsplit("/", 1)[-1]
    return tail[:-4] if tail.endswith(".git") else tail


def _parse_repo_spec(spec: str) -> dict:
    """Parse a 'name|url|branch' (or 'url', 'name|url') repo spec into a dict.
    Only the URL is required; name defaults to the repo's last path segment."""
    parts = [p.strip() for p in spec.split("|")]
    if len(parts) == 1:  # just a URL
        return {"name": _name_from_repo(parts[0]), "repo_url": parts[0]}
    out = {"name": parts[0], "repo_url": parts[1]}
    if len(parts) >= 3 and parts[2]:
        out["branch"] = parts[2]
    return out


class OnboardManager:
    def __init__(self, api: ApiClient, iam: IamManager | None = None):
        self.api = api
        self.cfg = api.config
        self.iam = iam or IamManager(api)

    # ------------------------------------------------------------- listing
    def list_projects(self) -> list[dict]:
        return self.api.paginate("projects", results_key="projects")

    def find(self, name: str) -> dict | None:
        for p in self.list_projects():
            if p.get("name") == name:
                return p
        return None

    def delete_project(self, name: str) -> None:
        p = self.find(name)
        if not p:
            logger.warning("Project '%s' not found", name)
            return
        if self.cfg.dry_run:
            logger.info("[dry-run] would delete project '%s' (%s)", name, p["id"])
            return
        self.api.delete(f"projects/{p['id']}")
        logger.info("Deleted project '%s'", name)

    # ------------------------------------------------------- orchestration
    def create_projects(self, projects: list[dict]) -> None:
        """Create a mixed list of manual and SCM projects (dicts from a blueprint)."""
        manual = [p for p in projects if p.get("type", "manual") == "manual"]
        scm = defaultdict(list)
        for p in projects:
            if p.get("type") == "scm":
                t = (p.get("scm_type") or "").lower()
                if t not in SUPPORTED_SCM:
                    logger.warning("SCM '%s' not implemented yet (project %s) — see "
                                   "references/extending.md. Skipping.", t, p.get("repository"))
                    continue
                scm[t].append(p)

        for p in manual:
            self.create_manual_project(p)
        if scm["github"]:
            self.onboard_github(scm["github"])

    # --------------------------------------------------- update a project
    def update_project(self, name: str, *, repo_url: str | None = None,
                       branch: str | None = None, add_group_names: list[str] | None = None,
                       add_tags: dict | list | None = None) -> bool:
        """Merge-update an existing project (PUT /projects/{id}).

        One place to attach a repo URL, grant group access, or add tags without
        clobbering the project's other fields. We GET the live project first and
        merge — groups and tags are *added* (union), never replaced — so this is
        safe to call repeatedly and to combine concerns.
        """
        p = self.find(name)
        if not p:
            logger.error("Project '%s' not found", name)
            return False
        pid = p["id"]
        # Authoritative current state (the list item may omit groups/tags)
        full = self.api.get(f"projects/{pid}") or p

        groups = list(full.get("groups", []) or [])
        granted = []
        for gname in (add_group_names or []):
            gid = self.iam.get_group_id(gname)
            if not gid:
                logger.warning("Group '%s' not found; skipping for project '%s'", gname, name)
                continue
            if gid not in groups:
                groups.append(gid)
                granted.append(gname)

        tags = dict(full.get("tags", {}) or {})
        new_tags = {t: "" for t in add_tags} if isinstance(add_tags, list) else dict(add_tags or {})
        added_tags = {k: v for k, v in new_tags.items() if k not in tags}
        tags.update(new_tags)

        body = {
            "name": full.get("name", name),
            "groups": groups,
            "tags": tags,
            "criticality": full.get("criticality", 3),
            "origin": full.get("origin", DEFAULT_ORIGIN),
        }
        if repo_url:
            body["repoUrl"] = repo_url
        if branch:
            body["mainBranch"] = branch
        elif full.get("mainBranch"):
            body["mainBranch"] = full["mainBranch"]

        changes = []
        if repo_url:
            changes.append(f"repoUrl={repo_url}")
        if branch:
            changes.append(f"branch={branch}")
        if granted:
            changes.append(f"+groups={','.join(granted)}")
        if added_tags:
            changes.append(f"+tags={','.join(added_tags)}")
        summary = ", ".join(changes) or "no change"

        if self.cfg.dry_run:
            logger.info("[dry-run] would update '%s' (%s): %s", name, pid, summary)
            return True
        self.api.put(f"projects/{pid}", body)
        logger.info("Updated '%s' (%s): %s", name, pid, summary)
        return True

    # --------------------------------------------------- attach repo URL
    def set_project_repo(self, name: str, repo_url: str, branch: str | None = None) -> bool:
        """Attach a clone URL + main branch so a manual project can be scanned via the
        git handler (public repos need no token). Thin wrapper over update_project."""
        return self.update_project(name, repo_url=repo_url, branch=branch)

    # ------------------------------------------------ one-shot provisioning
    def provision_project(self, name: str, *, repo_url: str | None = None,
                          branch: str | None = None, groups: list[str] | None = None,
                          tags: list | dict | None = None, criticality: int = 3,
                          preset: str | None = None, incremental: bool | None = None,
                          app_tag: str | None = None) -> str | None:
        """Create a manual project and, in the same call, attach its repo, grant
        group access, apply tags (incl. an application-association tag), and set the
        SAST preset / incremental flag.

        This collapses the create-manual -> set-repo -> authorize -> scanconfig
        sequence into one operation (one approval) and is the building block for the
        batch onboarding workflow. Returns the project id (None on dry-run/skip).
        """
        # Merge an application-association tag into the project's tags up front so
        # the project lands under the matching application immediately on create.
        tag_list: list[str] = []
        if isinstance(tags, dict):
            tag_list = list(tags.keys())
        elif isinstance(tags, list):
            tag_list = list(tags)
        if app_tag and app_tag not in tag_list:
            tag_list.append(app_tag)

        pid = self.create_manual_project({
            "name": name,
            "groups": groups or [],
            "tags": tag_list,
            "criticality": criticality,
        })

        # On a real run, resolve the id if the project already existed (create
        # returns None when it's a no-op) so repo/config steps still apply.
        if pid is None and not self.cfg.dry_run:
            existing = self.find(name)
            pid = existing.get("id") if existing else None

        if repo_url:
            if self.cfg.dry_run:
                # The project isn't actually created in dry-run, so don't route
                # through update_project (which would 'not found'-error); preview it.
                extra = f" (branch {branch})" if branch else ""
                logger.info("[dry-run] would attach repo to '%s': %s%s", name, repo_url, extra)
            else:
                self.update_project(name, repo_url=repo_url, branch=branch)

        if (preset is not None or incremental is not None):
            if self.cfg.dry_run:
                logger.info("[dry-run] would set scan config for '%s': preset=%s incremental=%s",
                            name, preset, incremental)
            elif pid:
                from scanconfig import ScanConfigManager
                ScanConfigManager(self.api).set_preset(pid, preset, incremental)
            else:
                logger.warning("Could not resolve project id for '%s'; skipped scan config.", name)
        return pid

    # ----------------------------------------------- batch onboarding (one call)
    def batch_onboard(self, repos: list[dict], *, groups: list[str] | None = None,
                      preset: str | None = None, incremental: bool | None = None,
                      app_tag: str | None = None, criticality: int = 3) -> list[str]:
        """Provision several repos as projects in a single operation (one approval),
        applying the same groups / preset / app tag to each. `repos` is a list of
        {name, repo_url, branch?} dicts. Returns the names successfully provisioned.

        This is the multi-repo counterpart to provision_project — it's what turns
        'onboard WebGoat, juice-shop and dvna' into one command instead of a dozen.
        """
        done: list[str] = []
        failed: list[str] = []
        for spec in repos:
            name = spec.get("name") or _name_from_repo(spec.get("repo_url", ""))
            if not name:
                logger.warning("Skipping repo with no resolvable name: %s", spec)
                continue
            try:
                pid = self.provision_project(
                    name,
                    repo_url=spec.get("repo_url"), branch=spec.get("branch"),
                    groups=groups, preset=spec.get("preset", preset),
                    incremental=incremental, app_tag=app_tag, criticality=criticality,
                )
            except Exception as exc:
                logger.error("Onboarding '%s' failed: %s", name, exc)
                failed.append(name)
                continue
            # Success = the project verifiably exists (created now or already
            # there and updated). In dry-run nothing is created, so the whole
            # plan counts as previewed. pid=None on a LIVE run means the id
            # never resolved — don't report that as provisioned.
            if self.cfg.dry_run or pid:
                done.append(name)
            else:
                logger.warning("Onboarding '%s': project id could not be resolved "
                               "after create; not counting as provisioned.", name)
                failed.append(name)
        if failed:
            logger.warning("Batch onboarding: %d of %d failed: %s",
                           len(failed), len(failed) + len(done), ", ".join(failed))
        return done

    # --------------------------------------------------------- manual
    def create_manual_project(self, project: dict) -> str | None:
        """POST /api/projects. `groups` are group NAMES, resolved to UUIDs."""
        name = project["name"]
        if self.find(name):
            logger.info("Project '%s' already exists", name)
            return None
        group_names = list(project.get("groups", []))
        group_ids = [gid for gid in (self.iam.get_group_id(g) for g in group_names) if gid]
        tags = project.get("tags", [])
        tags_dict = {t: "" for t in tags} if isinstance(tags, list) else dict(tags or {})
        tags_dict.setdefault(TOOL_MARKER, "")  # scoped-purge marker
        payload = {
            "name": name,
            "groups": group_ids,
            "origin": project.get("origin", DEFAULT_ORIGIN),
            "tags": tags_dict,
            "criticality": project.get("criticality", 3),
        }
        if self.cfg.dry_run:
            # In a blueprint dry-run the groups themselves haven't been created,
            # so their ids can't resolve yet. Preview by NAME and say so — an
            # empty `groups` list here would under-report what the live run does.
            preview = dict(payload)
            preview["groups"] = group_names
            unresolved = len(group_names) - len(group_ids)
            note = (f" ({unresolved} group id(s) not resolvable yet — resolved at "
                    "live run, after groups are created)") if unresolved else ""
            logger.info("[dry-run] would create manual project '%s': %s%s",
                        name, json.dumps(preview), note)
            return None
        resp = self.api.post("projects", payload)
        pid = resp.get("id") if isinstance(resp, dict) else None
        logger.info("Created manual project '%s' (%s)", name, pid)
        return pid

    # --------------------------------------------------------- GitHub
    def onboard_github(self, projects: list[dict]) -> None:
        token = next((p.get("token") for p in projects if p.get("token")), None) or self.cfg.github_token
        if not token:
            if self.cfg.dry_run:
                logger.info("[dry-run] no GitHub token set — preview only "
                            "(real run needs blueprint project.token or CXONE_GITHUB_TOKEN)")
                token = "<missing-token>"
            else:
                raise ValueError("GitHub token required (blueprint project.token or CXONE_GITHUB_TOKEN)")

        by_org = defaultdict(list)
        for p in projects:
            if not p.get("organization") or not p.get("repository"):
                raise ValueError(f"GitHub project needs organization and repository: {p}")
            by_org[p["organization"]].append(p)

        for i, (org, repos) in enumerate(by_org.items()):
            if i > 0:
                time.sleep(5)  # the import API can be slow between orgs
            group_names = {g for p in repos for g in p.get("groups", [])}
            gid_map = {g: self.iam.get_group_id(g) for g in group_names}

            project_configs = []
            for p in repos:
                tags = p.get("tags", [])
                tags_dict = {t: "" for t in tags} if isinstance(tags, list) else dict(tags or {})
                tags_dict.setdefault(TOOL_MARKER, "")  # scoped-purge marker
                project_configs.append({
                    "scmRepositoryUrl": f"https://github.com/{org}/{p['repository']}",
                    "protectedBranches": p.get("protected_branches", []),
                    "branchToScanUponCreation": p.get("main_branch"),
                    "customSettings": {
                        "webhookEnabled": True,
                        "decoratePullRequests": True,
                        "tags": tags_dict,
                        "groups": [gid_map[g] for g in p.get("groups", []) if gid_map.get(g)],
                    },
                })

            payload = {
                "scm": {"type": "github", "token": token},
                "organization": {"orgIdentity": org, "monitorForNewProjects": False},
                "defaultProjectSettings": {"webhookEnabled": True, "decoratePullRequests": True},
                "projects": project_configs,
                "scanProjectsAfterImport": False,
            }
            if self.cfg.dry_run:
                redacted = json.loads(json.dumps(payload))
                redacted["scm"]["token"] = "***"
                logger.info("[dry-run] would import %d repo(s) into org '%s': %s",
                            len(project_configs), org, json.dumps(redacted))
                continue

            resp = self.api.post("repos-manager/scm-projects", payload) or {}
            process_id = resp.get("processId")
            message = resp.get("message", "")
            # The status URL is scraped out of a human-readable `message` field
            # ("... GET <url>") — a heuristic, because the API returns it nowhere
            # structured. If the message format drifts, fail loudly with the raw
            # response so the new shape is visible, and note the import may still
            # be running server-side.
            if not process_id or "GET " not in message:
                logger.error(
                    "Unexpected import response for org '%s' (no processId or no "
                    "'GET <url>' in message) — the import may still have started "
                    "server-side; check the tenant. Raw response: %s", org, resp)
                continue
            status_url = message.split("GET ", 1)[-1].strip()
            if "/api/" in status_url:
                status_url = status_url.split("/api/", 1)[1]
            logger.info("GitHub import started for org '%s' (process %s)", org, process_id)
            self._poll_github(status_url, org)

    def _poll_github(self, status_url: str, org: str, timeout: int = 3600,
                     delay: float = 2.0) -> None:
        # Status-driven, like the report / SCA-export / scan-wait polls: return on
        # DONE (the result carries per-repo ok/failed) and bail on a FAILED phase.
        # `timeout` is a generous 60-min wall-clock backstop (consistent with those
        # other generation polls) that only guards the never-terminal case; the
        # adaptive backoff keeps early polling responsive without hammering the API.
        deadline = time.time() + timeout
        while time.time() < deadline:
            resp = self.api.get(status_url) or {}
            phase = (resp.get("currentPhase") or "").upper()
            pct = resp.get("percentage", 0)
            logger.debug("Import org '%s': phase=%s %s%%", org, phase, pct)
            if phase == "DONE":
                result = resp.get("result", {})
                status = (result.get("status") or "").upper()
                ok = result.get("successfulProjects", [])
                failed = result.get("failedProjects", [])
                logger.info("Import org '%s' %s: %d ok, %d failed", org, status, len(ok), len(failed))
                for f in failed:
                    repo = f.get("repoUrl", "?").rsplit("/", 1)[-1] if isinstance(f, dict) else f
                    err = f.get("error", "") if isinstance(f, dict) else ""
                    level = logger.info if "already" in err.lower() else logger.warning
                    level("  %s: %s", repo, err or "failed")
                return
            if phase in ("FAILED", "ERROR"):
                logger.warning("Import org '%s' failed: %s", org, resp.get("result") or resp)
                return
            time.sleep(delay)
            delay = min(delay * 1.5, 10.0)
        logger.warning("Import polling for org '%s' timed out after %ds", org, timeout)

    # ----------------------------------------------- SCM extension points
    def onboard_gitlab(self, projects: list[dict]) -> None:
        """TODO: GitLab. Same flow as GitHub with scm.type='gitlab' and group/subgroup
        identity. Validate identity fields against the live tenant / Stoplight."""
        raise NotImplementedError("GitLab onboarding not implemented — see references/extending.md")

    def onboard_azure(self, projects: list[dict]) -> None:
        """TODO: Azure DevOps. scm.type='azure'; org + project identity."""
        raise NotImplementedError("Azure DevOps onboarding not implemented — see references/extending.md")

    def onboard_bitbucket(self, projects: list[dict]) -> None:
        """TODO: Bitbucket. scm.type='bitbucket'; workspace/project identity."""
        raise NotImplementedError("Bitbucket onboarding not implemented — see references/extending.md")


def _selector_from(args):
    """Build an inventory Selector from the shared selector flags."""
    from ops.project_inventory import Selector
    return Selector(
        tags=list(getattr(args, "tag", []) or []),
        names=list(getattr(args, "name_filter", []) or []),
        exclude_names=list(getattr(args, "exclude_name", []) or []),
        owner=getattr(args, "owner", None),
        stale_days=getattr(args, "stale_days", None),
        no_scans=bool(getattr(args, "no_scans", False)),
        created_before=getattr(args, "created_before", None),
    )


# Columns that require an extra API call per project, or the tenant-wide audit
# sweep. Naming them keeps `project list` as cheap as it has always been unless
# the caller actually asked for something that costs more.
_SCAN_COLUMNS = {"last-scan", "scans", "stale"}
_CREATOR_COLUMNS = {"creator", "created"}


def _cmd_inventory(mgr, args) -> int:
    from ops import project_inventory as inv

    is_inventory = args.cmd == "inventory"
    default_cols = ("name,creator,last-scan,scans,tags" if is_inventory else "id,name")
    columns = [c.strip() for c in (args.columns or default_cols).split(",") if c.strip()]

    selector = _selector_from(args)
    wanted = set(columns)
    # Enrich only when a requested column or an active filter needs it.
    need_scans = bool(wanted & _SCAN_COLUMNS) or selector.no_scans \
        or selector.stale_days is not None
    need_creator = (bool(wanted & _CREATOR_COLUMNS) or bool(selector.owner)
                    or bool(selector.created_before))
    if getattr(args, "no_creator", False):
        need_creator = False
        columns = [c for c in columns if c not in _CREATOR_COLUMNS]

    builder = inv.InventoryBuilder(mgr.api)
    rows = builder.build(selector, enrich_scans=need_scans,
                         enrich_creator=need_creator)
    rows.sort(key=lambda r: (r.name or "").lower())

    if args.csv:
        n = inv.render_csv(rows, args.csv)
        print(f"CSV export: {n} row(s) written to {args.csv}")
        return 0
    if args.as_json:
        inv.render_json(rows)
        return 0
    if not rows:
        scope = selector.describe() if hasattr(selector, "describe") else ""
        print("No projects matched." + (f" ({scope})" if scope else ""))
        return 0
    inv.render_table(rows, columns)
    if is_inventory:
        proxies = sum(1 for r in rows if r.creator_source == "first-scan")
        print(f"\n{len(rows)} project(s).")
        if proxies:
            # Say it once, plainly: some of these creators are inferred.
            print(f"{proxies} creator(s) marked '(first scan)' are INFERRED from "
                  f"whoever ran the earliest scan — no create event survives the "
                  f"365-day audit window. Treat as a lead, not a record.")
    return 0


def _cmd_delete(mgr, args) -> int:
    """Delete by explicit name(s), or by selector.

    A selector-based delete resolves to a concrete list and shows it before
    acting, because "--tag tmp" is a claim about the tenant's current state, not
    a list the caller has actually read.
    """
    from ops import project_inventory as inv

    dry = bool(getattr(args, "sub_dry_run", False)) or mgr.cfg.dry_run
    names = list(args.name or [])
    selector = _selector_from(args)

    if not names and not selector.active:
        print("Nothing selected: pass project name(s) or a selector "
              "(--tag/--name-filter/--stale-days/--no-scans/--owner).")
        return 2

    targets: list[tuple[str, str]] = []          # (name, project_id)
    if names:
        for n in names:
            found = mgr.find(n)
            if not found:
                logger.warning("Project '%s' not found", n)
                continue
            targets.append((found.get("name") or n, found.get("id")))
    if selector.active:
        builder = inv.InventoryBuilder(mgr.api)
        need_scans = selector.no_scans or selector.stale_days is not None
        need_creator = bool(selector.owner or selector.created_before)
        for row in builder.build(selector, enrich_scans=need_scans,
                                 enrich_creator=need_creator):
            if row.project_id not in {t[1] for t in targets}:
                targets.append((row.name, row.project_id))

    if not targets:
        print("No projects matched — nothing to delete.")
        return 0

    print(f"{len(targets)} project(s) selected for deletion:")
    for name, pid in targets:
        print(f"  {name}  ({pid})")
    # This listing goes to STDOUT while progress below goes to the logger on
    # STDERR. Piped stdout is block-buffered and stderr is not, so without an
    # explicit flush the "Deleted ..." lines surface BEFORE the list of what is
    # being deleted — output that reads as if the tool acted before it decided.
    # Flush at every handoff between the two streams.
    sys.stdout.flush()

    if dry:
        print("\n[dry-run] nothing was deleted.")
        return 0

    # A selector can match more than the caller pictured; an explicit name list
    # cannot. So confirmation is required for selectors unless --yes is given.
    if selector.active and not args.yes:
        if not sys.stdin.isatty():
            print("\nRefusing a selector-based delete without confirmation. "
                  "Re-run with --dry-run to review, then --yes to proceed.")
            return 2
        sys.stdout.flush()
        reply = input(f"\nPermanently delete these {len(targets)} project(s) "
                      f"and all their scan history? [y/N] ").strip().lower()
        if reply not in ("y", "yes"):
            print("Aborted.")
            return 1

    deleted = 0
    for name, pid in targets:
        try:
            mgr.api.delete(f"projects/{pid}")
            logger.info("Deleted project '%s'", name)
            deleted += 1
        except Exception as exc:                                   # noqa: BLE001
            logger.error("Failed to delete '%s' (%s): %s", name, pid, exc)
    sys.stderr.flush()          # the summary must land after the per-item log
    print(f"\nDeleted {deleted} of {len(targets)} project(s).")
    sys.stdout.flush()
    return 0 if deleted == len(targets) else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="onboard")
    p.add_argument("--env", default=None); p.add_argument("--dry-run", action="store_true")
    p.add_argument("--debug", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    def _add_selector(sp):
        """Shared selector vocabulary, so `inventory` and `delete` agree on what
        a given set of flags means. Anything inventory lists, delete removes."""
        g = sp.add_argument_group("selection")
        g.add_argument("--tag", action="append", default=[], metavar="TAG",
                       help="tag filter: 'tmp' (key present) or 'Demo:T&R' "
                            "(key:value). Repeatable; a project matching ANY wins")
        g.add_argument("--name-filter", action="append", default=[], metavar="PATTERN",
                       dest="name_filter",
                       help="name substring, or glob if it contains * ? [ . Repeatable")
        g.add_argument("--exclude-name", action="append", default=[], metavar="PATTERN",
                       help="name pattern to exclude (wins over --name-filter)")
        g.add_argument("--owner", default=None, metavar="WHO",
                       help="creator username/email substring")
        g.add_argument("--stale-days", type=int, default=None, metavar="N",
                       help="only projects with no scan in the last N days "
                            "(never-scanned projects always qualify)")
        g.add_argument("--no-scans", action="store_true",
                       help="only projects that have never been scanned")
        g.add_argument("--created-before", default=None, metavar="YYYY-MM-DD",
                       help="only projects created before this date")

    ls = sub.add_parser("list", help="list projects, with optional filters and columns")
    _add_selector(ls)
    ls.add_argument("--columns", default=None,
                    help="comma-separated: id,name,tags,creator,created,last-scan,"
                         "scans,stale (default: id,name)")
    ls.add_argument("--json", action="store_true", dest="as_json")
    ls.add_argument("--csv", default=None, metavar="PATH")

    inv = sub.add_parser("inventory",
                         help="tenant hygiene: what is here that shouldn't be "
                              "(stale, untouched, scratch-tagged, by owner)")
    _add_selector(inv)
    inv.add_argument("--columns", default=None,
                     help="comma-separated columns (default: name,creator,"
                          "last-scan,scans,tags)")
    inv.add_argument("--json", action="store_true", dest="as_json")
    inv.add_argument("--csv", default=None, metavar="PATH")
    inv.add_argument("--no-creator", action="store_true",
                     help="skip creator attribution (faster; no audit sweep)")
    m = sub.add_parser("create-manual")
    m.add_argument("--name", required=True); m.add_argument("--groups", default="")
    m.add_argument("--tags", default=""); m.add_argument("--criticality", type=int, default=3)
    # One-shot: create + attach repo + authorize groups + tag + set scan config.
    c = sub.add_parser("create", help="create a project and attach repo/preset/groups in one step")
    c.add_argument("--name", required=True)
    c.add_argument("--repo-url", default=None)
    c.add_argument("--branch", default=None)
    c.add_argument("--groups", default="", help="comma-separated group names to authorize")
    c.add_argument("--tags", default="", help="comma-separated project tags")
    c.add_argument("--app-tag", default=None, help="application-association tag, e.g. app:goats")
    c.add_argument("--criticality", type=int, default=3)
    c.add_argument("--preset", default=None, help="SAST preset, e.g. 'ASA Premium'")
    c.add_argument("--incremental", choices=["true", "false"], default=None)
    # Batch: provision several repos (and optionally scan them) in one invocation.
    ob = sub.add_parser("onboard", help="batch-onboard multiple repos as projects in one call")
    ob.add_argument("--repo", action="append", default=[], dest="repos", required=True,
                    help="repeatable: 'Name|https://repo/url|branch' (name/branch optional)")
    ob.add_argument("--groups", default="", help="comma-separated group names to authorize on all")
    ob.add_argument("--app-tag", default=None, help="application-association tag for all, e.g. app:goats")
    ob.add_argument("--preset", default=None, help="SAST preset applied to all")
    ob.add_argument("--incremental", choices=["true", "false"], default=None)
    ob.add_argument("--criticality", type=int, default=3)
    ob.add_argument("--scan", action="store_true", help="trigger a scan on each after onboarding")
    g = sub.add_parser("github")
    g.add_argument("--org", required=True); g.add_argument("--repos", required=True,
                   help="comma-separated repo names")
    g.add_argument("--groups", default=""); g.add_argument("--branch", default=None)
    r = sub.add_parser("set-repo", help="attach a clone URL + branch to an existing project")
    r.add_argument("--name", required=True); r.add_argument("--repo-url", required=True)
    r.add_argument("--branch", default=None)
    az = sub.add_parser("authorize", help="grant a group (or groups) access to a project")
    az.add_argument("--name", required=True)
    az.add_argument("--groups", required=True, help="comma-separated group names")
    at = sub.add_parser("add-tags", help="add tag(s) to a project (key or key:value, comma-separated)")
    at.add_argument("--name", required=True)
    at.add_argument("--tags", required=True, help="comma-separated tag keys")
    d = sub.add_parser("delete", help="delete projects by name or selector")
    d.add_argument("name", nargs="*", help="project name(s); or use the selector flags")
    _add_selector(d)
    d.add_argument("--dry-run", action="store_true", dest="sub_dry_run",
                   help="list what would be deleted, change nothing. Also accepted "
                        "before the subcommand (`project --dry-run delete`)")
    d.add_argument("--yes", action="store_true",
                   help="skip the confirmation prompt (required for a selector-based "
                        "delete in a non-interactive shell)")
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = CxConfig.from_env(args.env)
    cfg.dry_run = cfg.dry_run or args.dry_run
    mgr = OnboardManager(ApiClient(cfg))
    if args.cmd in ("list", "inventory"):
        return _cmd_inventory(mgr, args)
    elif args.cmd == "create-manual":
        mgr.create_manual_project({
            "name": args.name,
            "groups": [g for g in args.groups.split(",") if g],
            "tags": [t for t in args.tags.split(",") if t],
            "criticality": args.criticality,
        })
    elif args.cmd == "create":
        inc = None if args.incremental is None else args.incremental == "true"
        mgr.provision_project(
            args.name,
            repo_url=args.repo_url, branch=args.branch,
            groups=[g.strip() for g in args.groups.split(",") if g.strip()],
            tags=[t.strip() for t in args.tags.split(",") if t.strip()],
            criticality=args.criticality,
            preset=args.preset, incremental=inc, app_tag=args.app_tag,
        )
    elif args.cmd == "onboard":
        inc = None if args.incremental is None else args.incremental == "true"
        specs = [_parse_repo_spec(s) for s in args.repos]
        names = mgr.batch_onboard(
            specs,
            groups=[g.strip() for g in args.groups.split(",") if g.strip()],
            preset=args.preset, incremental=inc, app_tag=args.app_tag,
            criticality=args.criticality,
        )
        if args.scan and names and not cfg.dry_run:
            from ops.run import run_scan
            logger.info("Triggering scans for %d onboarded project(s)...", len(names))
            run_scan(cfg, project_names=",".join(names))
        elif args.scan and cfg.dry_run:
            logger.info("[dry-run] would trigger scans for: %s", ", ".join(names))
    elif args.cmd == "github":
        mgr.onboard_github([
            {"type": "scm", "scm_type": "github", "organization": args.org,
             "repository": r.strip(), "main_branch": args.branch,
             "groups": [g for g in args.groups.split(",") if g]}
            for r in args.repos.split(",") if r.strip()
        ])
    elif args.cmd == "set-repo":
        ok = mgr.set_project_repo(args.name, args.repo_url, args.branch)
        return 0 if ok else 1
    elif args.cmd == "authorize":
        groups = [g.strip() for g in args.groups.split(",") if g.strip()]
        ok = mgr.update_project(args.name, add_group_names=groups)
        return 0 if ok else 1
    elif args.cmd == "add-tags":
        tags = [t.strip() for t in args.tags.split(",") if t.strip()]
        ok = mgr.update_project(args.name, add_tags=tags)
        return 0 if ok else 1
    elif args.cmd == "delete":
        return _cmd_delete(mgr, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
