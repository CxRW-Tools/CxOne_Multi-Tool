"""
Which branch's results are "the" results for a project?

"How many Critical findings do we have?" has more than one correct answer, and
the tool used to pick one silently. Live example that prompted this module
(CxSolutionEngineer/Totally_Secure, 2026-08-03):

    latest scan, any branch  (agent branch)   25 Critical, 18 To Verify
    latest scan on primary   (main)           21 Critical,  0 To Verify   <- the UI
    analytics / production branches            7 Critical,  7 To Verify   <- KPIs

The newest scan was on a throwaway ``cx-ai-agent-main-…`` branch, so anything
keyed off "latest scan" reported findings the UI does not show and a user
cannot reconcile.

**Checkmarx One's own rules**, which this mirrors:

* The **primary branch** configured on the project wins. With none set, the UI
  falls back to the branch of the most recent scan.
* **Analytics/report** views instead use *production branches*: the primary
  branch, plus branches flagged protected during integration setup, plus the
  conventional names (``main``, ``master``, ``dev``, ``develop``,
  ``development``, ``merge``).

Hence ``SCOPES`` below. The default is ``primary`` — UI parity — because that is
what someone means when they say "the UI shows X", and being checkable against
the UI is how the original bug was caught at all.

One live-verified subtlety worth keeping: ``project.mainBranch`` is set on only
a minority of projects (6 of 33 here), but
``GET repos-manager/protected-branches`` knew the default branch for 15 MORE of
them. Resolving primary from ``mainBranch`` alone would therefore fall through
to "latest scan" for projects whose real default branch is perfectly well known.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger("cxone.branch_scope")

SCOPES = ("primary", "production", "latest", "all")
DEFAULT_SCOPE = "primary"

# Checkmarx One's documented production-branch naming convention.
CONVENTIONAL_NAMES = ("main", "master", "dev", "develop", "development", "merge")

_PROTECTED_ENDPOINT = "repos-manager/protected-branches"


@dataclass
class BranchChoice:
    """The branch/scan a query resolved to, and why — so callers can say so."""

    project_id: str
    project_name: str
    scope: str
    branch: str | None = None          # None => "any branch" (latest/all)
    scan_id: str | None = None
    source: str = ""                   # how `branch` was decided
    skipped_scan: str | None = None    # newer scan excluded by this scope
    skipped_branch: str | None = None
    branches: list[str] = field(default_factory=list)   # 'all'/'production'

    def describe(self) -> str:
        where = self.branch or "any branch"
        base = f"{self.project_name} — branch '{where}'"
        if self.scan_id:
            base += f", scan {self.scan_id}"
        base += f"  [scope={self.scope}"
        if self.source:
            base += f" via {self.source}"
        return base + "]"

    def drift_note(self) -> str | None:
        """Why the newest scan isn't the one being reported, when that's so.

        Silence here is what made the original bug invisible: the numbers were
        simply wrong with nothing indicating a branch had been chosen at all.
        """
        if not self.skipped_scan:
            return None
        return (f"newest scan {self.skipped_scan} is on branch "
                f"'{self.skipped_branch}' (excluded by --scope {self.scope}); "
                f"reporting branch '{self.branch}' scan {self.scan_id}")


class BranchResolver:
    """Resolves a project to the branch(es) in scope. Caches per run."""

    def __init__(self, api):
        self.api = api
        self._protected: dict[str, list[dict]] = {}
        self._scans: dict[str, list[dict]] = {}

    # ------------------------------------------------------------- fetching
    def protected_branches(self, project_name: str) -> list[dict]:
        """``[{pattern, isDefaultBranch, tags}]`` for a project, or ``[]``.

        Keyed by project NAME: the endpoint takes ``cxProjectName`` and returns
        400 (not an empty list) when it is omitted. Projects with no SCM
        integration simply have none, which is not an error.
        """
        if project_name in self._protected:
            return self._protected[project_name]
        out: list[dict] = []
        try:
            resp = self.api.get(_PROTECTED_ENDPOINT,
                                params={"cxProjectName": project_name})
            if isinstance(resp, list):
                out = resp
        except Exception as exc:                              # noqa: BLE001
            logger.debug("protected-branches unavailable for %s: %s",
                         project_name, exc)
        self._protected[project_name] = out
        return out

    def _completed_scans(self, project_id: str) -> list[dict]:
        if project_id in self._scans:
            return self._scans[project_id]
        try:
            scans = self.api.paginate("scans", results_key="scans",
                                      params={"project-id": project_id,
                                              "statuses": "Completed"})
        except Exception as exc:                              # noqa: BLE001
            logger.debug("scan list failed for %s: %s", project_id, exc)
            scans = []
        self._scans[project_id] = scans
        return scans

    # ------------------------------------------------------------ resolving
    def primary_branch(self, project: dict) -> tuple[str | None, str]:
        """The project's primary branch and how it was determined.

        Order matches Checkmarx One: the configured primary branch first, then
        the protected branch marked as default, then any protected branch, then
        a conventional name seen in the project's scan history. Returns
        ``(None, 'latest-scan')`` when nothing is configured — the UI's own
        fallback.
        """
        if project.get("mainBranch"):
            return project["mainBranch"], "project primary branch"

        prot = self.protected_branches(project.get("name") or "")
        default = [b.get("pattern") for b in prot if b.get("isDefaultBranch")]
        if default and default[0]:
            return default[0], "protected default branch"
        plain = [b.get("pattern") for b in prot if b.get("pattern")]
        if plain:
            return plain[0], "protected branch"

        seen = {s.get("branch") for s in self._completed_scans(project.get("id") or "")}
        for name in CONVENTIONAL_NAMES:
            if name in seen:
                return name, "conventional branch name"
        return None, "latest-scan"

    def production_branches(self, project: dict) -> tuple[list[str], str]:
        """Every branch analytics would treat as production, for this project."""
        names: list[str] = []
        if project.get("mainBranch"):
            names.append(project["mainBranch"])
        for b in self.protected_branches(project.get("name") or ""):
            pat = b.get("pattern")
            # Wildcard protected patterns ('release/*') can't be matched against
            # a scan's branch by equality; skip rather than silently mis-scope.
            if pat and "*" not in pat and pat not in names:
                names.append(pat)
        seen = {s.get("branch") for s in self._completed_scans(project.get("id") or "")}
        for name in CONVENTIONAL_NAMES:
            if name in seen and name not in names:
                names.append(name)
        return names, "primary + protected + conventional"

    def resolve(self, project: dict, scope: str = DEFAULT_SCOPE,
                branch: str | None = None) -> BranchChoice:
        """Pick the scan to report for one project under ``scope``."""
        pid = project.get("id") or ""
        pname = project.get("name") or pid
        scans = self._completed_scans(pid)
        newest = scans[0] if scans else None
        choice = BranchChoice(project_id=pid, project_name=pname, scope=scope)

        if branch:
            choice.scope, choice.branch, choice.source = "branch", branch, "--branch"
            wanted = [s for s in scans if s.get("branch") == branch]
        elif scope == "latest":
            choice.source = "newest scan, any branch"
            wanted = scans
        elif scope == "all":
            choice.source = "every branch"
            choice.branches = sorted({s.get("branch") for s in scans if s.get("branch")})
            wanted = scans
        elif scope == "production":
            names, src = self.production_branches(project)
            choice.branches, choice.source = names, src
            wanted = [s for s in scans if s.get("branch") in names]
            if len(names) == 1:
                choice.branch = names[0]
        else:                                                  # primary
            name, src = self.primary_branch(project)
            choice.branch, choice.source = name, src
            wanted = [s for s in scans if s.get("branch") == name] if name else scans

        if wanted:
            top = wanted[0]
            choice.scan_id = top.get("id")
            if choice.branch is None and scope in ("latest", "primary", "production"):
                choice.branch = top.get("branch")
            if newest and top.get("id") != newest.get("id"):
                choice.skipped_scan = newest.get("id")
                choice.skipped_branch = newest.get("branch")
        return choice
