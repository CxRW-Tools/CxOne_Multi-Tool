"""
`project import-scm`: make a project an SCM (Code Repository) project, creating
it first when it doesn't exist.

The flow, for one repository:

1. If a project of that name exists and is already an SCM project (it has a
   `repoId`), stop: nothing to do.
2. If the repository is already onboarded under a DIFFERENT project, stop and say
   which one: the conversion would fail on it anyway.
3. Create a manual project when there isn't one (with groups and tags).
4. `POST /api/repos-manager/project-conversion` converts it to an SCM project.
5. Poll `GET /api/repos-manager/project-conversion?processId=...` until the
   conversion is no longer IN_PROGRESS.

The status route is `project-conversion?processId=`. A standalone importer polled
`/api/repos-manager/conversion/status`, which returns 404 today.

SCM type comes from the repository host (github.com, gitlab.com, bitbucket.org,
dev.azure.com / *.visualstudio.com); a self-hosted SCM needs `--scm-type` and
`--scm-url`. The SCM token is read from an environment variable the caller
names, never from the command line, and is never printed or logged.
"""

from __future__ import annotations

import logging
import os
import re
import time
from urllib.parse import urlparse

logger = logging.getLogger("cxone.scmimport")

_HOSTS = {"github.com": "github", "gitlab.com": "gitlab", "bitbucket.org": "bitbucket",
          "dev.azure.com": "azure", "ssh.dev.azure.com": "azure"}
SCM_TYPES = ("github", "gitlab", "bitbucket", "azure")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def detect_scm_type(repo_url: str, override: str | None = None) -> str | None:
    """github / gitlab / bitbucket / azure from the host, or the override."""
    if override:
        return override.lower()
    host = (urlparse(repo_url).hostname or "").lower()
    if host in _HOSTS:
        return _HOSTS[host]
    if host.endswith(".visualstudio.com") or host.endswith(".azure.com"):
        return "azure"
    return None


def resolve_token(env_var: str | None, cfg, scm_type: str | None) -> tuple[str | None, str]:
    """(token, source label). Never returns the token in the label."""
    if env_var:
        if not _ENV_NAME.match(env_var):
            return None, f"'{env_var}' is not a valid environment variable name"
        value = os.environ.get(env_var, "").strip()
        return (value or None), f"environment variable {env_var}"
    if scm_type == "github" and getattr(cfg, "github_token", None):
        return cfg.github_token, "the configured GitHub token"
    return None, "no token supplied"


def _repo_owner_project(mgr, repo_url: str, exclude_name: str) -> str | None:
    want = repo_url.rstrip("/").lower().removesuffix(".git")
    for p in mgr.list_projects():
        have = str(p.get("repoUrl") or "").rstrip("/").lower().removesuffix(".git")
        if have == want and p.get("name") != exclude_name and (
                p.get("repoId") or p.get("imported_proj_name")):
            return p.get("name")
    return None


def import_scm(mgr, *, name: str, repo_url: str, scm_org: str, token_env: str | None,
               scm_type: str | None, scm_url: str | None, groups: list[str],
               tags: list[str], webhook: bool, auto_scan: bool, criticality: int,
               timeout: int = 300, poll: float = 2.0) -> int:
    cfg = mgr.cfg
    stype = detect_scm_type(repo_url, scm_type)
    if stype not in SCM_TYPES:
        print(f"Cannot tell the SCM type from '{repo_url}'. Pass --scm-type "
              f"({', '.join(SCM_TYPES)}), and --scm-url for a self-hosted server.")
        return 2
    if scm_url and not scm_type:
        print("--scm-url (a self-hosted server) needs --scm-type as well.")
        return 2
    token, token_src = resolve_token(token_env, cfg, stype)
    if not token and not cfg.dry_run:
        print(f"No SCM token: {token_src}. Name an environment variable holding it with "
              f"--scm-token-env VAR" + (" (a configured GitHub token is used for github.com "
                                       "when that flag is omitted)." if stype == "github" else "."))
        return 2

    existing = mgr.find(name)
    if existing and (existing.get("repoId")):
        print(f"Project '{name}' is already an SCM project (repoId {existing.get('repoId')}). "
              f"Nothing to do.")
        return 0
    owner = _repo_owner_project(mgr, repo_url, name)
    if owner:
        print(f"The repository {repo_url} is already onboarded as the SCM project '{owner}'. "
              f"A repository can belong to only one SCM project; use that project, or delete it first.")
        return 1

    payload = {
        "scmType": stype, "scmOnPremUrl": scm_url or None, "orgIdentity": scm_org,
        "token": token, "webhookEnabled": bool(webhook),
        "autoScanCxProjectAfterConversion": bool(auto_scan),
        "projects": [{"cxProjectId": (existing or {}).get("id") or "<new project id>",
                      "scmRepositoryUrl": repo_url}],
    }
    action = f"convert the existing manual project '{name}'" if existing else \
        f"create the manual project '{name}' and convert it"
    if cfg.dry_run:
        shown = dict(payload, token="***" if token else "(none: set --scm-token-env)")
        print(f"[dry-run] would {action} to an SCM project:")
        print(f"  repository : {repo_url}")
        print(f"  SCM        : {stype}" + (f" at {scm_url}" if scm_url else "") + f", organisation '{scm_org}'")
        print(f"  token      : {token_src}")
        print(f"  options    : webhook={'on' if webhook else 'off'}, scan after conversion="
              f"{'yes' if auto_scan else 'no'}")
        if not existing:
            print(f"  groups     : {', '.join(groups) or '(none)'};  tags: {', '.join(tags) or '(none)'}")
        logger.debug("conversion payload: %s", shown)
        return 0

    if existing:
        pid = existing["id"]
    else:
        pid = mgr.create_manual_project({"name": name, "groups": groups, "tags": tags,
                                         "criticality": criticality})
        if not pid:
            print(f"Could not create project '{name}'.")
            return 1
        mgr.set_project_repo(name, repo_url)
    payload["projects"][0]["cxProjectId"] = pid

    try:
        started = mgr.api.post("repos-manager/project-conversion", payload)
    except Exception as exc:                                       # noqa: BLE001
        # The token is in the request body, so report only the status, not the payload.
        print(f"The conversion request was rejected: {exc}")
        return 1
    process_id = started.get("processId") if isinstance(started, dict) else None
    if not process_id:
        print("The conversion request returned no processId; check the project in the UI.")
        return 1
    logger.info("Conversion started (process %s)", process_id)

    deadline = time.monotonic() + timeout
    status, body = "IN_PROGRESS", {}
    while status == "IN_PROGRESS" and time.monotonic() < deadline:
        time.sleep(poll)
        body = mgr.api.get("repos-manager/project-conversion",
                           params={"processId": process_id}) or {}
        status = str(body.get("migrationStatus") or "UNKNOWN")
    if status == "OK":
        print(f"'{name}' is now an SCM project ({repo_url}).")
        return 0
    if status == "IN_PROGRESS":
        print(f"The conversion is still running after {timeout}s (process {process_id}); "
              f"check it later with `project list`.")
        return 1
    other = _repo_owner_project(mgr, repo_url, name)
    detail = body.get("summary") or body.get("failedProjectList") or ""
    print(f"Conversion finished as {status}" + (f": {detail}" if detail else "") + ".")
    if other:
        print(f"The repository is already in use by the SCM project '{other}'.")
    return 1
