"""
Thin runners that drive the ported v2 scan/triage Operations from plain kwargs,
so the rest of the Multi-Tool (and the unified CLI) can invoke them without
constructing argparse Namespaces by hand.
"""

from __future__ import annotations

import logging
from argparse import Namespace

from cxone import CxConfig, AuthManager, ApiClient
from ops.scans import ScanOperation
from ops.triage.triage_operation import TriageOperation

logger = logging.getLogger("cxone.run")


def _components(cfg: CxConfig):
    auth = AuthManager(cfg)
    api = ApiClient(cfg, auth)
    return auth, api


def run_scan(cfg: CxConfig, project_names: str | None = None, project_ids: str | None = None,
             auto: bool = False, percentage: int = 20, min_projects: int = 2,
             force: bool = False, no_overrides: bool = False,
             seed: int | None = None, api=None, acting_as: str | None = None,
             identity_selector=None) -> int:
    """`api` overrides the client (multi-identity: pass pool.client_for(name));
    `acting_as` is the identity label for the log line. `identity_selector`
    (automatic --as specs) resolves the identity PER PROJECT instead, and then
    `api`/`acting_as` are only the fallback/default. Defaults preserve the
    single-identity behavior exactly. Returns the number of projects actually
    resolved and attempted (0 = nothing matched)."""
    if api is None:
        _auth, api = _components(cfg)
    log = logging.getLogger("cxone.scan")
    if acting_as and acting_as != "primary":
        log.info("Acting as identity '%s'", acting_as)
    args = Namespace(project_names=project_names, project_ids=project_ids, auto=auto,
                     percentage=percentage, min_projects=min_projects, force=force,
                     no_overrides=no_overrides, seed=seed)
    return ScanOperation(cfg, getattr(api, "auth", None), api, log,
                         identity_selector=identity_selector).execute(args)


def run_triage(cfg: CxConfig, projects: str, scan_types: str,
               rules_file: str | None = None, intensity: str = "moderate",
               seed: int | None = None, api=None, acting_as: str | None = None,
               identity_selector=None) -> int:
    """`identity_selector` (automatic --as specs) resolves the acting identity
    PER PROJECT; `api`/`acting_as` pin a single identity for the whole run.
    Returns the number of projects actually resolved and processed
    (0 = nothing matched)."""
    if api is None:
        _auth, api = _components(cfg)
    log = logging.getLogger("cxone.triage")
    if acting_as and acting_as != "primary":
        log.info("Acting as identity '%s'", acting_as)
    args = Namespace(projects=projects, scan_types=scan_types, rules_file=rules_file,
                     intensity=intensity, seed=seed)
    return TriageOperation(cfg, getattr(api, "auth", None), api, log,
                           identity_selector=identity_selector).execute(args)
