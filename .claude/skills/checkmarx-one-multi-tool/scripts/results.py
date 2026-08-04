"""
Results querying for Checkmarx One (AST plane, read-only).

Turns raw scan findings into the views an SE actually asks for:
  - summary : counts by engine x severity, per project (or rolled up per application)
  - show    : the actual findings (query/rule/package names), filterable by engine,
              severity, and triage state, for drill-down
  - kpi     : tenant-wide, server-aggregated KPIs (severity/state/status
              distributions, aging, most-common, etc.) via the Analytics API —
              one call instead of walking every project's results client-side

Everything reads the latest Completed/Partial scan per project. Findings are
fetched via ApiClient.fetch_results, which pages /api/results correctly (that
endpoint's `offset` is a page index — see api_client.paginate). On /api/results
`type` is a *sort* option, not a filter, so engine filtering is done client-side
on each result's own `type` field.
"""

from __future__ import annotations

import sys
import json
import logging
import argparse
from collections import defaultdict

from cxone import CxConfig, ApiClient
from ops.project_resolve import warn_unresolved_projects

logger = logging.getLogger("cxone.results")

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_SEV_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# Friendly engine labels (result `type` -> display name).
ENGINE_LABELS = {
    "sast": "SAST", "sca": "SCA", "kics": "IaC/KICS", "containers": "Containers",
    "sscs-secret-detection": "Secrets", "apisec": "API Security",
}
# Accept friendly engine aliases from the CLI -> result `type`.
ENGINE_ALIASES = {
    "sast": "sast", "sca": "sca", "iac": "kics", "kics": "kics",
    "containers": "containers", "container": "containers",
    "secrets": "sscs-secret-detection", "secret": "sscs-secret-detection",
    "apisec": "apisec", "api": "apisec",
}

# The Analytics API's `scanners` filter uses its OWN vocabulary (ScannerType in
# its OpenAPI schema), distinct from /api/results `type` above — most notably
# "secretdetection", not "sscs-secret-detection". Confirmed live: the
# tool-bundled spec/cxone_openapi.json under-lists this enum (only sast/iac/
# sca/dast/containers); the tenant's live spec at {base_url}/spec/v1/... adds
# secretdetection, repohealth, byor. Query the live spec when in doubt instead
# of trusting the bundled snapshot for this endpoint.
ANALYTICS_SCANNER_ALIASES = {
    "sast": "sast", "sca": "sca", "iac": "iac", "kics": "iac",
    "dast": "dast", "containers": "containers", "container": "containers",
    "secrets": "secretdetection", "secret": "secretdetection",
    "secretdetection": "secretdetection",
    "repohealth": "repohealth", "byor": "byor",
}
ANALYTICS_SEVERITY_ALIASES = {
    # live SeverityType enum: critical/high/medium/low/information (lowercase,
    # "information" not "info") — confirmed live: CRITICAL (uppercase) 400s.
    "critical": "critical", "high": "high", "medium": "medium", "low": "low",
    "info": "information", "information": "information",
}
ANALYTICS_STATE_ALIASES = {
    # "proposedNotExploitable" is correct per the tenant's LIVE spec
    # ({base_url}/spec/v1/...ANALYTICS_API.yaml); the public doc site lists
    # the misspelled "propsedNotExploitable" for this same enum — another
    # live-vs-doc-site discrepancy the live spec resolves correctly.
    "to verify": "toVerify", "toverify": "toVerify",
    "not exploitable": "notExploitable", "notexploitable": "notExploitable",
    "proposed not exploitable": "proposedNotExploitable",
    "proposednotexploitable": "proposedNotExploitable",
    "confirmed": "confirmed", "urgent": "urgent",
}


# Shown beside the scope label so a number is never presented without saying
# which branches produced it.
_SCOPE_HINT = {
    "primary": " (project primary branch — matches the UI project view)",
    "production": " (primary + protected + conventional — matches analytics/KPIs)",
    "latest": " (newest scan on ANY branch — may include feature/agent branches)",
    "all": " (every branch)",
}


def _norm_sev(raw: str) -> str:
    return (raw or "UNKNOWN").upper()


def _finding_label(r: dict) -> str:
    """A human label for a finding, chosen per engine, with a description fallback."""
    t = (r.get("type") or "").lower()
    data = r.get("data") or {}
    if t in ("sast", "kics"):
        return data.get("queryName") or _desc(r)
    if t == "sca":
        # The package alone is NOT a distinguishing label: one vulnerable package
        # commonly yields several findings (commons-collections 3.2.1 produced 4
        # Criticals live), which then render as identical rows. The advisory id is
        # what separates them, and on SCA it lives in `id` — the CVE for public
        # advisories, a `Cx…` id for Checkmarx-proprietary ones (malicious/
        # typosquatted packages). NOTE `id` here is NOT `alternateId`; the AI
        # Assist APIs need the latter (see ops/findings.py).
        package = data.get("packageIdentifier") or data.get("packageName")
        advisory = r.get("id") or ""
        if package and advisory and not advisory.startswith(package):
            return f"{advisory} — {package}"
        return package or _desc(r)
    if t == "sscs-secret-detection":
        return data.get("ruleName") or _desc(r)
    if t == "containers":
        pkg = data.get("packageName")
        cve = (r.get("vulnerabilityDetails") or {}).get("cveName") if isinstance(
            r.get("vulnerabilityDetails"), dict) else None
        return f"{cve or ''} {('(' + pkg + ')') if pkg else ''}".strip() or _desc(r)
    return _desc(r)


def _desc(r: dict) -> str:
    d = (r.get("description") or "").strip().replace("\n", " ")
    return (d[:80] + "…") if len(d) > 80 else (d or "(no description)")


def _location(r: dict) -> str:
    """Where the finding lives (best-effort, per engine)."""
    data = r.get("data") or {}
    if data.get("fileName"):
        loc = data["fileName"]
        return f"{loc}:{data['line']}" if data.get("line") else loc
    if data.get("nodes"):
        n0 = data["nodes"][0] if data["nodes"] else {}
        if n0.get("fileName"):
            return f"{n0['fileName']}:{n0.get('line', '?')}"
    if data.get("imageName"):
        return f"{data['imageName']}:{data.get('imageTag', '')}"
    # SCA deliberately has no location: the package IS the label (see
    # _finding_label), so repeating it here printed every row twice.
    return ""


class ResultsManager:
    def __init__(self, api: ApiClient):
        self.api = api
        self.cfg = api.config
        self._branches = None

    @property
    def branches(self):
        """Lazy BranchResolver — only built when a query needs branch scoping,
        so nothing pays for the protected-branches lookups unless asked."""
        if self._branches is None:
            from ops.branch_scope import BranchResolver
            self._branches = BranchResolver(self.api)
        return self._branches

    def _scoped_scan(self, project: dict, scope: str, branch: str | None):
        """(scan_id, BranchChoice) for a project under the active scope.

        Always returns the choice so the caller can SAY which branch/scan it
        used; reporting a number without that is what made the branch bug
        invisible in the first place.
        """
        choice = self.branches.resolve(project, scope=scope, branch=branch)
        return choice.scan_id, choice

    # ----------------------------------------------------- project resolution
    def _all_projects(self) -> list[dict]:
        return self.api.paginate("projects", results_key="projects")

    def _resolve_projects(self, names: list[str] | None = None,
                          app_name: str | None = None) -> list[dict]:
        projects = self._all_projects()
        if app_name:
            ids = self._app_project_ids(app_name)
            return [p for p in projects if p.get("id") in ids]
        if names:
            wanted = {n.lower() for n in names}
            matched = [p for p in projects if p.get("name", "").lower() in wanted]
            found = {p.get("name", "").lower() for p in matched}
            warn_unresolved_projects(logger, names, projects, found)
            return matched
        return projects

    def _app_project_ids(self, app_name: str) -> set[str]:
        """Project ids belonging to an application (via its tag rules)."""
        apps = self.api.paginate("applications", results_key="applications")
        app = next((a for a in apps if a.get("name") == app_name), None)
        if not app:
            logger.warning("Application '%s' not found", app_name)
            return set()
        # Applications expose their resolved projectIds directly when present.
        ids = set(app.get("projectIds") or [])
        if ids:
            return ids
        # Fallback: match projects whose tags satisfy the app's tag-key rules.
        keys = [rule.get("value") for rule in (app.get("rules") or [])
                if rule.get("type") == "project.tag.key.exists"]
        if not keys:
            return ids
        out = set()
        for p in self._all_projects():
            tags = p.get("tags") or {}
            if any(k in tags for k in keys):
                out.add(p.get("id"))
        return out

    def _latest_scan_id(self, project_id: str) -> str | None:
        scan = self.api.get_latest_scan_for_project(
            project_id, statuses=["Completed", "Partial"])
        return scan.get("id") if scan else None

    # ----------------------------------------------------------- aggregation
    def _counts_for_scan(self, scan_id: str) -> dict[str, dict[str, int]]:
        counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for r in self.api.fetch_results(scan_id):
            counts[(r.get("type") or "unknown")][_norm_sev(r.get("severity"))] += 1
        return counts

    def summarize(self, names: list[str] | None = None, app_name: str | None = None,
                  min_severity: str | None = None, scope: str = "primary",
                  branch: str | None = None) -> int:
        projects = self._resolve_projects(names, app_name)
        if not projects:
            logger.warning("No matching projects.")
            return 1
        min_rank = _SEV_RANK.get((min_severity or "").upper(), len(SEVERITY_ORDER))
        # Application rollup totals across member projects.
        rollup: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        what = f"application '{app_name}'" if app_name else "projects"
        logger.info("Results summary (%s) — branch scope: %s%s",
                    what, "--branch " + branch if branch else scope,
                    "" if branch else _SCOPE_HINT.get(scope, ""))
        for p in projects:
            sid, choice = self._scoped_scan(p, scope, branch)
            if not sid:
                logger.info("  %-26s no completed scan in scope", p.get("name"))
                continue
            counts = self._counts_for_scan(sid)
            logger.info("  %s", choice.describe())
            drift = choice.drift_note()
            if drift:
                logger.warning("      %s", drift)
            self._print_project(p.get("name", "?"), counts, min_rank)
            if app_name:
                for eng, sevs in counts.items():
                    for sev, n in sevs.items():
                        rollup[eng][sev] += n
        if app_name and rollup:
            logger.info("  %s", "-" * 50)
            self._print_project(f"TOTAL ({app_name})", rollup, min_rank)
        return 0

    def _print_project(self, name: str, counts: dict[str, dict[str, int]],
                       min_rank: int) -> None:
        total = sum(sum(s.values()) for s in counts.values())
        logger.info("  %s — %d findings", name, total)
        for eng in sorted(counts, key=lambda e: ENGINE_LABELS.get(e, e)):
            sevs = counts[eng]
            parts = []
            for sev in SEVERITY_ORDER:
                if sev in sevs and _SEV_RANK[sev] <= min_rank:
                    parts.append(f"{sev.title()}: {sevs[sev]}")
            if parts:
                label = ENGINE_LABELS.get(eng, eng)
                eng_total = sum(sevs.values())
                logger.info("      %-13s %4d   %s", label, eng_total, " | ".join(parts))

    # ---------------------------------------------------------------- show
    def show(self, project_name: str, *, engine: str | None = None,
             severities: list[str] | None = None, states: list[str] | None = None,
             limit: int = 25, match: str | None = None, show_ids: bool = False,
             as_json: bool = False, history: bool = False,
             scope: str = "primary", branch: str | None = None,
             full_history: bool = False) -> int:
        projects = self._resolve_projects([project_name])
        if not projects:
            return 1
        project_id = projects[0]["id"]
        sid, choice = self._scoped_scan(projects[0], scope, branch)
        if not sid:
            logger.info("%s: no completed scan in scope (%s)", project_name,
                        branch or scope)
            return 0
        result_type = ENGINE_ALIASES.get((engine or "").lower()) if engine else None
        results = self.api.fetch_results(sid, result_type=result_type)
        # SCA scans are immutable: /api/results reports the state as of the scan,
        # so triage applied since would be invisible. Replace it with the current
        # state before any filtering or display. See ops/sca_live_state.py.
        from ops.sca_live_state import enrich_results
        enrich_results(self.api, sid, project_id, results)
        sev_set = {s.upper() for s in (severities or [])}
        state_set = {s.upper().replace(" ", "_") for s in (states or [])}
        if sev_set:
            results = [r for r in results if _norm_sev(r.get("severity")) in sev_set]
        if state_set:
            results = [r for r in results if (r.get("state") or "").upper() in state_set]
        if match:
            needle = match.lower()
            results = [r for r in results if needle in _finding_label(r).lower()
                       or needle in (r.get("description") or "").lower()]
        results.sort(key=lambda r: _SEV_RANK.get(_norm_sev(r.get("severity")), 99))
        shown = results[:limit]

        want_history = history or full_history

        if as_json:
            # Machine-readable form always carries the identifiers, so a finding
            # can be piped straight into `ai-assist` or any API call.
            from ops.findings import group_id_for
            rows = []
            for r in shown:
                row = {
                    "projectId": project_id, "projectName": project_name, "scanId": sid,
                    "branch": choice.branch, "branchScope": choice.scope,
                    "resultId": r.get("alternateId"), "engine": (r.get("type") or "").lower(),
                    "groupId": group_id_for(r, project_id), "label": _finding_label(r),
                    "severity": _norm_sev(r.get("severity")), "state": r.get("state"),
                    "location": _location(r),
                }
                if want_history:
                    from ops.triage_history import history_for
                    events = history_for(self.api, r, sid, project_id)
                    row["triageHistory"] = [e.to_dict()
                                            for e in (events if full_history else events[:1])]
                rows.append(row)
            print(json.dumps(rows, indent=2))
            return 0

        eng_disp = ENGINE_LABELS.get(result_type, engine) if engine else "all engines"
        logger.info("%s — %s: %d finding(s)%s", project_name, eng_disp, len(results),
                    f" (showing {len(shown)})" if len(shown) < len(results) else "")
        logger.info("  %s", choice.describe())
        _drift = choice.drift_note()
        if _drift:
            logger.warning("  %s", _drift)
        if show_ids:
            logger.info("  scan id: %s", sid)
        for r in shown:
            sev = _norm_sev(r.get("severity")).title()
            state = (r.get("state") or "").replace("_", " ").title()
            label = _finding_label(r)
            loc = _location(r)
            line = f"  [{sev:<8}] {ENGINE_LABELS.get(r.get('type'), r.get('type')):<10} {label}"
            if loc:
                line += f"  — {loc}"
            line += f"  ({state})"
            logger.info(line)
            if show_ids:
                # alternateId — NOT `id`. They match on SAST but diverge on SCA,
                # and the AI Assist APIs only accept alternateId.
                from ops.findings import group_id_for
                logger.info("             result id: %s", r.get("alternateId"))
                gid = group_id_for(r, project_id)
                if gid:
                    logger.info("             group id : %s", gid)
            if want_history:
                from ops.triage_history import history_for
                events = history_for(self.api, r, sid, project_id)
                if not events:
                    logger.info("             (no triage history)")
                for e in (events if full_history else events[:1]):
                    for i, part in enumerate(e.describe().split("\n")):
                        logger.info("             %s%s", "" if i else "triaged: ", part.strip()
                                    if i else part)
        return 0

    # ----------------------------------------------------------------- kpi
    def kpi(self, kpi_name: str, *, scanners: list[str] | None = None,
            states: list[str] | None = None, severities: list[str] | None = None,
            project_names: list[str] | None = None, start_date: str | None = None,
            end_date: str | None = None, limit: int | None = None,
            offset: int | None = None) -> int:
        """Tenant-wide server-aggregated KPI via the Analytics API. See
        references/cxone-api.md 'Analytics KPI endpoint' for the KPI catalog
        and gotchas (required endDate, 1-year startDate cap, scanner vocab)."""
        scanner_vals = [ANALYTICS_SCANNER_ALIASES.get(s.lower(), s) for s in (scanners or [])] or None
        state_vals = [ANALYTICS_STATE_ALIASES.get(s.lower(), s) for s in (states or [])] or None
        # Analytics API SeverityType is lowercase and spells Info as "information"
        # (live-verified: uppercase 400s) — unlike every other engine in this tool,
        # which uses UPPER severities. Don't reuse _norm_sev/.upper() here.
        sev_vals = [ANALYTICS_SEVERITY_ALIASES.get(s.lower(), s.lower()) for s in (severities or [])] or None
        # The Analytics API applies its OWN production-branch filter server-side
        # (primary + protected + conventional names). Saying so matters: these
        # numbers can and do differ from `results summary`, and an unlabelled
        # difference reads as a bug in one of them rather than two scopes.
        logger.info("Analytics KPI '%s' — branch scope: production branches "
                    "(server-side; may differ from `results summary --scope primary`)",
                    kpi_name)
        data = self.api.query_analytics_kpi(
            kpi_name, start_date=start_date, end_date=end_date,
            scanners=scanner_vals, states=state_vals, severities=sev_vals,
            projects=project_names, limit=limit, offset=offset,
        )
        if kpi_name == "vulnerabilitiesBySeverityAndStateTotal" and isinstance(data, list):
            self._print_severity_and_state_table(data)
        else:
            import json
            logger.info(json.dumps(data, indent=2))
        return 0

    @staticmethod
    def _print_severity_and_state_table(rows: list[dict]) -> None:
        sevs = ["Critical", "High", "Medium", "Low", "Information"]
        header = f"{'State':<26}" + "".join(f"{s:>10}" for s in sevs) + f"{'Total':>10}"
        logger.info(header)
        for row in rows:
            sevmap = {s.get("label"): s.get("results", 0) for s in row.get("severities", [])}
            line = f"{row.get('label', '?'):<26}" + "".join(
                f"{sevmap.get(s, 0):>10}" for s in sevs) + f"{row.get('results', 0):>10}"
            logger.info(line)


SCOPE_HELP = ("branch scope: primary (project primary branch — UI parity, default), production (primary+protected+conventional — analytics parity), latest (newest scan on any branch), all")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="results")
    p.add_argument("--env", default=None)
    p.add_argument("--debug", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("summary", help="counts by engine x severity per project / app")
    g = s.add_mutually_exclusive_group()
    g.add_argument("--projects", help="comma-separated project names")
    g.add_argument("--app", help="roll up across an application's projects")
    g.add_argument("--all", action="store_true", help="every project in the tenant")
    s.add_argument("--scope", default="primary",
                   choices=["primary", "production", "latest", "all"],
                   help="%s" % SCOPE_HELP)
    s.add_argument("--branch", default=None,
                   help="report this exact branch (overrides --scope)")
    s.add_argument("--min-severity", default=None,
                   choices=["Critical", "High", "Medium", "Low", "Info"],
                   help="only show this severity and above")

    sh = sub.add_parser("show", help="list findings (drill-down)")
    sh.add_argument("--project", required=True)
    sh.add_argument("--scope", default="primary",
                    choices=["primary", "production", "latest", "all"],
                    help="%s" % SCOPE_HELP)
    sh.add_argument("--branch", default=None,
                    help="report this exact branch (overrides --scope)")
    sh.add_argument("--engine", default=None,
                    choices=["sast", "sca", "iac", "kics", "containers", "secrets", "apisec"])
    sh.add_argument("--severity", default=None,
                    help="comma-separated: Critical,High,Medium,Low,Info")
    sh.add_argument("--state", default=None,
                    help="comma-separated triage states, e.g. 'To Verify,Confirmed'")
    sh.add_argument("--limit", type=int, default=25)
    sh.add_argument("--match", default=None,
                    help="case-insensitive substring of the finding name/description, "
                         "e.g. --match \"SQL Injection\"")
    sh.add_argument("--ids", action="store_true",
                    help="also print the scan id, result id (alternateId) and group id "
                         "each finding needs for API calls (e.g. ai-assist)")
    sh.add_argument("--json", action="store_true",
                    help="emit findings as JSON, identifiers included")
    sh.add_argument("--history", action="store_true",
                    help="also show WHO triaged each finding, when, and their comment "
                         "(the latest change) — read from the engine's own predicate/"
                         "action store, never the audit trail")
    sh.add_argument("--full-history", action="store_true",
                    help="like --history but every triage change, not just the latest")

    k = sub.add_parser("kpi", help="tenant-wide server-aggregated KPI (Analytics API)")
    k.add_argument("--kpi", required=True,
                   choices=["vulnerabilitiesBySeverityTotal", "vulnerabilitiesByStateTotal",
                            "vulnerabilitiesByStatusTotal", "vulnerabilitiesBySeverityAndStateTotal",
                            "vulnerabilitiesBySeverityOvertime", "meanTimeToResolution",
                            "fixedVulnerabilitiesBySeverityOvertime", "agingTotal",
                            "allVulnerabilities", "mostCommonVulnerabilities",
                            "mostAgingVulnerabilities", "ideOvertime", "ideTotal"])
    k.add_argument("--scanners", default=None,
                   help="comma-separated: sast,sca,iac,dast,containers,secrets,repohealth,byor")
    k.add_argument("--states", default=None,
                   help="comma-separated: 'To Verify,Not Exploitable,Proposed Not Exploitable,"
                        "Confirmed,Urgent'")
    k.add_argument("--severities", default=None,
                   help="comma-separated: Critical,High,Medium,Low,Info")
    k.add_argument("--projects", default=None, help="comma-separated project names or IDs")
    k.add_argument("--start-date", default=None, help="ISO 8601; default 364 days back")
    k.add_argument("--end-date", default=None, help="ISO 8601; default now")
    k.add_argument("--limit-n", type=int, default=None,
                   help="required by allVulnerabilities/mostCommonVulnerabilities/"
                        "mostAgingVulnerabilities")
    k.add_argument("--offset", type=int, default=None, help="allVulnerabilities only")

    args = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = CxConfig.from_env(args.env)
    mgr = ResultsManager(ApiClient(cfg))

    if args.cmd == "summary":
        names = [n.strip() for n in (args.projects or "").split(",") if n.strip()] or None
        return mgr.summarize(names=names, app_name=args.app,
                             min_severity=args.min_severity,
                             scope=args.scope, branch=args.branch)
    if args.cmd == "show":
        return mgr.show(
            args.project,
            engine=args.engine,
            severities=[s.strip() for s in (args.severity or "").split(",") if s.strip()] or None,
            states=[s.strip() for s in (args.state or "").split(",") if s.strip()] or None,
            limit=args.limit,
            match=args.match,
            show_ids=args.ids,
            as_json=args.json,
            scope=args.scope,
            branch=args.branch,
            history=args.history,
            full_history=args.full_history,
        )
    if args.cmd == "kpi":
        return mgr.kpi(
            args.kpi,
            scanners=[s.strip() for s in (args.scanners or "").split(",") if s.strip()] or None,
            states=[s.strip() for s in (args.states or "").split(",") if s.strip()] or None,
            severities=[s.strip() for s in (args.severities or "").split(",") if s.strip()] or None,
            project_names=[s.strip() for s in (args.projects or "").split(",") if s.strip()] or None,
            start_date=args.start_date, end_date=args.end_date,
            limit=args.limit_n, offset=args.offset,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
