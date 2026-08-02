"""
Scan operation for the Checkmarx One Multi-Tool.

Triggers scans for specified projects (explicit or random subset) using
percentage-based overrides defined in config/scan_rules.yaml.
"""

import json
import time
import random
import logging
from argparse import Namespace
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

from ops.base import Operation
from ops.project_resolve import warn_unresolved_projects
from cxone import CxConfig as Config
from cxone import AuthManager
from cxone import ApiClient
from ops.config_loader import load_yaml_config
from ops.logger import get_logger

# Thread-safe RNG for override rolls (roll is per project, per setting, from
# worker threads). Only used when no run seed is set; seeded runs derive a
# per-(seed, project, setting) RNG instead — see _apply_overrides.
_override_rng = random.SystemRandom()

# Flip on to log full request payloads at DEBUG (noisy; off by default).
_LOG_FULL_API_BODIES = False

# config[] shape is the same for manual (POST /scans) and SCM (projectScan).
# Allowed config[].type: sast, sca, kics, apisec, containers, microengines.
# microengines = Secret Detection (2ms) + Scorecard; value keys: scorecard, 2ms, gitCommitHistory.
# SCM project.scannerTypes expands microengines to "2ms" and "scorecard"; manual keeps one microengines entry.
# See Legacy and Reference/CHECKMARX_ONE_SCAN_PAYLOADS_SPEC.md.
ALL_SCANNER_TYPES = ["sast", "sca", "kics", "apisec", "containers", "microengines"]
SCM_SCANNER_TYPES = ["sast", "sca", "kics", "apisec", "containers", "2ms", "scorecard"]

# Scan execution statuses that mean a scan is still in flight for a project. If one
# of these is the project's latest scan, re-triggering would stack a duplicate.
ACTIVE_SCAN_STATUSES = ["Queued", "Running"]

# Statuses that mean the scan itself did not (or will not) produce results. The
# TRIGGER still succeeded in these cases — we report the status rather than
# pretending the call failed.
UNSUCCESSFUL_SCAN_STATUSES = {"failed", "canceled", "cancelled", "partial"}

# Post-trigger confirmation (see ScanManager._confirm_scan). The scan record can
# lag the trigger by a moment, so poll briefly rather than giving up on the first
# empty read.
_CONFIRM_ATTEMPTS = 4
_CONFIRM_BACKOFF_S = 2.0
# Tolerance when matching a freshly-created scan by timestamp: our clock and the
# platform's can differ slightly, so accept a scan created a little "before" the
# moment we triggered. Kept small so we can't mistake an older scan for ours.
_CONFIRM_SKEW_S = 120


def _parse_iso_utc(value: str | None) -> datetime | None:
    """Parse a CxOne timestamp ('2026-07-28T22:32:33.915636Z') to aware UTC."""
    if not value or not isinstance(value, str):
        return None
    txt = value.strip()
    if txt.endswith("Z"):
        txt = txt[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(txt)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class ScanOperation(Operation):
    """Triggers scans for projects, applying optional config overrides."""

    def __init__(
        self,
        config: Config,
        auth: AuthManager,
        api: ApiClient,
        logger: logging.Logger,
        identity_selector=None,
    ):
        super().__init__(config, auth, api, logger, identity_selector)
        self._scan_rules: dict = {}
        # When True, skip the weighted preset/incremental randomizer entirely so
        # an explicitly pinned preset survives the immediately-following scan.
        self._no_overrides: bool = False

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def execute(self, args: Namespace) -> int:
        """Returns the number of projects actually resolved and attempted —
        0 if none matched (a caller like the agent uses this to decide
        whether a no-op should count toward cadence tracking; see
        references/cxone-api.md 'Project resolution and zero-visibility
        identities' for the incident this return value exists to prevent)."""
        cfg = load_yaml_config("scan_rules.yaml")
        self._scan_rules = cfg.get("scanRules") or cfg.get("scan_rules", {})
        # Re-scanning a project that already has a Queued/Running scan stacks a
        # duplicate; guard against it unless --force is given (see _scan_project).
        self._force = bool(getattr(args, "force", False))
        # Opt out of the weighted preset/incremental randomizer for this run so a
        # preset pinned via `scanconfig set` isn't silently re-rolled at scan time.
        self._no_overrides = bool(getattr(args, "no_overrides", False))

        # Reproducible selection + override rolls. With a seed, a dry-run and the
        # live run pick the same random project subset and roll the same overrides.
        # If none given, generate + announce one so the run can be reproduced.
        seed = getattr(args, "seed", None)
        if seed is None:
            seed = random.SystemRandom().randint(0, 2**31 - 1)
        self._seed = int(seed)
        self._rng = random.Random(self._seed)
        self.logger.info(
            "Scan seed: %d  (pass --seed %d to reproduce this selection/rolls)",
            self._seed, self._seed,
        )

        projects = self._resolve_projects(args)
        if not projects:
            self.logger.warning("No projects found to scan.")
            return 0

        for i, p in enumerate(projects, 1):
            self.logger.debug(
                "Selected project %d/%d: name=%s id=%s",
                i, len(projects),
                p.get("name", "(no name)"),
                p.get("id", "(no id)"),
            )
        self.logger.debug("Scanning %d project(s) with %d worker(s).", len(projects), self.config.workers)

        successful, failed, skipped = [], [], []

        with ThreadPoolExecutor(max_workers=self.config.workers) as pool:
            futures = {pool.submit(self._scan_project, p): p for p in projects}
            for future in as_completed(futures):
                project = futures[future]
                try:
                    result = future.result()
                    if isinstance(result, dict) and result.get("skipped"):
                        skipped.append(result)
                    elif result:
                        successful.append(result)
                    else:
                        failed.append({
                            "name": project.get("name", project.get("id")),
                            "reason": "Scan failed",
                        })
                except Exception as exc:
                    name = project.get("name", project.get("id"))
                    self.logger.error("Error scanning project '%s': %s", name, exc)
                    failed.append({"name": name, "reason": str(exc)})

        self._print_summary(successful, failed, skipped)
        return len(projects)

    # ------------------------------------------------------------------
    # Duplicate-scan guard
    # ------------------------------------------------------------------

    def _active_scan_for(self, project_id: str) -> dict | None:
        """Return the project's in-flight (Queued/Running) scan, if any."""
        try:
            return self.api.get_latest_scan_for_project(
                project_id, statuses=ACTIVE_SCAN_STATUSES
            )
        except Exception as exc:
            self.logger.debug("Could not check active scans for %s: %s", project_id, exc)
            return None

    # ------------------------------------------------------------------
    # Project resolution
    # ------------------------------------------------------------------

    def _resolve_projects(self, args: Namespace) -> list[dict]:
        if getattr(args, "auto", False):
            return self._auto_select(
                args.percentage or 20,
                args.min_projects or 2,
            )

        if getattr(args, "project_names", None):
            names = [n.strip() for n in args.project_names.split(",") if n.strip()]
            return self._get_projects_by_name(names)

        if getattr(args, "project_ids", None):
            ids = [i.strip() for i in args.project_ids.split(",") if i.strip()]
            return [{"id": pid} for pid in ids]

        self.logger.error(
            "Provide --project-names, --project-ids, or --auto for the scan command."
        )
        return []

    def _get_all_projects(self) -> list[dict]:
        self.logger.debug("Fetching all projects...")
        return self.api.paginate("projects", results_key="projects")

    def _get_projects_by_name(self, names: list[str]) -> list[dict]:
        self.logger.debug("Resolving project names: %s", names)
        all_projects = self._get_all_projects()
        name_set = {n.lower() for n in names}
        matched = [p for p in all_projects if p.get("name", "").lower() in name_set]

        found_names = {p.get("name", "").lower() for p in matched}
        warn_unresolved_projects(self.logger, names, all_projects, found_names)

        return matched

    def _auto_select(self, percentage: int, min_projects: int) -> list[dict]:
        all_projects = self._get_all_projects()
        if not all_projects:
            return []

        target = max(min_projects, int(len(all_projects) * percentage / 100))
        target = min(target, len(all_projects))

        # Deterministic under the run seed: sort first for a stable base order, then
        # sample with the seeded RNG so a dry-run and live run pick the same subset.
        rng = getattr(self, "_rng", None) or random
        ordered = sorted(all_projects, key=lambda p: str(p.get("id") or p.get("name") or ""))
        selected = rng.sample(ordered, target)
        self.logger.info(
            "Auto-scan: selected %d of %d projects (%d%%, min %d).",
            len(selected), len(all_projects), percentage, min_projects,
        )
        return selected

    # ------------------------------------------------------------------
    # Per-project scan logic
    # ------------------------------------------------------------------

    def _scan_project(self, project: dict) -> dict | None:
        project_id = project.get("id")
        project_name = project.get("name", project_id)

        if not project_id:
            self.logger.warning("Skipping project with no ID: %s", project)
            return None

        # Automatic --as specs resolve per project, not once per invocation: with
        # `--auto` picking a dozen projects, one person triggering all of them is
        # not what a team looks like. The bound view carries that identity's client
        # through every self.api call below.
        me, _acting = self.acting_for(project_name)   # logs the owner itself
        return me._scan_project_as(project, project_id, project_name)

    def _scan_project_as(self, project: dict, project_id: str,
                         project_name: str) -> dict | None:

        # Fetch full project to determine SCM vs manual and get fields
        display_name = project.get("name", project_id)
        self.logger.debug(
            "['%s'] Getting project details: GET projects/%s",
            display_name, project_id,
        )
        try:
            full_project = self._fetch_project(project_id) or project
        except Exception as exc:
            self.logger.error(
                "Could not fetch project details for '%s': %s", project_name, exc
            )
            return None
        project_name = full_project.get("name") or project_name

        # Duplicate-scan guard: skip if a Queued/Running scan already exists, unless
        # forced. The check is read-only, so it runs in DRY-RUN too — otherwise the
        # preview lists projects the live run would then skip, and "the live run
        # executes exactly what was previewed" breaks.
        if not self._force:
            active = self._active_scan_for(project_id)
            if active:
                status_l = (active.get("status") or "in progress").lower()
                verb = "Would skip" if self.config.dry_run else "Skipping"
                self.logger.warning(
                    "%s '%s': a scan is already %s (id=%s, started %s). "
                    "Use --force to scan anyway.",
                    verb, project_name, status_l,
                    active.get("id", "?"), (active.get("createdAt") or "")[:19],
                )
                return {"skipped": True, "project_name": project_name,
                        "project_id": project_id,
                        "reason": f"already {status_l}"}

        route = "SCM" if self._is_scm_project(full_project) else "manual"
        self.logger.info(
            "['%s'] routing scan via %s endpoint (%s).",
            project_name, route,
            "repos-manager/.../projectScan" if route == "SCM" else "POST /scans",
        )
        if route == "SCM":
            return self._trigger_scan_scm(full_project, project_name, project_id)
        return self._trigger_scan_manual(full_project, project_name, project_id)

    def _is_scm_project(self, project: dict) -> bool:
        """True if this project was imported from an SCM and must scan via the
        repos-manager `projectScan` endpoint.

        Keyed on the fields that endpoint actually needs — `scmRepoId` and
        `repoId` — NOT on `origin`: `origin` is set on manually-created projects
        too (e.g. "Checkmarx One Multi-Tool"), so it can't discriminate. A project
        with both SCM ids is SCM; anything else is treated as manual (POST /scans).
        This keeps a mixed batch (some SCM, some manual) correctly routed per
        project. If an SCM project is somehow missing these ids, we log it so the
        misroute is visible rather than silent."""
        has_scm_ids = (
            project.get("scmRepoId") is not None
            and project.get("repoId") is not None
        )
        if not has_scm_ids and project.get("scmRepoId") is not None:
            # Partial SCM signal — surface it rather than silently going manual.
            self.logger.debug(
                "['%s'] has scmRepoId but no repoId — treating as manual; "
                "if this project is SCM-imported the detail record may be partial.",
                project.get("name") or project.get("id"),
            )
        return has_scm_ids

    def _trigger_scan_scm(
        self, project: dict, project_name: str, project_id: str
    ) -> dict | None:
        """Trigger scan via POST repos-manager/.../projectScan (SCM-imported project)."""
        repo_id = project.get("repoId")
        scm_repo_id = project.get("scmRepoId")
        origin = project.get("origin") or ""
        default_branch = (project.get("mainBranch") or "main").strip()

        if repo_id is None or scm_repo_id is None:
            self.logger.warning("Skipping SCM project '%s': missing repoId or scmRepoId.", project_name)
            return None

        # Prefer branch from latest Completed/Partial scan (same as manual path)
        self.logger.debug(
            "['%s'] Getting latest scan (branch/repo): GET scans",
            project_name,
        )
        latest_scan = self.api.get_latest_scan_for_project(project_id)
        if latest_scan:
            scan_branch, _ = self._get_branch_and_repo_from_scan(latest_scan)
            if scan_branch:
                default_branch = scan_branch.strip()

        self.logger.debug(
            "['%s'] Getting repo URL and SCM: GET repos-manager/repo/%s",
            project_name, repo_id,
        )
        repo = self.api.get_repo_by_id(repo_id, project_id)
        if not repo:
            self.logger.error("Could not get repo by id %s for project '%s'.", repo_id, project_name)
            return None

        scm_id = repo.get("scmId") or repo.get("scm_id")
        repo_url = (repo.get("url") or repo.get("repoUrl") or "").strip()
        if not scm_id or not repo_url:
            self.logger.error(
                "Repo for project '%s' missing scmId or url.", project_name
            )
            return None

        # Use project's origin for repoOrigin (GET /repos-manager/scms/{id} is not supported by the API)
        repo_origin = (origin or "GitHub").strip()
        repo_org = self._parse_repo_org(repo_url, repo_origin)

        # 1) Resolve effective config + overrides (shared with the manual path).
        # SCM projects tolerate a missing config: scanner types fall back to the
        # rules/default list and no PATCH is attempted.
        resolved = self._resolve_config_updates(project_id, project_name)
        if resolved:
            config_array, to_patch_preset, to_patch_inc, config_changes = resolved
            scanner_types = self._config_array_to_scm_scanner_types(config_array)
        else:
            scanner_types = []
            to_patch_preset, to_patch_inc, config_changes = None, None, None
        if not scanner_types:
            engines = self._scan_rules.get("engines", [])
            scanner_types = self._engine_list_to_scm_scanner_types(engines) if engines else SCM_SCANNER_TYPES.copy()

        # 2) PATCH only when something actually changed (live runs only)
        if not self._patch_config_if_needed(project_id, project_name,
                                            to_patch_preset, to_patch_inc):
            return None

        # 3) Scan request
        body = {
            "repoOrigin": repo_origin,
            "project": {
                "repoIdentity": str(scm_repo_id),
                "repoUrl": repo_url,
                "projectId": project_id,
                "defaultBranch": default_branch,
                "scannerTypes": scanner_types,
                "repoId": repo_id,
            },
            "orgSshKey": None,
        }

        self.logger.debug(
            "Scan project (SCM): name=%s id=%s branch=%s repo_org=%s",
            project_name, project_id, default_branch, repo_org,
        )
        if _LOG_FULL_API_BODIES:
            self.logger.debug(
                "Scan request payload (SCM) for '%s':\n%s",
                project_name, json.dumps(body, indent=2),
            )
        else:
            self.logger.debug("Scan request (SCM) for '%s'", project_name)

        if self.config.dry_run:
            self.logger.debug(
                "[DRY-RUN] Would trigger SCM scan for '%s' (branch: %s, engines: %s)",
                project_name, default_branch, scanner_types,
            )
            return self._trigger_result(project_name, project_id, "DRY-RUN",
                                        default_branch, config_changes)

        # Step 1 — issue the trigger. A raised exception is the ONLY explicit
        # failure signal here; anything else moves on to confirmation.
        triggered_at = datetime.now(timezone.utc)
        try:
            response = self.api.post_project_scan_scm(
                scm_id, repo_org, project_id, body
            )
        except Exception as exc:
            self.logger.error("Failed to trigger SCM scan for '%s': %s", project_name, exc)
            return None

        # Step 2 — confirm: resolve the scan id and read its real status. This
        # endpoint returns no id at all, so the hint is expected to be empty.
        self.logger.debug("Scan triggered for '%s' — branch=%s", project_name, default_branch)
        return self._finalize_trigger(
            project_name, project_id,
            self._extract_scan_id_from_response(response),
            default_branch, config_changes, triggered_at,
        )

    # Keys for GET/PATCH configuration/project (scan_rules overrides → project-level change)
    _SAST_PRESET_KEY = "scan.config.sast.presetName"
    _SAST_INCREMENTAL_KEY = "scan.config.sast.incremental"

    # ------------------------------------------------------------------
    # Shared config resolution (used by BOTH the SCM and manual trigger paths;
    # previously duplicated in each)
    # ------------------------------------------------------------------

    def _resolve_config_updates(
        self, project_id: str, project_name: str
    ) -> tuple[list[dict], str | None, bool | None, str | None] | None:
        """GET the project's effective scan config (engines filtered, overrides
        rolled) and diff the rolled SAST preset/incremental against the current
        values. Returns (config_array, to_patch_preset, to_patch_inc,
        config_changes_display) — the *_patch values are None when nothing
        changed — or None when the config couldn't be retrieved (the SCM path
        falls back to default scanner types; the manual path treats it as fatal).
        """
        result = self._get_effective_scan_config(project_id, project_name)
        if not result:
            return None
        config_array, current_preset, current_inc = result
        target_preset, target_inc = self._get_sast_preset_and_incremental(config_array)
        to_patch_preset = (
            target_preset
            if target_preset and (target_preset.strip() != (current_preset or "").strip())
            else None
        )
        to_patch_inc = (
            target_inc
            if target_inc is not None and target_inc != current_inc
            else None
        )
        changed = to_patch_preset or to_patch_inc is not None
        config_changes = self._format_config_changes(to_patch_preset, to_patch_inc) if changed else None
        return config_array, to_patch_preset, to_patch_inc, config_changes

    def _patch_config_if_needed(self, project_id: str, project_name: str,
                                to_patch_preset: str | None,
                                to_patch_inc: bool | None) -> bool:
        """PATCH the rolled preset/incremental onto the project, live runs only.
        Dry-runs never PATCH (the change is previewed via config_changes).
        Returns False when a needed PATCH failed (caller aborts the trigger)."""
        if self.config.dry_run or (not to_patch_preset and to_patch_inc is None):
            return True
        return self._apply_project_config_overrides(
            project_id, project_name, to_patch_preset, to_patch_inc)

    @staticmethod
    def _trigger_result(project_name: str, project_id: str, scan_id: str,
                        branch: str, config_changes: str | None) -> dict:
        """Uniform per-project result record for the run summary."""
        out = {"project_name": project_name, "project_id": project_id,
               "scan_id": scan_id, "branch": branch}
        if config_changes:
            out["config_changes"] = config_changes
        return out

    # ------------------------------------------------------------------
    # Post-trigger confirmation (single flow for BOTH routes)
    # ------------------------------------------------------------------

    def _scan_status_by_id(self, scan_id: str) -> str | None:
        """GET scans/{id} -> status, or None if it can't be read."""
        try:
            scan = self.api.get(f"scans/{scan_id}") or {}
        except Exception as exc:
            self.logger.debug("Could not read scan %s: %s", scan_id, exc)
            return None
        return scan.get("status")

    def _confirm_scan(self, project_name: str, project_id: str,
                      triggered_at: datetime,
                      hinted_scan_id: str | None) -> tuple[str | None, str | None]:
        """Resolve the scan a just-issued trigger created, and read its status.

        ONE path for both routes, because the two trigger endpoints differ in
        what they hand back and that difference shouldn't leak into the result:
          * POST /api/scans (manual/clone-URL projects) returns a scan id inline.
          * repos-manager/.../projectScan (SCM-imported projects) is internal and
            returns an EMPTY body with no Location header — there is no id to
            parse, by design, not because its shape drifted.
        So the response id is treated as a HINT: use it when present, otherwise
        find the scan by looking up the project's newest scan created at/after
        the moment we triggered. Either way we end up with a real id AND the
        scan's actual status.

        Returns (scan_id, status); (None, None) if no scan record turned up.
        """
        if hinted_scan_id and hinted_scan_id != "unknown":
            status = self._scan_status_by_id(hinted_scan_id)
            if status:
                return hinted_scan_id, status
            self.logger.debug(
                "['%s'] trigger returned id %s but it did not resolve; "
                "falling back to lookup.", project_name, hinted_scan_id)

        cutoff = triggered_at - timedelta(seconds=_CONFIRM_SKEW_S)
        for attempt in range(_CONFIRM_ATTEMPTS):
            try:
                data = self.api.get("scans", params={
                    "project-id": project_id, "sort": "-created_at", "limit": 5,
                }) or {}
            except Exception as exc:
                self.logger.debug("['%s'] scan lookup failed (attempt %d): %s",
                                  project_name, attempt + 1, exc)
                data = {}
            for scan in (data.get("scans") or []):
                created = _parse_iso_utc(scan.get("createdAt"))
                if created and created >= cutoff and scan.get("id"):
                    return scan["id"], scan.get("status")
            if attempt < _CONFIRM_ATTEMPTS - 1:
                time.sleep(_CONFIRM_BACKOFF_S)
        return None, None

    def _finalize_trigger(self, project_name: str, project_id: str,
                          hinted_scan_id: str | None, branch: str,
                          config_changes: str | None,
                          triggered_at: datetime) -> dict:
        """Confirm a successfully-issued trigger and build its result record.

        Reached only when the POST did NOT raise — an explicit trigger failure
        returns earlier. From here the question is no longer 'did the call
        work' but 'which scan did it create and what is that scan doing'.
        """
        scan_id, status = self._confirm_scan(
            project_name, project_id, triggered_at, hinted_scan_id)

        if not scan_id:
            # Accepted, but no scan record surfaced in the confirmation window.
            self.logger.warning(
                "Scan for '%s' was accepted but no matching scan record appeared "
                "within %.0fs. It may still be materializing — check "
                "`scan status --projects \"%s\"`.",
                project_name, _CONFIRM_ATTEMPTS * _CONFIRM_BACKOFF_S, project_name)
            res = self._trigger_result(project_name, project_id, "unknown",
                                       branch, config_changes)
            res["uncertain"] = True
            return res

        res = self._trigger_result(project_name, project_id, scan_id,
                                   branch, config_changes)
        res["status"] = status or "Unknown"
        if (status or "").lower() in UNSUCCESSFUL_SCAN_STATUSES:
            # The trigger worked; the scan itself is not a clean success. Surface
            # that distinctly instead of burying it under a check mark.
            res["scan_unsuccessful"] = True
            self.logger.warning("Scan for '%s' — id=%s status=%s",
                                project_name, scan_id, status)
        else:
            self.logger.info("Scan for '%s' confirmed — id=%s status=%s",
                             project_name, scan_id, status)
        return res

    @staticmethod
    def _format_config_changes(preset_name: str | None, incremental_bool: bool | None) -> str:
        """Format only the keys that are actually changing for summary display."""
        parts = []
        if preset_name:
            parts.append("preset set to %s" % preset_name)
        if incremental_bool is not None:
            parts.append("incremental set to %s" % incremental_bool)
        return ", ".join(parts)

    def _apply_project_config_overrides(
        self,
        project_id: str,
        project_name: str,
        preset_name: str | None,
        incremental_bool: bool | None,
    ) -> bool:
        """
        PATCH project configuration for SAST preset and/or incremental when overrides rolled.
        Returns True if PATCH succeeded (or nothing to do).
        """
        if not preset_name and incremental_bool is None:
            return True
        raw = self.api.get_project_configuration(project_id)
        if not isinstance(raw, list):
            self.logger.warning("Could not get project configuration for '%s'.", project_name)
            return False
        updates = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            key = item.get("key")
            if key == self._SAST_PRESET_KEY and preset_name:
                up = dict(item)
                up["value"] = preset_name
                up["originLevel"] = "Project"
                updates.append(up)
                self.logger.debug(
                    "Project config updated for '%s': preset=%s",
                    project_name, preset_name,
                )
            elif key == self._SAST_INCREMENTAL_KEY and incremental_bool is not None:
                up = dict(item)
                up["value"] = "true" if incremental_bool else "false"
                up["originLevel"] = "Project"
                updates.append(up)
                self.logger.debug(
                    "Project config updated for '%s': incremental=%s",
                    project_name, incremental_bool,
                )
        if not updates:
            if preset_name:
                self.logger.warning(
                    "Preset param '%s' not found for project '%s'; skipping.",
                    self._SAST_PRESET_KEY, project_name,
                )
            return not preset_name  # ok if only incremental was missing
        try:
            self.api.patch_project_configuration(project_id, updates)
            return True
        except Exception as exc:
            self.logger.error(
                "Failed to update project config for '%s': %s",
                project_name, exc,
            )
            return False

    def _get_sast_preset_and_incremental(self, config_array: list[dict]) -> tuple[str | None, bool | None]:
        """Get presetName and incremental from SAST entry. Reads short keys (from overrides) and API long keys (scan.config.sast.*)."""
        for item in config_array:
            if (item.get("type") or "").lower() != "sast":
                continue
            value = item.get("value") or {}
            preset = (
                (value.get("presetName") or value.get(self._SAST_PRESET_KEY) or "").strip()
                or None
            )
            inc = value.get("incremental") or value.get(self._SAST_INCREMENTAL_KEY)
            if inc is None:
                incremental_bool = None
            else:
                incremental_bool = str(inc).lower() in ("true", "1", "yes")
            return (preset, incremental_bool)
        return (None, None)

    def _config_array_to_scm_scanner_types(self, config_array: list[dict]) -> list[str]:
        """
        Map config array (type + value) to SCM projectScan scannerTypes.
        Microengines expand to '2ms' (secret detection) and 'scorecard' per API spec.
        """
        out: list[str] = []
        for c in config_array:
            t = str(c.get("type", "")).lower()
            if not t:
                continue
            if t == "microengines":
                out.append("2ms")
                out.append("scorecard")
            else:
                out.append(t)
        return out

    def _engine_list_to_scm_scanner_types(self, engines: list) -> list[str]:
        """Map scan_rules.engines list to SCM scannerTypes (microengines -> 2ms, scorecard)."""
        out: list[str] = []
        for e in engines:
            t = str(e).lower()
            if not t:
                continue
            if t == "microengines":
                out.append("2ms")
                out.append("scorecard")
            else:
                out.append(t)
        return out

    def _parse_repo_org(self, repo_url: str, scm_type: str) -> str:
        """Extract org/group from repo URL (e.g. GitHub org); else 'anyorg'."""
        if not repo_url or not repo_url.strip():
            return "anyorg"
        try:
            parsed = urlparse(repo_url.strip())
            path = (parsed.path or "").strip("/")
            parts = [p for p in path.split("/") if p and p != ".git"]
            if parts:
                return parts[0]
        except Exception:
            pass
        return "anyorg"

    def _extract_scan_id_from_response(self, response: dict | None) -> str:
        """Best-effort scan id from a trigger response — a HINT, not the source
        of truth. Tries common inline keys, one level of nesting, then the REST
        Location URL (`_location`/`location`/`Location`, id = last path segment).

        Returning 'unknown' is NORMAL, not a fault: the SCM `projectScan`
        endpoint answers with an empty body and no Location header, so there is
        no id to find (live-verified — every SCM scan hits this path). Callers
        resolve the real id via _confirm_scan(), so this logs at DEBUG only.
        """
        def _probe(d: dict) -> str | None:
            for key in ("id", "scanId", "scan_id"):
                val = d.get(key)
                if val and isinstance(val, str):
                    return val
            return None

        if isinstance(response, dict):
            found = _probe(response)
            if found:
                return found
            for nest in ("scan", "data"):
                obj = response.get(nest)
                if isinstance(obj, dict):
                    found = _probe(obj)
                    if found:
                        return found
            # REST 201-Created pattern: the trigger returns a Location URL for the
            # created scan (seen as `_location` / `location` / `Location`) rather
            # than an inline id, e.g. ".../scans/{scanId}". Pull the id off the end.
            for loc_key in ("_location", "location", "Location"):
                loc = response.get(loc_key)
                if loc and isinstance(loc, str):
                    # Strip any query/fragment, take the last non-empty path segment.
                    path = loc.split("?", 1)[0].split("#", 1)[0].rstrip("/")
                    seg = path.rsplit("/", 1)[-1]
                    if seg:
                        return seg
        self.logger.debug(
            "No scan id in the trigger response (keys: %s) — expected for the SCM "
            "endpoint; resolving it from the project's scan list instead.",
            sorted(response.keys()) if isinstance(response, dict) else type(response).__name__)
        return "unknown"

    def _trigger_scan_manual(
        self, project: dict, project_name: str, project_id: str
    ) -> dict | None:
        """Trigger scan via POST /scans (manual/clone-URL project). Branch and repo from latest scan or project."""
        repo_url: str | None = None
        branch: str | None = None
        self.logger.debug(
            "['%s'] Getting latest scan (branch/repo): GET scans",
            project_name,
        )
        latest_scan = self.api.get_latest_scan_for_project(project_id)
        if latest_scan:
            branch, repo_url = self._get_branch_and_repo_from_scan(latest_scan)
            if latest_scan.get("projectName"):
                project_name = latest_scan["projectName"]

        if not repo_url:
            repo_url = self._get_project_repo_url(project)
            if not branch:
                branch = project.get("mainBranch")

        if not repo_url:
            self.logger.warning(
                "Skipping '%s': manual project with no repository URL (no previous repo-based scan and no repoUrl on project).",
                project_name,
            )
            return None

        branch = (branch or "main").strip()
        branch_display = branch or "main"

        self.logger.debug(
            "Scan project (manual): name=%s id=%s branch=%s repoUrl=%s",
            project_name, project_id, branch, repo_url,
        )

        # 1) Resolve effective config + overrides (shared with the SCM path).
        # The manual POST /scans body carries the config array, so a missing
        # config is fatal here (the SCM path can fall back; this one can't).
        resolved = self._resolve_config_updates(project_id, project_name)
        if not resolved:
            self.logger.error(
                "Could not retrieve scan config for '%s'.", project_name
            )
            return None
        config_array, to_patch_preset, to_patch_inc, config_changes = resolved

        # 2) PATCH only when something actually changed (live runs only)
        if not self._patch_config_if_needed(project_id, project_name,
                                            to_patch_preset, to_patch_inc):
            return None

        # 3) Scan request
        config_for_request = self._sanitize_config_for_scans(config_array)

        payload = {
            "project": {"id": project_id},
            "type": "git",
            "handler": {
                "branch": branch,
                "repoUrl": repo_url,
            },
            "config": config_for_request,
        }

        if _LOG_FULL_API_BODIES:
            self.logger.debug(
                "Scan request payload (manual) for '%s':\n%s",
                project_name, json.dumps(payload, indent=2),
            )
        else:
            self.logger.debug("Scan request (manual) for '%s'", project_name)

        if self.config.dry_run:
            self.logger.debug(
                "[DRY-RUN] Would trigger scan for '%s' (branch: %s, engines: %s)",
                project_name,
                branch_display,
                [c.get("type") for c in config_for_request],
            )
            return self._trigger_result(project_name, project_id, "DRY-RUN",
                                        branch_display, config_changes)

        # Step 1 — issue the trigger. A raised exception is the ONLY explicit
        # failure signal here; anything else moves on to confirmation.
        triggered_at = datetime.now(timezone.utc)
        try:
            response = self.api.post("scans", json_body=payload)
        except Exception as exc:
            self.logger.error("Failed to trigger scan for '%s': %s", project_name, exc)
            return None

        # Step 2 — confirm. This endpoint DOES return an id, so the hint is
        # normally populated; it's still verified (and its status read) through
        # the same path the SCM route uses.
        self.logger.debug("Scan triggered for '%s' — branch=%s", project_name, branch_display)
        return self._finalize_trigger(
            project_name, project_id,
            self._extract_scan_id_from_response(response),
            branch_display, config_changes, triggered_at,
        )

    def _fetch_project(self, project_id: str) -> dict | None:
        try:
            return self.api.get(f"projects/{project_id}")
        except Exception:
            return None

    def _get_effective_scan_config(
        self, project_id: str, project_name: str
    ) -> tuple[list[dict], str | None, bool | None] | None:
        """
        GET project config, apply scan_rules (engines + overrides), and return
        (config_array, current_preset, current_incremental). Current values are
        read before overrides so callers can PATCH only when rolled value differs.
        """
        self.logger.debug(
            "['%s'] Getting current config: GET configuration/project",
            project_name,
        )
        try:
            raw_config = self.api.get(
                "configuration/project", params={"project-id": project_id}
            )
        except Exception as exc:
            self.logger.debug(
                "Could not retrieve scan config for '%s': %s", project_name, exc
            )
            return None
        config_array = self._build_config_array(raw_config)
        config_array = self._filter_engines(config_array)
        current_preset, current_inc = self._get_sast_preset_and_incremental(config_array)
        config_array = self._apply_overrides(config_array, project_name)
        return (config_array, current_preset, current_inc)

    def _get_branch_and_repo_from_scan(self, scan: dict) -> tuple[str | None, str | None]:
        """
        Extract branch and repo URL from a GET /api/scans scan object.

        Branch is at top level; repo_url is in metadata.Handler.GitHandler.repo_url
        (casing may vary: Handler/GitHandler or handler/gitHandler).
        """
        branch = (scan.get("branch") or "").strip() or None
        meta = scan.get("metadata") or {}
        handler = meta.get("Handler") or meta.get("handler") or {}
        git_handler = handler.get("GitHandler") or handler.get("gitHandler") or {}
        repo_url = (git_handler.get("repo_url") or git_handler.get("repoUrl") or "").strip() or None
        return branch, repo_url

    def _get_project_repo_url(self, project: dict) -> str | None:
        """Return the project's Git repository URL (required for POST /api/scans type=git)."""
        url = project.get("repoUrl") or project.get("repositoryUrl")
        if url and isinstance(url, str) and url.strip():
            return url.strip()
        repo = project.get("repository")
        if isinstance(repo, dict):
            url = repo.get("url") or repo.get("repoUrl")
            if url and isinstance(url, str) and url.strip():
                return url.strip()
        return None

    # ------------------------------------------------------------------
    # Config conversion and overrides
    # ------------------------------------------------------------------

    def _sanitize_config_for_scans(self, config_array: list[dict]) -> list[dict]:
        """
        Remove empty string values from each scanner's value dict.
        For SAST, omit presetName and incremental (handled via project config).
        """
        result = []
        for item in config_array:
            value = item.get("value") or {}
            if not isinstance(value, dict):
                result.append(item)
                continue
            sanitized = {
                k: v for k, v in value.items()
                if v is not None and str(v).strip() != ""
            }
            if (item.get("type") or "").lower() == "sast":
                sanitized.pop("presetName", None)
                sanitized.pop("incremental", None)
            result.append({"type": item.get("type", ""), "value": sanitized})
        return result

    def _build_config_array(self, raw_config: Any) -> list[dict]:
        """
        Convert the /api/configuration/project response into a scan config array.

        The API returns a flat list of {category, name, value} items.
        We group them by category (engine type) to form:
            [{type: engine, value: {setting_name: setting_value, ...}}, ...]
        """
        scanner_configs: dict[str, dict] = {}

        items = raw_config if isinstance(raw_config, list) else []
        for item in items:
            category = item.get("category", "").lower()
            name = item.get("name")
            value = item.get("value")
            if category and name and value is not None:
                scanner_configs.setdefault(category, {})[name] = value

        return [
            {"type": engine, "value": settings}
            for engine, settings in scanner_configs.items()
            if engine and settings
        ]

    def _filter_engines(self, config_array: list[dict]) -> list[dict]:
        """Keep only engines listed in scanRules.engines; add missing ones with empty config.
        When engines is empty, default to all scanner types (sast, sca, kics, apisec, containers, microengines)."""
        engines = self._scan_rules.get("engines", [])
        enabled_engines = [str(e).lower() for e in engines if e]
        if not enabled_engines:
            enabled_engines = ALL_SCANNER_TYPES.copy()

        existing = {item["type"].lower(): item for item in config_array}
        result = []
        for engine in enabled_engines:
            item = existing.get(engine, {"type": engine, "value": {}})
            if engine == "microengines":
                # Secret detection (2ms) analyzes the cloned source, so it runs on
                # manual / clone-URL projects too — not just SCM-imported ones. The
                # project config ships these settings empty (stripped before send),
                # so we explicitly enable 2ms whenever microengines is requested.
                # Scorecard needs an SCM integration (repo/PR metadata via a token);
                # the SCM scan path enables it via scannerTypes, so we don't force it
                # on here and risk a partial failure on a plain clone.
                val = item.get("value")
                val = dict(val) if isinstance(val, dict) else {}
                val["2ms"] = "true"
                item = {"type": "microengines", "value": val}
            result.append(item)
        return result

    def _apply_overrides(self, config_array: list[dict], project_name: str = "") -> list[dict]:
        """
        Apply weighted single-roll overrides from scan_rules.overrides.

        For each setting, one roll 1–100 is made (thread-safe RNG). Outcomes are
        cumulative bands: roll in [1, p1] → first outcome, (p1, p1+p2] → second, etc.
        If the roll exceeds the sum of all outcome percentages, no override is applied.
        """
        # Deterministic path: caller pinned a preset and asked us not to re-roll.
        # Return the config untouched — no roll, no log — so the pinned value survives.
        if self._no_overrides:
            return config_array
        for override in self._scan_rules.get("overrides", []):
            setting = override.get("setting")
            outcomes = override.get("outcomes")
            if not setting or not outcomes:
                continue

            setting_lower = str(setting).lower().replace("_", "")
            current = None
            for item in config_array:
                if (item.get("type") or "").lower() != "sast":
                    continue
                value = item.get("value") or {}
                if setting_lower == "sastpreset":
                    current = (
                        (value.get("presetName") or value.get(self._SAST_PRESET_KEY) or "").strip()
                        or None
                    )
                elif setting_lower == "incremental":
                    inc = value.get("incremental") or value.get(self._SAST_INCREMENTAL_KEY)
                    current = None if inc is None else (str(inc).lower() in ("true", "1", "yes"))
                break
            current_display = current if current is not None else "(not set)"

            # Reproducible roll: derive a per-(seed, project, setting) RNG so a
            # dry-run and live run under the same seed roll identically, while each
            # project/setting stays independent. Falls back to the non-deterministic
            # system RNG only if no seed was set.
            if getattr(self, "_seed", None) is not None:
                import hashlib
                key = "|".join((str(self._seed), "override", project_name or "", str(setting)))
                digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
                roll = random.Random(int(digest[:16], 16)).randint(1, 100)
            else:
                roll = _override_rng.randint(1, 100)
            cumulative = 0
            chosen = None
            for outcome in outcomes:
                pct = int(outcome.get("percentage", 0))
                cumulative += pct
                if roll <= cumulative:
                    chosen = outcome.get("value")
                    break

            if project_name:
                self.logger.debug(
                    "Override roll for '%s': setting=%s current=%s roll=%d",
                    project_name, setting, current_display, roll,
                )
            else:
                self.logger.debug(
                    "Override roll: setting=%s current=%s roll=%d",
                    setting, current_display, roll,
                )
            if chosen is not None:
                change_display = str(chosen).lower() if isinstance(chosen, bool) else chosen
                if project_name:
                    self.logger.debug(
                        "Override for '%s': %s -> %s",
                        project_name, setting, change_display,
                    )
                else:
                    self.logger.debug("Override: %s -> %s", setting, change_display)
            else:
                if project_name:
                    self.logger.debug(
                        "Override for '%s': %s no change (roll > band)",
                        project_name, setting,
                    )
                else:
                    self.logger.debug("Override: %s no change (roll > band)", setting)

            if chosen is None:
                continue

            if setting_lower == "sastpreset":
                for item in config_array:
                    if item.get("type", "").lower() == "sast":
                        item["value"]["presetName"] = chosen
                        break
            elif setting_lower == "incremental":
                for item in config_array:
                    if item.get("type", "").lower() == "sast":
                        item["value"]["incremental"] = str(chosen).lower()
                        break
            else:
                self.logger.warning("Unknown scan override setting: '%s'", setting)

        return config_array

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def _print_summary(self, successful: list[dict], failed: list,
                       skipped: list | None = None) -> None:
        skipped = skipped or []
        dry = getattr(self.config, "dry_run", False)
        self.logger.info("=" * 60)
        if dry:
            self.logger.info("Dry run — would scan %d project(s)", len(successful) + len(failed))
        else:
            self.logger.info("Scan Summary")
        self.logger.info("=" * 60)

        for s in successful:
            if s.get("uncertain"):
                # Triggered, but no scan record surfaced during confirmation.
                line = ("  ~ '%s' — triggered, but no scan record found yet; "
                        "verify with `scan status`" % s["project_name"])
                if s.get("config_changes"):
                    line += " (%s)" % s["config_changes"]
                self.logger.warning(line)
                continue
            # Confirmed: we hold a real scan id and its status, on both routes.
            marker = "✗" if s.get("scan_unsuccessful") else "✓"
            line = "  %s '%s'" % (marker, s["project_name"])
            if s.get("status"):
                line += " — %s" % s["status"]
            if s.get("scan_id") and s["scan_id"] not in ("unknown", "DRY-RUN"):
                line += " [%s]" % s["scan_id"]
            if s.get("config_changes"):
                line += " (%s)" % s["config_changes"]
            if s.get("scan_unsuccessful"):
                self.logger.warning(line)
            else:
                self.logger.info(line)
        for s in skipped:
            self.logger.info("  ⊘ '%s' — skipped (%s)",
                             s.get("project_name", "?"), s.get("reason", "duplicate"))
        for f in failed:
            name = f.get("name", f) if isinstance(f, dict) else f
            reason = f.get("reason", "Scan failed") if isinstance(f, dict) else "Scan failed"
            self.logger.warning("  ✗ '%s' — %s", name, reason)

        if dry and successful:
            # A dry-run resolves a concrete set — including randomized (`--auto`)
            # selections. The live run must scan THIS set, not re-roll: re-invoking
            # `--auto` would pick a different random subset. Emit a ready-to-use
            # command that pins the previewed names so the confirmed set is exactly
            # what executes.
            names = [s["project_name"] for s in successful if s.get("project_name")]
            if names:
                joined = ",".join(names)
                self.logger.info("-" * 60)
                self.logger.info(
                    "To execute exactly these %d project(s), run WITHOUT --dry-run "
                    "and pin the names (do NOT re-use --auto — it re-rolls):",
                    len(names),
                )
                self.logger.info('  scan --project-names "%s"', joined)

        if not successful and not skipped and failed:
            raise SystemExit(1)
