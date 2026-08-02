"""
Composite workflows that chain several Multi-Tool steps into one invocation.

The point is approval-economy: a realistic standup is groups -> users -> apps ->
projects -> scan -> triage, which is a dozen separate calls (and prompts) done
one at a time. `quickstart` runs the whole sequence from a single blueprint in one
command, so the operator approves once.

It composes existing, separately-tested pieces (provision.apply_blueprint, the
scan and triage operations) rather than reimplementing them — so behavior matches
running each verb by hand. Dry-run propagates to every stage.
"""

from __future__ import annotations

import sys
import logging
import argparse
from pathlib import Path

from cxone import CxConfig, ApiClient

logger = logging.getLogger("cxone.workflows")


def quickstart(cfg: CxConfig, blueprint_path: str, *, scan_percentage: int | None = None,
               scan_projects: str | None = None, triage_intensity: str | None = None,
               triage_scan_types: str = "sast,sca,iac,secrets,containers",
               no_overrides: bool = False) -> int:
    """Apply a blueprint, then optionally scan and triage — one operation.

    - scan_projects: comma-separated names to scan; or scan_percentage for a random
      subset; if neither is given, scanning is skipped.
    - triage_intensity: if set, triage the scanned projects at that intensity after
      scans are submitted. (On a fresh tenant, triage of not-yet-finished scans is a
      natural no-op; pass a higher intensity once results exist.)
    """
    import yaml
    from provision import apply_blueprint
    from ops.run import run_scan, run_triage

    if not Path(blueprint_path).is_file():
        logger.error("Blueprint not found: %s", blueprint_path)
        return 1
    bp = yaml.safe_load(Path(blueprint_path).read_text(encoding="utf-8")) or {}

    api = ApiClient(cfg)
    logger.info("== Quickstart: applying blueprint '%s'%s ==",
                bp.get("tenant", {}).get("name", Path(blueprint_path).stem),
                " [DRY-RUN]" if cfg.dry_run else "")
    apply_blueprint(bp, api)

    # Determine projects to scan: explicit list, else the blueprint's project names.
    bp_names = [p.get("name") for p in bp.get("projects", []) if p.get("name")]
    names = scan_projects or (",".join(bp_names) if bp_names and scan_percentage is None else None)

    if names or scan_percentage is not None:
        logger.info("== Quickstart: scanning ==")
        run_scan(cfg, project_names=names,
                 auto=scan_percentage is not None,
                 percentage=scan_percentage or 20,
                 no_overrides=no_overrides)

    if triage_intensity:
        triage_targets = names or (",".join(bp_names) if bp_names else None)
        if triage_targets:
            logger.info("== Quickstart: triaging (%s) ==", triage_intensity)
            run_triage(cfg, projects=triage_targets, scan_types=triage_scan_types,
                       intensity=triage_intensity)
        else:
            logger.info("No projects to triage; skipping.")

    logger.info("Quickstart complete%s.", " (dry-run)" if cfg.dry_run else "")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="quickstart",
                                description="Apply a blueprint, then scan and triage in one go")
    p.add_argument("--blueprint", required=True)
    p.add_argument("--env", default=None)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--scan-projects", default=None,
                   help="comma-separated names to scan (default: all blueprint projects)")
    p.add_argument("--scan-percentage", type=int, default=None,
                   help="scan a random %% of projects instead of a named list")
    p.add_argument("--triage-intensity", default=None,
                   choices=["light", "some", "moderate", "thorough"],
                   help="triage after scanning at this intensity (omit to skip triage)")
    p.add_argument("--triage-scan-types", default="sast,sca,iac,secrets,containers")
    p.add_argument("--no-overrides", action="store_true",
                   help="skip the weighted preset/incremental randomizer during the "
                        "scan step (use when the blueprint pins exact presets)")
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = CxConfig.from_env(args.env)
    cfg.dry_run = cfg.dry_run or args.dry_run
    cfg.debug = cfg.debug or args.debug
    return quickstart(cfg, args.blueprint,
                      scan_percentage=args.scan_percentage,
                      scan_projects=args.scan_projects,
                      triage_intensity=args.triage_intensity,
                      triage_scan_types=args.triage_scan_types,
                      no_overrides=args.no_overrides)


if __name__ == "__main__":
    sys.exit(main())
