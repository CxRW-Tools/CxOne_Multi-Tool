#!/usr/bin/env python3
"""
Checkmarx One Multi-Tool — unified entry point.

One command surface over every capability. Each top-level verb forwards its
remaining arguments to the relevant module, so per-module help works too:

    python multitool.py iam create-user --username ... --email ...
    python multitool.py app create --name "Acme Banking" --project-tag app:banking
    python multitool.py project github --org myorg --repos WebGoat,juice-shop
    python multitool.py scanconfig set <project-id> --preset "ASA Premium"
    python multitool.py scan --auto --percentage 20
    python multitool.py triage-simulate --projects "Acme" --scan-types sast,iac,sca
    python multitool.py triage-real prepare --project "Acme" --match "SQL Injection"
    python multitool.py ai-assist find --project "Acme" --match "SQL Injection"
    python multitool.py provision --blueprint blueprints/example-tenant.yaml --dry-run
    python multitool.py purge --dry-run

Global flags (--env / --dry-run / --debug) go right after the verb, BEFORE any
subcommand: `project --dry-run create-manual ...` works; placing --dry-run after
the subcommand fails on verbs that have subcommands (iam/app/project/scanconfig/env).
Run `python multitool.py <verb> --help` for verb-specific options.
"""

from __future__ import annotations

import sys
import logging
import argparse


def _ensure_utf8_console() -> None:
    """Make stdout/stderr tolerate the banner's Unicode on legacy consoles.

    The welcome banner uses box-drawing, bullets, a checkmark, a warning sign,
    and arrows (U+2554/U+2550, U+2022, U+2713, U+26A0, U+2192). On a Windows
    console defaulting to cp1252 these raise UnicodeEncodeError on print().
    Prefer real UTF-8 where the terminal supports it; otherwise fall back to
    replacing unencodable chars so output degrades instead of crashing.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8")
        except (ValueError, OSError):
            try:
                reconfigure(errors="replace")
            except (ValueError, OSError):
                pass


_ensure_utf8_console()


def _freshness_line(*, indent: str = "") -> str | None:
    """Format the 'reference spec last synced' line for version displays, or
    None if spec/LAST_SYNCED isn't found. Flags a refresh suggestion past
    STALE_REFERENCE_DAYS — the platform's API surface (enums, required fields)
    can drift from our bundled spec/docs between syncs; see
    references/api-index.md 'Where to look' for how to re-check the live spec."""
    from cxone import get_reference_freshness, STALE_REFERENCE_DAYS
    date_str, days_ago = get_reference_freshness()
    if date_str is None:
        return None
    if days_ago is None:
        return f"{indent}Reference spec last synced: {date_str}"
    line = f"{indent}Reference spec last synced: {date_str} ({days_ago} day{'s' if days_ago != 1 else ''} ago)"
    if days_ago > STALE_REFERENCE_DAYS:
        line += (f"\n{indent}⚠ That's over {STALE_REFERENCE_DAYS} days — the live platform API may have "
                 f"drifted since. Consider asking to refresh the live-spec sync "
                 f"(see references/api-index.md \"Where to look\").")
    return line


def _emit_update_notice() -> None:
    """THE update check. One call site, on every command (see main()).

    Deliberately the only automatic trigger: `welcome` used to run its own copy,
    which meant two places could disagree about when a check happened. The
    `selfcheck` verb and publish_skill's preflight still call into selfcheck,
    but those are explicit, synchronous, blocking uses — a different policy over
    the same implementation, not a second scattered trigger.

    Cache read only; the refresh happens on a background thread inside
    selfcheck, so no command ever waits on git. Goes to stderr so it can never
    corrupt parseable stdout, and swallows everything: an advisory notice must
    never break a tenant operation.
    """
    try:
        import selfcheck
        line = selfcheck.ambient_notice()
        if line:
            print(line, file=sys.stderr)
    except Exception:                                     # noqa: BLE001
        pass


def _welcome_entry(argv: list[str]) -> int:
    import os as _os
    import config_setup as cs
    from cxone import default_env_file, is_inside_skill_dir, get_version
    p = argparse.ArgumentParser(prog="multitool welcome")
    p.add_argument("--env", default=None)
    a = p.parse_args(argv)
    env_path = a.env or default_env_file()

    print(WELCOME)
    print(f"\n  Version: {get_version()}")
    freshness = _freshness_line(indent="  ")
    if freshness:
        print(freshness)
    # Same read guard as CxConfig.from_env: never present credentials found inside
    # the skill's own directory as the "active tenant" — that file is shared across
    # chats and may be stale, which is exactly the wrong-tenant trap.
    if _os.path.isfile(env_path) and is_inside_skill_dir(env_path):
        print("\nStatus")
        print(f"  \u26a0 Found a credentials file INSIDE the skill directory: {env_path}")
        print("  Refusing to use it — that location is shared across chats and may be")
        print("  stale, so trusting it risks operating on the wrong tenant.")
        print("  Fix: delete that file, set CXONE_ENV_FILE=<project-dir>/cxone.env,")
        print("  and run `env init --api-key <KEY>` to configure your tenant properly.")
        print("\n  New here or want a refresher? Ask me to \"open the overview\" for a")
        print("  guided tour of what this does and how to use it safely.")
        return 2
    data = cs.read_env_file(env_path)
    tenant = data.get("CXONE_TENANT")
    base = data.get("CXONE_BASE_URL")
    print("\nStatus")
    if tenant and base and data.get("CXONE_API_KEY"):
        print(f"  \u2713 Active tenant: \"{tenant}\" ({base}).")
        print(f"    Config source: {env_path}")
        print("  This skill works with ONE tenant at a time. Every command below acts")
        print(f"    on \"{tenant}\". If that isn't the tenant you mean to work on, stop and")
        print("    reconfigure (`env init`) before running anything — don't operate on two")
        print("    tenants in parallel.")
        print("  Tip: ask for a dry-run of anything before you run it live.")
    else:
        print("  \u26a0 No tenant configured yet.")
        print(f"    (Looked in: {env_path})")
        print("  To begin, share your Checkmarx One API key. It's a refresh token, so")
        print("  I'll read your tenant and region from it and confirm before saving —")
        print("  no URLs to look up. (Checkmarx One \u2192 Settings \u2192 Identity and Access")
        print("  Management \u2192 API Keys.)")
        print("  This skill works with ONE tenant at a time; configure the one you")
        print("  intend to work on, and start a separate session to switch tenants.")
    print("\n  New here or want a refresher? Ask me to \"open the overview\" for a")
    print("  guided tour of what this does and how to use it safely.")
    return 0


def _effective_seed(seed: int | None) -> int:
    """The seed the run will actually use, decided BEFORE identity selection.

    The operations generate a seed when given none, and print it as the value to
    replay with. Identity selection used to happen earlier, on the raw (possibly
    None) seed — so an unseeded dry-run picked its people from an UNSEEDED
    Random, and re-running with the printed seed reproduced the findings while
    re-rolling the identities. Deciding it here makes the printed seed cover both.
    """
    if seed is not None:
        return int(seed)
    import random as _random
    return _random.SystemRandom().randint(0, 2**31 - 1)


def _resolve_identity(cfg, as_spec: str | None, kind: str, key: str,
                      seed: int | None):
    """Map an --as value to (api client, acting name, per-project selector).

    (None, None, None) -> the runner builds the default primary client and prints
    nothing, keeping single-identity runs byte-identical.

    For the AUTOMATIC specs (auto/random, ±secondary) the third element is an
    IdentitySelector and the first two are None: the identity is chosen per
    project inside the run, not once for the whole invocation. An explicit name
    (`--as alice`) pins one client, because that is what the user asked for.
    Selection is seeded so a dry-run's 'as X' is the live run's 'as X'.
    """
    if not as_spec:
        return None, None, None
    import random as _random
    from cxone.identity_pool import IdentityPool
    pool = IdentityPool(cfg)
    if as_spec in ("random", "auto") and not pool.has_secondaries():
        # Soft fallback for the INCLUSIVE specs only: with no secondaries the
        # honest pool is just the primary, so act as primary and say so. The
        # -secondary variants are an explicit "not the admin" and instead fail
        # loudly inside resolve() below.
        logging.getLogger("cxone").info(
            "No secondary identities configured (%s missing or empty) — "
            "acting as primary.", pool.sidecar_path() or "identities file")
        return None, None, None
    selector = pool.selector(as_spec, kind, seed)
    if selector is not None:
        # Validate the spec now so a bad one fails before any work starts, rather
        # than inside a worker thread on the first project.
        try:
            pool.resolve(as_spec, kind, key, _random.Random(seed))
        except (KeyError, ValueError) as exc:
            print(f"error: {exc.args[0]}", file=sys.stderr)
            raise SystemExit(2)
        return None, None, selector
    try:
        name = pool.resolve(as_spec, kind, key, _random.Random(seed))
    except (KeyError, ValueError) as exc:
        print(f"error: {exc.args[0]}", file=sys.stderr)
        raise SystemExit(2)
    return pool.client_for(name), name, None


def _scan_entry(argv: list[str]) -> int:
    from cxone import CxConfig
    # Optional read-only subcommands share the `scan` verb: `scan status`,
    # `scan history`. Anything else is the (flag-based) trigger path, so
    # `scan --project-names ...` stays backward-compatible.
    if argv and argv[0] in ("status", "history"):
        return _scan_query_entry(argv[0], argv[1:])

    from ops.run import run_scan
    p = argparse.ArgumentParser(prog="multitool scan")
    p.add_argument("--env", default=None); p.add_argument("--dry-run", action="store_true")
    p.add_argument("--debug", action="store_true")
    grp = p.add_mutually_exclusive_group()
    grp.add_argument("--project-names"); grp.add_argument("--project-ids")
    grp.add_argument("--auto", action="store_true")
    p.add_argument("--percentage", type=int, default=20)
    p.add_argument("--min-projects", type=int, default=2)
    p.add_argument("--force", action="store_true",
                   help="scan even if a Queued/Running scan already exists for the project")
    p.add_argument("--no-overrides", action="store_true",
                   help="skip the weighted preset/incremental randomizer for this run "
                        "(use when a preset was just pinned via `scanconfig set`)")
    p.add_argument("--seed", type=int, default=None,
                   help="reproduce a prior run's random project selection and override "
                        "rolls (the dry-run prints the seed it used)")
    p.add_argument("--as", dest="as_identity", default=None, metavar="IDENTITY",
                   help="act as this identity from cxone-identities.yaml; 'random'/'auto' "
                        "pick over ALL identities (seeded random / stable "
                        "per-project affinity); 'random-secondary'/'auto-secondary' "
                        "do the same EXCLUDING the primary/admin key; default: primary")
    a = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.debug else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = CxConfig.from_env(a.env); cfg.dry_run = cfg.dry_run or a.dry_run
    seed = _effective_seed(a.seed)
    api, acting, selector = _resolve_identity(
        cfg, a.as_identity, "scan",
        a.project_names or a.project_ids or "auto", seed)
    run_scan(cfg, project_names=a.project_names, project_ids=a.project_ids,
             auto=a.auto, percentage=a.percentage, min_projects=a.min_projects,
             force=a.force, no_overrides=a.no_overrides, seed=seed,
             api=api, acting_as=acting, identity_selector=selector)
    return 0


def _scan_query_entry(sub: str, argv: list[str]) -> int:
    from cxone import CxConfig
    from ops import scan_status as ss
    p = argparse.ArgumentParser(prog=f"multitool scan {sub}")
    p.add_argument("--env", default=None); p.add_argument("--debug", action="store_true")
    if sub == "status":
        p.add_argument("--project-names", default=None,
                       help="comma-separated; omit for all projects")
    elif sub == "history":
        p.add_argument("--project", required=True)
        p.add_argument("--limit", type=int, default=10)
    a = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.debug else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = CxConfig.from_env(a.env)
    if sub == "status":
        names = [n.strip() for n in (a.project_names or "").split(",") if n.strip()] or None
        return ss.scan_status(cfg, names)
    if sub == "history":
        return ss.scan_history(cfg, a.project, a.limit)
    return 0


def _deprecated_triage_entry(argv: list[str]) -> int:
    """`triage` used to mean the simulated one. Keep it working, but say so.

    Renamed in 3.27.0 because a bare "triage" could no longer distinguish three
    very different actions. The alias stays so existing scripts don't break;
    it forwards to triage-simulate after a loud warning.
    """
    print("WARNING: `triage` is deprecated and now means `triage-simulate` "
          "(fabricated states for demo realism).\n"
          "         Did you want one of:\n"
          "           triage-simulate   invented states + canned comments (free)\n"
          "           triage-real       this assistant reviews your actual code (free)\n"
          "           ai-assist triage  Checkmarx AI Triage Assist (spends credits)\n",
          file=sys.stderr)
    return _triage_entry(argv)


def _triage_entry(argv: list[str]) -> int:
    from cxone import CxConfig
    from ops.run import run_triage
    p = argparse.ArgumentParser(prog="multitool triage")
    p.add_argument("--env", default=None); p.add_argument("--dry-run", action="store_true")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--projects", required=True)
    p.add_argument("--scan-types", required=True, help="comma-separated: sast,iac,sca,secrets,containers")
    p.add_argument("--rules-file", default=None)
    p.add_argument("--intensity", default="moderate",
                   choices=["light", "some", "moderate", "thorough", "heavy"],
                   help="how thoroughly a realistic team triages (maps fuzzy asks "
                        "like 'triage some' -> some, 'triage everything' -> thorough; "
                        "'heavy' = work through the backlog: strongest coverage but "
                        "hard-capped at a human day's decisions per project per pass)")
    p.add_argument("--seed", type=int, default=None,
                   help="reproduce a prior run's exact triage selection (the dry-run "
                        "prints the seed it used; pass it here for the live run)")
    p.add_argument("--as", dest="as_identity", default=None, metavar="IDENTITY",
                   help="act as this identity from cxone-identities.yaml; 'random'/'auto' "
                        "pick over ALL identities (seeded random / stable "
                        "per-project affinity); 'random-secondary'/'auto-secondary' "
                        "do the same EXCLUDING the primary/admin key; default: primary")
    a = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.debug else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = CxConfig.from_env(a.env); cfg.dry_run = cfg.dry_run or a.dry_run
    seed = _effective_seed(a.seed)
    api, acting, selector = _resolve_identity(cfg, a.as_identity, "triage",
                                              a.projects, seed)
    run_triage(cfg, projects=a.projects, scan_types=a.scan_types,
               rules_file=a.rules_file, intensity=a.intensity, seed=seed,
               api=api, acting_as=acting, identity_selector=selector)
    return 0


# verb -> callable(argv) -> int
WELCOME = """\
\u2554\u2550\u2550 Checkmarx One Multi-Tool \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
Stand up and maintain realistic Checkmarx One demo / POV tenants, in plain language.

What it can do
  \u2022 Identity      users, groups, roles, memberships
  \u2022 Structure     applications + repo onboarding (GitHub; extensible to others)
  \u2022 Findings      run scans and apply realistic, \"lived-in\" triage
                 (severity- and engine-aware \u2014 not random rolls)
  \u2022 Whole tenant  apply a blueprint; ordered, confirmed teardown
  \u2022 Realism       a local UI, plus a timed agent that staggers activity over time

Best practices
  \u2022 One tenant per chat/project \u2014 keeps environments from getting crossed.
  \u2022 Dry-run first \u2014 you'll see the planned actions before anything changes.
  \u2022 Confirm bulk / destructive steps (onboarding many repos, teardown).
  \u2022 Let scans finish before triaging; preview agent plans before going live.

Just say what you want \u2014 e.g. \"stand up a demo tenant for Acme and make it look
lived-in\", or \"scan a few projects and triage some results over the next hour.\""""


def _dispatch():
    import iam, applications, onboard, scanconfig, purge, provision, export_blueprint, identities, ui, agent, envmgr, results, reports, workflows, ai_assist, triage_real, audit, selfcheck
    return {
        "iam": iam.main,
        "app": applications.main,
        "project": onboard.main,
        "onboard": onboard.main,
        "scanconfig": scanconfig.main,
        "scan": _scan_entry,
        "results": results.main,
        "report": reports.main,
        "audit": audit.main,
        "ai-assist": ai_assist.main,
        "assist": ai_assist.main,
        # Three distinct triage paths, named so they can never be confused:
        #   triage-simulate  fabricated states (dice + canned comments)
        #   triage-real      this assistant reviews the real code, then triages
        #   ai-assist triage Checkmarx's AI agent (spends credits)
        "triage-simulate": _triage_entry,
        "triage-real": triage_real.main,
        "triage": _deprecated_triage_entry,
        "provision": provision.main,
        "export": export_blueprint.main,
        "identities": identities.main,
        "quickstart": workflows.main,
        "purge": purge.main,
        "ui": ui.main,
        "agent": agent.main,
        "env": envmgr.main,
        "welcome": _welcome_entry,
        "start": _welcome_entry,
        "version": _version_entry,
        "selfcheck": selfcheck.main,
    }


def _version_entry(argv: list[str]) -> int:
    from cxone import get_version
    print(f"Checkmarx One Multi-Tool v{get_version()}")
    freshness = _freshness_line()
    if freshness:
        print(freshness)
    return 0


VERBS_HELP = """\
Verbs:
  iam         users, groups, roles, group membership
  app         applications (create/list/delete, tag-rule association)
  project     projects + repo onboarding (manual, github, ...)
  scanconfig  per-project SAST preset / incremental
  scan        trigger scans (by name/id or random %); also: scan status/history
  results     summarize / drill into findings (per project or per application)
  report      generate PDF/JSON/CSV scan reports and SBOMs
  audit       search/export tenant audit trail (who did what, when)
  triage-simulate  FABRICATED triage for demo realism (weighted rolls; free)
  triage-real      REAL review of your code by this assistant, then real triage
  ai-assist        Checkmarx Assist: AI Triage / Remediation (real; spends credits)
  provision   apply a full tenant blueprint (groups->users->apps->projects->config)
  export      export the live tenant TO a blueprint YAML (read-only inverse of provision)
  identities  list/test secondary identities used by --as (multi-user attribution)
  quickstart  apply a blueprint then scan + triage, in one command
  purge       tear down a tenant (ordered, confirmed)
  ui          launch the local web UI (auth + common actions)
  agent       real activity over real time — real scans + triage (run/plan)
  env         manage single-tenant credentials: derive/init/show/set
  welcome     concise overview, best practices, and credential status
  version     print the installed skill version
  selfcheck   is this checkout current with the published branch? (--sync to update)
"""


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in ("-v", "--version"):
        return _version_entry(argv[1:])
    if not argv or argv[0] in ("-h", "--help"):
        from cxone import get_version
        print(f"Checkmarx One Multi-Tool v{get_version()}")
        freshness = _freshness_line()
        if freshness:
            print(freshness)
        print(__doc__); print(VERBS_HELP)
        return 0
    verb, rest = argv[0], argv[1:]
    table = _dispatch()
    if verb not in table:
        print(f"Unknown verb '{verb}'.\n"); print(VERBS_HELP)
        return 2
    # Always surface the running version on every invocation (to stderr, so it
    # never pollutes parseable stdout). This makes the build identifiable no matter
    # which command runs — even if the assistant skips `welcome` — so "am I on the
    # latest version?" is answerable from any command's output. `version`/`welcome`
    # print it on stdout already, and `env` stamps its own output (derive/init/
    # show), so those skip the duplicate stderr line.
    if verb not in ("version", "welcome", "start", "env"):
        try:
            from cxone import get_version
            print(f"Checkmarx One Multi-Tool v{get_version()}", file=sys.stderr)
        except Exception:
            pass
    # Ambient "you're behind" notice — every verb except `selfcheck`, which
    # prints its own, fuller report and would otherwise say it twice.
    if verb != "selfcheck":
        _emit_update_notice()
    return table[verb](rest)


if __name__ == "__main__":
    sys.exit(main())
