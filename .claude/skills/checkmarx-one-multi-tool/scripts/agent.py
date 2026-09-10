#!/usr/bin/env python3
"""
Activity agent — real tenant activity over real-world time.

Real tenants generate activity continuously, not in one batch. This agent runs a
realistic stream of REAL events (mostly scans, some triage, rare onboarding)
spread across business hours with jitter, so a demo tenant becomes genuinely
lived-in. There is no simulation mode and no time compression: if you want a few
days of activity, the agent runs for a few days and does the work.

IMPORTANT — what this is and isn't:
  * Claude is not a background daemon. This agent is YOUR local automation: you
    start it, it logs everything (each 24h window's full plan, then each event's
    execution, duration, and outcome), and you can stop it any time.
  * It only does constructive demo activity: scans, triage, and onboarding from an
    explicit allowlist. It never deletes/purges or makes destructive changes.
  * It defaults to DRY-RUN. Pass --live to actually act on the tenant. Hard caps
    (per hour, per day) bound volume.

Verbs (the only two):
  run    THE executor. Plans the next 24h internally, executes each event at its
         natural time, re-plans at the horizon, repeats until --until (then idles)
         or until stopped. Stale events (host asleep/down) are DROPPED, not
         replayed — a missed day becomes a quiet day, never a late burst.
         Substrate: if docker/podman is available you choose --container (durable,
         survives host sleep; recommended for multi-day runs) or --process; with
         no container runtime it runs as a long-lived process automatically.
  plan   Print the committed next-24h events plus a summary of the general
         behavior beyond (rate, business-hours weighting, end date). No execution,
         no invented future timestamps.

Examples:
  python multitool.py agent plan --until 2026-07-28
  python multitool.py agent run --live --until 2026-07-28 --container
  python multitool.py agent run --live --process          # no end date; stop manually
"""

from __future__ import annotations

import os
import sys
import json
import time
import signal
import random
import logging
import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import yaml

from cxone import CxConfig, ApiClient
from ops.activity import ActivityModel, Event, parse_window

logger = logging.getLogger("cxone.agent")

_CONFIG = Path(__file__).resolve().parent.parent / "config" / "activity.yaml"
# The agent's OWN private ledger of what IT scanned/triaged and when — used to keep
# per-project cadence + daily caps consistent across restarts/ticks. Deliberately
# NOT the tenant's scan history (which mixes in real activity and would make
# cadence circular). CXONE_STATE_DIR overrides the location so a container can
# mount it as a volume (Dockerfile sets CXONE_STATE_DIR=/state). Never packaged.
_STATE_DIR = Path(os.environ.get("CXONE_STATE_DIR") or Path(__file__).resolve().parent)
_STATE = _STATE_DIR / ".agent_state.json"
# The COMMITTED plan, persisted so a restart resumes it instead of silently
# discarding it (the ledger records what EXECUTED; this records what was
# PROMISED). Live runs only — a dry-run's plan must never be resumed by a later
# live run. Rewritten after every event; versioned so old files load cleanly.
_PLAN_STATE = _STATE_DIR / ".agent_plan.json"
_PLAN_FORMAT = 1
_LEDGER_RETENTION_DAYS = 30   # trim entries older than this on load/save


def _load_activity() -> ActivityModel:
    block = {}
    if _CONFIG.is_file():
        data = yaml.safe_load(open(_CONFIG, encoding="utf-8")) or {}
        block = data.get("activity") or data
    return ActivityModel(block)


def _activity_projects_cfg() -> dict:
    """The `activity.projects:` scope block from activity.yaml, if any.

    Accepted at either `activity.projects` or a top-level `projects`, matching
    how _load_activity tolerates both nestings.
    """
    try:
        if _CONFIG.is_file():
            data = yaml.safe_load(open(_CONFIG, encoding="utf-8")) or {}
            block = data.get("activity") or data
            return (block.get("projects") or data.get("projects") or {})
    except Exception as exc:
        logger.debug("Could not read project scope from %s: %s", _CONFIG, exc)
    return {}


def _identity_affinity() -> float:
    """The identities.affinity knob from activity.yaml (0.85 default)."""
    try:
        if _CONFIG.is_file():
            data = yaml.safe_load(open(_CONFIG, encoding="utf-8")) or {}
            return float((data.get("identities") or {}).get("affinity", 0.85))
    except Exception:
        pass
    return 0.85


def _identity_include_primary() -> bool:
    """The identities.include_primary knob from activity.yaml (default True).
    Set False to keep the admin/primary key out of autonomous scan/triage
    attribution entirely — only registered secondaries act."""
    try:
        if _CONFIG.is_file():
            data = yaml.safe_load(open(_CONFIG, encoding="utf-8")) or {}
            return bool((data.get("identities") or {}).get("include_primary", True))
    except Exception:
        pass
    return True


def _log_behavior(model, behavior=None) -> None:
    """State this agent's behavior on every run and plan.

    Printed whether or not anything was overridden: the point is that the log
    describes the agent that ran, rather than leaving a future reader to infer
    it from a shared config file that may have changed since.
    """
    from ops.agent_behavior import AgentBehavior
    b = behavior or AgentBehavior()
    logger.info("Agent behavior - %s",
                b.describe(model,
                           affinity=_effective_affinity(behavior),
                           include_primary=_effective_include_primary(behavior)))


def _effective_affinity(behavior=None) -> float:
    """activity.yaml's affinity, unless this run overrode it."""
    base = _identity_affinity()
    return base if behavior is None else behavior.effective_affinity(base)


def _effective_include_primary(behavior=None) -> bool:
    """activity.yaml's include_primary, unless this run overrode it."""
    base = _identity_include_primary()
    return base if behavior is None else behavior.effective_include_primary(base)


def _assign_identities(plan: list[Event], pool, rng: random.Random,
                       behavior=None) -> None:
    """Stamp each scan/triage event with the identity that will perform it
    (detail['as']). Done at PLANNING time, not execution, so the identity shows
    in the plan log, persists in the plan file, and survives a restart-resume
    unchanged. Stable per-project affinity + run-seeded wobble; see
    IdentityPool.pick. No-op without secondaries (detail stays untouched, so
    single-identity plans are byte-identical to pre-3.4)."""
    if pool is None or not pool.has_secondaries():
        return
    include_primary = _effective_include_primary(behavior)
    for e in plan:
        if e.type == "scan":
            key = ",".join(sorted(e.detail.get("projects", []))) or "?"
        elif e.type == "triage":
            key = e.detail.get("project", "?")
        else:
            continue
        e.detail["as"] = pool.pick(e.type, key, rng, include_primary=include_primary)


def _load_ledger() -> dict:
    """Read the agent's private ledger as {'scan': {pid: [datetime]}, 'triage': {...}},
    dropping entries older than the retention window."""
    out = {"scan": {}, "triage": {}}
    if not _STATE.is_file():
        return out
    try:
        raw = json.loads(_STATE.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Could not read agent ledger (%s); starting fresh.", exc)
        return out
    cutoff = datetime.now() - timedelta(days=_LEDGER_RETENTION_DAYS)
    for kind in ("scan", "triage"):
        for pid, stamps in (raw.get(kind) or {}).items():
            kept = []
            for s in stamps:
                try:
                    dt = datetime.fromisoformat(s)
                except (ValueError, TypeError):
                    continue
                if dt >= cutoff:
                    kept.append(dt)
            if kept:
                out[kind][pid] = kept
    return out


def _save_ledger(ledger: dict) -> None:
    cutoff = datetime.now() - timedelta(days=_LEDGER_RETENTION_DAYS)
    serializable = {"scan": {}, "triage": {}}
    for kind in ("scan", "triage"):
        for pid, stamps in (ledger.get(kind) or {}).items():
            kept = [s.isoformat() for s in stamps if isinstance(s, datetime) and s >= cutoff]
            if kept:
                serializable[kind][pid] = kept
    try:
        _STATE.write_text(json.dumps(serializable), encoding="utf-8")
    except Exception as exc:
        logger.warning("Could not write agent ledger (%s).", exc)


def _save_plan(plan: list[Event], plan_end: datetime) -> None:
    """Persist the committed remaining plan (called at generation and after every
    event is consumed). Small file, rewritten whole — atomicity isn't critical
    because a torn/invalid file just means 'no resume, plan fresh'."""
    try:
        payload = {
            "format": _PLAN_FORMAT,
            "saved_at": datetime.now().isoformat(timespec="seconds"),
            "plan_end": plan_end.isoformat(timespec="seconds"),
            "events": [{"at": e.at.isoformat(timespec="seconds"),
                        "type": e.type, "detail": e.detail} for e in plan],
        }
        _PLAN_STATE.write_text(json.dumps(payload), encoding="utf-8")
    except (OSError, TypeError, ValueError) as exc:
        logger.warning("Could not persist plan (%s) - a restart will re-plan "
                       "instead of resuming.", exc)


def _clear_plan() -> None:
    try:
        _PLAN_STATE.unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        logger.debug("Could not remove plan file: %s", exc)


def _load_resumable_plan(max_lateness_s: float) -> tuple[list[Event], datetime] | None:
    """Load a previously committed plan if it can still be honored.

    Returns (events, plan_end) when the persisted window is still open and at
    least one event survives the lateness policy: events within `max_lateness_s`
    of now (or in the future) are kept; older ones are dropped exactly as the
    live loop would drop them (quiet gap, never a makeup burst). Anything else —
    missing file, unknown format, expired window, nothing resumable — returns
    None and the loop plans fresh."""
    try:
        raw = json.loads(_PLAN_STATE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Could not read persisted plan (%s); planning fresh.", exc)
        return None
    if raw.get("format") != _PLAN_FORMAT:
        logger.info("Persisted plan has unknown format %r; planning fresh.",
                    raw.get("format"))
        return None
    try:
        plan_end = datetime.fromisoformat(raw["plan_end"])
        events = [Event(at=datetime.fromisoformat(ev["at"]),
                        type=ev["type"], detail=ev.get("detail") or {})
                  for ev in raw.get("events", [])]
    except (KeyError, TypeError, ValueError) as exc:
        logger.warning("Persisted plan is malformed (%s); planning fresh.", exc)
        return None
    now = datetime.now()
    if now >= plan_end:
        return None  # window over — normal re-plan takes it from here
    kept = [e for e in events if (now - e.at).total_seconds() <= max_lateness_s]
    dropped = len(events) - len(kept)
    if dropped:
        logger.info("Resuming plan: dropped %d stale event(s) beyond the %dm "
                    "lateness tolerance (host was down) — quiet gap, no makeup "
                    "burst.", dropped, int(max_lateness_s // 60))
    if not kept:
        return None
    return kept, plan_end


def _record_in_ledger(ledger: dict, event: Event) -> None:
    """Append an executed scan/triage event to the ledger (keyed by project name —
    the same identifier the plan uses for spacing)."""
    if event.type == "scan":
        for name in event.detail.get("projects", []):
            ledger["scan"].setdefault(name, []).append(event.at)
    elif event.type == "triage":
        name = event.detail.get("project")
        if name:
            ledger["triage"].setdefault(name, []).append(event.at)


def _projects(api: ApiClient, scope=None) -> list[dict]:
    """Tenant projects the agent may act on, narrowed by `scope` if given.

    `tags` is carried through (not just id/name) because the scope can filter
    on them — the planner ignores the extra key.
    """
    from onboard import OnboardManager
    projects = [{"id": p.get("id"), "name": p.get("name"), "tags": p.get("tags") or {}}
                for p in OnboardManager(api).list_projects()]
    if scope is not None and scope.active:
        projects = scope.apply(projects, logger)
    return projects


def _execute(event: Event, cfg: CxConfig, api: ApiClient,
             pool=None) -> bool:
    """Perform one event using the existing modules. Honors cfg.dry_run.
    When the event carries an identity (detail['as'], assigned at planning),
    the action runs under that identity's client — with the pool's built-in
    403->primary fallback — so tenant history shows a team, not one admin.

    Returns True only if the event actually did work (at least one project
    resolved). A False return means the event was a NO-OP — typically the
    named projects didn't resolve — and the caller must NOT record it in the
    cadence ledger. Live-observed on cnf26 (2026-07): during an identity
    visibility outage every event resolved 0 projects, yet each was recorded
    as executed, so the cadence gate then believed those projects had just
    been scanned/triaged and would not reschedule them for a full interval.
    An outage should leave a quiet gap the agent naturally catches up from,
    not silently poison the cadence memory."""
    from ops.run import run_scan, run_triage
    acting = event.detail.get("as")
    event_api = None
    if pool is not None and acting and acting != "primary":
        try:
            event_api = pool.client_for(acting)
        except KeyError:
            logger.warning("Identity '%s' from the plan is no longer registered "
                           "- executing as primary.", acting)
            acting = None
    if event.type == "scan":
        names = ",".join(event.detail.get("projects", []))
        if not names:
            return False
        return bool(run_scan(cfg, project_names=names, api=event_api,
                             acting_as=acting))
    elif event.type == "triage":
        # The plan sets a per-engine fraction of untriaged to clear (SAST high ..
        # Containers low). Map each engine's fraction onto the triage engine's
        # intensity bands and review engines together by band, so SAST is reviewed
        # harder than Containers in the same pass.
        project = event.detail.get("project", "")
        fractions = event.detail.get("fractions") or {"sast": 0.2, "sca": 0.12, "iac": 0.08}
        by_intensity: dict[str, list[str]] = {}
        for eng, frac in fractions.items():
            # Fraction -> intensity band. The upper bands only engage under a
            # tuned heavy-run profile (typical fractions top out ~0.20*1.5
            # jitter); "heavy" carries its own per-pass human budget, so even
            # aggressive profiles can't exceed an analyst-day per project.
            if frac < 0.10:
                band = "light"
            elif frac < 0.18:
                band = "some"
            elif frac < 0.28:
                band = "moderate"
            elif frac < 0.45:
                band = "thorough"
            else:
                band = "heavy"
            by_intensity.setdefault(band, []).append(eng)
        did_work = False
        for intensity, engs in by_intensity.items():
            if run_triage(cfg, projects=project, scan_types=",".join(engs),
                          intensity=intensity, api=event_api, acting_as=acting):
                did_work = True
        return did_work
    elif event.type == "onboard":
        from onboard import OnboardManager
        org, _, repo = event.detail.get("repo", "").partition("/")
        if org and repo:
            OnboardManager(api).onboard_github([
                {"type": "scm", "scm_type": "github", "organization": org, "repository": repo}
            ])
            return True
    return False


# --------------------------------------------------------------------- modes
def cmd_plan(cfg: CxConfig, model: ActivityModel, seed: int | None,
             api: ApiClient | None, until: str | None = None,
             scope=None, behavior=None) -> int:
    projects = (_projects(api, scope) if api
                else [{"id": f"p{i}", "name": f"demo-project-{i}"} for i in range(12)])
    if not projects:
        logger.error("No projects in scope - nothing to plan.")
        return 2
    rng = random.Random(seed)
    now = datetime.now()
    _log_behavior(model, behavior)

    # Only ever list the committed window (the internal 24h rolling horizon): what
    # the agent actually locks in before its next re-plan. We never print specific
    # events beyond it, because they won't happen as shown — the agent re-plans
    # forward with fresh jitter.
    listed_window = float(_HORIZON_S)
    plan = model.generate_plan(now, listed_window, projects, rng)
    from cxone.identity_pool import IdentityPool
    _assign_identities(plan, IdentityPool(cfg, affinity=_effective_affinity(behavior)),
                       rng, behavior)
    listed_end = now + timedelta(seconds=listed_window)
    src = "live tenant projects" if api else "placeholder projects"

    print(f"Next {listed_window/3600:.0f}h - {len(plan)} committed event(s) ({src}):\n")
    counts: dict[str, int] = {}
    for e in plan:
        counts[e.type] = counts.get(e.type, 0) + 1
        print(f"   {e.at:%a %H:%M:%S}  {e.describe()}")
    print("\nby type:", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none")

    # Beyond the horizon: describe the *behavior*, never commit to events. The
    # daemon re-plans every horizon with new jitter, so only the pattern is knowable.
    scans_day = counts.get("scan", 0) * (86400.0 / listed_window)
    triage_day = counts.get("triage", 0) * (86400.0 / listed_window)
    bh_start, bh_end = model.bh_start, model.bh_end
    print(f"\nBeyond {listed_end:%a %H:%M} - general behavior, not a fixed schedule:")
    print(f"  The agent re-plans every {_HORIZON_S/3600:.0f}h with fresh timing (jitter),")
    print(f"  so specific times past the horizon aren't decided yet. Expect a similar")
    print(f"  rhythm: roughly {scans_day:.0f} scan(s) and {triage_day:.0f} triage pass(es) "
          f"per day,")
    print(f"  weighted toward business hours (~{bh_start:02d}:00–{bh_end:02d}:00 local), "
          f"tapering")
    print(f"  overnight and on weekends, with per-project spacing and daily caps enforced.")
    if until:
        print(f"  This continues, re-planned each cycle, through {until} - then the agent idles.")
    else:
        print(f"  This continues, re-planned each cycle, until the agent is stopped.")
    return 0


_HORIZON_S = 24 * 3600   # internal rolling plan horizon; not user-configurable
_IMAGE = "cxone-agent"
_CONTAINER = "cxone-agent"
_STATE_VOLUME = "cxone-agent-state"


@dataclass
class ContainerRuntime:
    """A detected runtime, kept as both forms because they serve different jobs.

    ``name`` ('docker'/'podman') is for human-facing messages. ``exe`` is the
    absolute path ``shutil.which`` resolved and is what MUST be passed as
    subprocess argv[0] — passing the bare name instead broke launches on
    Windows even though `shutil.which` had already found the binary: without
    an extension, Windows CreateProcess only tries appending '.exe' and never
    finds a '.cmd'/'.bat' shim (e.g. a `docker -> podman` alias script), so a
    perfectly working runtime looked absent. The resolved path carries its
    real extension and sidesteps that lookup entirely — the fix generalizes
    cleanly to Linux/macOS too, since an absolute path there is just as valid
    an argv[0] as a bare name.
    """
    name: str
    exe: str


# Extensions Windows can only run by handing off to a shell (cmd.exe), which then
# re-tokenizes the command line using its OWN metacharacter rules (&, |, ^, <, >,
# ...). A real .exe/.com never takes this detour — argv reaches it unmangled. Empty
# on POSIX, where "docker"/"podman" are always native binaries, so this filter is a
# no-op there and the preference logic below only ever activates on Windows.
_SHELL_SCRIPT_EXTENSIONS = {".cmd", ".bat", ".ps1"}


def _is_shell_script(exe: str) -> bool:
    return Path(exe).suffix.lower() in _SHELL_SCRIPT_EXTENSIONS


def _detect_container_runtime() -> ContainerRuntime | None:
    """Return the working container runtime: a native binary, if one is available,
    else whichever script-based one works; docker preferred over podman within
    each tier.

    A `docker` found on PATH is sometimes a `.cmd`/`.bat` alias that just calls
    `podman` (as this project's own dev machines do) — plausible on any Windows
    box with both installed. Picking that over a genuine `podman.exe` looks
    identical right up until an argument contains a shell metacharacter: a tag
    filter like `T&R` silently splits into two commands under cmd.exe, launching
    with a truncated/wrong command line instead of failing loudly. Preferring a
    native binary whenever one exists closes that trap entirely, without giving
    up on a script-only install (better a working shim than no runtime).
    """
    import shutil, subprocess
    candidates = []
    for name in ("docker", "podman"):
        exe = shutil.which(name)
        if not exe:
            continue
        try:
            r = subprocess.run([exe, "info"], capture_output=True, timeout=15)
            if r.returncode == 0:
                candidates.append(ContainerRuntime(name=name, exe=exe))
            else:
                logger.debug("%s present but not usable (info rc=%d): %s",
                             name, r.returncode, r.stderr.decode(errors="replace")[:200])
        except Exception as exc:
            logger.debug("%s present but check failed: %s", name, exc)
    if not candidates:
        return None
    native = [c for c in candidates if not _is_shell_script(c.exe)]
    chosen = native[0] if native else candidates[0]
    if _is_shell_script(chosen.exe):
        logger.warning(
            "Only a script-based container runtime was found (%s, %s) - arguments "
            "containing shell metacharacters (&, |, ^, <, >) may be silently "
            "corrupted when launched. Install a native %s binary to avoid this.",
            chosen.name, chosen.exe, chosen.name)
    logger.debug("Container runtime detected: %s (%s)", chosen.name, chosen.exe)
    return chosen


def _resolve_timezone() -> tuple[str | None, str]:
    """Resolve an IANA timezone name to forward into the container so its clock
    and business-hours weighting match the host — DST-aware.

    We forward a *zone name* (e.g. 'America/Chicago'), not a fixed offset, so the
    container's tzdata handles daylight-saving transitions across a multi-day run.
    Order: explicit TZ (user wins) -> tzlocal (best on Windows) -> stdlib zoneinfo
    key -> /etc/localtime symlink (Linux/macOS). Returns (zone_or_None, source).

    Last-resort offset fallback: if only a numeric offset is knowable, we return a
    POSIX-style fixed offset and label it clearly — it aligns to the current wall
    clock but is NOT DST-aware. On the common platforms a real zone name is found,
    so this is rare.
    """
    # 1. Explicit TZ always wins.
    env_tz = os.environ.get("TZ")
    if env_tz:
        return env_tz, "from TZ env var"

    # 2. tzlocal — purpose-built, returns IANA names including on Windows.
    tzlocal_missing = False
    try:
        import tzlocal  # optional dependency
        name = tzlocal.get_localzone_name()
        if name:
            return name, "detected from host via tzlocal"
    except ImportError:
        tzlocal_missing = True
    except Exception:
        pass

    # 3. stdlib: astimezone().tzinfo carries a zoneinfo `key` on 3.9+ when the
    #    platform's local zone is zoneinfo-backed (reliable on Linux/macOS).
    try:
        from datetime import datetime
        key = getattr(datetime.now().astimezone().tzinfo, "key", None)
        if key and key != "UTC":
            return key, "detected from host (zoneinfo)"
    except Exception:
        pass

    # 4. /etc/localtime symlink -> .../zoneinfo/Area/City (Linux/macOS).
    try:
        import os.path as _p
        link = _p.realpath("/etc/localtime")
        if "zoneinfo/" in link:
            name = link.split("zoneinfo/", 1)[1]
            if name and name != "UTC":
                return name, "detected from /etc/localtime"
    except Exception:
        pass

    # 5. Last resort: current UTC offset as a fixed POSIX TZ (NOT DST-aware).
    #    POSIX sign is inverted (east of UTC is negative), hence the sign logic.
    try:
        from datetime import datetime
        off = datetime.now().astimezone().utcoffset()
        if off is not None:
            total_min = int(off.total_seconds() // 60)
            hh, mm = divmod(abs(total_min), 60)
            sign = "-" if total_min >= 0 else "+"   # POSIX inversion
            posix = f"UTC{sign}{hh:02d}:{mm:02d}"
            why = ("host UTC offset only - NOT DST-aware; "
                   + ("install tzlocal (pip install -r requirements.txt) for a "
                      "DST-correct zone name" if tzlocal_missing
                      else "set TZ=Area/City for a DST-correct zone"))
            return posix, why
    except Exception:
        pass

    return None, "undetected"


def _launch_container(rt: ContainerRuntime, cfg: CxConfig, until: str | None,
                      max_lateness: str, live: bool, scope=None,
                      behavior=None) -> int:
    """Build the agent image if needed and start the containerized run loop.

    The container runs `agent run --process` internally (never recursing into
    container detection). Credentials go in as env vars, never baked in.
    """
    import subprocess
    exe = rt.exe
    skill_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def _redacted(cmd: list[str]) -> str:
        """The launch command is logged for auditability, but it carries
        credentials as `-e KEY=value` args — redact those values. (The values
        still reach the runtime via the process args; see the env-file note at
        the call site for why that trade-off is accepted here.)"""
        out = []
        for part in cmd:
            k, sep, _v = part.partition("=")
            if sep and any(s in k for s in ("API_KEY", "TOKEN", "PASSWORD", "SECRET")):
                out.append(f"{k}=***")
            else:
                out.append(part)
        return " ".join(out)

    def _run(cmd: list[str], **kw):
        logger.info("$ %s", _redacted(cmd))
        return subprocess.run(cmd, **kw)

    # Image present AND current? The image is labeled with the skill version at
    # build time; a mismatch (or a pre-label image, like 3.1.x) means the image
    # is frozen older code — installing a new skill version does nothing for the
    # container until the image is rebuilt, so do that here rather than letting
    # a stale build linger silently. Skipped when the installed version can't be
    # read ('unknown', e.g. a partial copy) to avoid a rebuild loop.
    from cxone import get_version
    want = get_version()
    have = subprocess.run([exe, "image", "inspect", _IMAGE],
                          capture_output=True).returncode == 0
    if have and want != "unknown":
        r = subprocess.run(
            [exe, "image", "inspect", "-f",
             '{{ index .Config.Labels "cxone.multitool.version" }}', _IMAGE],
            capture_output=True, text=True)
        built = (r.stdout or "").strip()
        if r.returncode != 0 or built != want:
            logger.info("Image '%s' was built from version %s but the installed "
                        "skill is %s - rebuilding so the container runs current "
                        "code.", _IMAGE, built or "pre-3.2 (unlabeled)", want)
            have = False
    if not have:
        logger.info("Building image '%s' from %s", _IMAGE, skill_root)
        r = _run([exe, "build", "-t", _IMAGE,
                  "--label", f"cxone.multitool.version={want}", skill_root])
        if r.returncode != 0:
            logger.error("Image build failed (rc=%d). Falling back is possible with "
                         "--process.", r.returncode)
            return r.returncode

    # State volume for the cadence ledger.
    subprocess.run([exe, "volume", "create", _STATE_VOLUME], capture_output=True)

    # Replace any prior container of the same name.
    subprocess.run([exe, "rm", "-f", _CONTAINER], capture_output=True)

    cmd = [exe, "run", "-d", "--name", _CONTAINER, "--restart=unless-stopped",
           "-e", f"CXONE_BASE_URL={cfg.base_url}",
           "-e", f"CXONE_TENANT={cfg.tenant_name}",
           "-e", f"CXONE_API_KEY={cfg.api_key}",
           "-v", f"{_STATE_VOLUME}:/state"]
    # The container must see the SAME effective config as a process run would:
    #  - CXONE_IAM_BASE_URL: without it, non-standard hosts (the exact case the
    #    override exists for) can't authenticate inside the container.
    #  - SCM tokens: onboarding events (activity.yaml onboard.enabled) fail
    #    without them. They were loaded into this process's env from the env
    #    file by CxConfig.from_env, so read them from os.environ.
    #  - CXONE_WORKERS: keep fan-out consistent with the host config.
    if cfg.iam_base_url:
        cmd += ["-e", f"CXONE_IAM_BASE_URL={cfg.iam_base_url}"]
    # Secondary identities travel as one JSON env var via a TRANSIENT env-file
    # (0600, deleted right after launch) — a list of API keys is too sensitive
    # for `-e` args even with log redaction, since the raw command is visible
    # in the host process list while `run` executes.
    env_file_path = None
    try:
        from cxone.identity_pool import IdentityPool
        _pool = IdentityPool(cfg)
        if _pool.has_secondaries():
            import tempfile
            fd, env_file_path = tempfile.mkstemp(prefix="cxone-ids-", suffix=".env")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(f"CXONE_IDENTITIES_JSON={_pool.to_json()}\n")
            os.chmod(env_file_path, 0o600)
            cmd += ["--env-file", env_file_path]
            logger.info("Passing %d secondary identit%s into the container.",
                        len(_pool.names(include_primary=False)),
                        "y" if len(_pool.names(include_primary=False)) == 1 else "ies")
    except Exception as exc:
        # ERROR, not warning: this does not merely lose a feature, it silently
        # changes WHO the tenant records as having run every scan for days.
        logger.error("Could not pass identities into the container (%s) - every "
                     "event would be attributed to the primary/admin key.", exc)
        raise RuntimeError(
            "Refusing to start: secondary identities are configured but could "
            "not be delivered to the container, so all activity would be "
            "attributed to the admin key. Fix the identities file (see "
            "`identities list`), or pass --identities all to accept the "
            "primary key deliberately.") from exc
    if cfg.github_token and not os.environ.get("CXONE_GITHUB_TOKEN"):
        cmd += ["-e", f"CXONE_GITHUB_TOKEN={cfg.github_token}"]  # GITHUB_TOKEN alias
    for var in ("CXONE_GITHUB_TOKEN", "CXONE_AZURE_TOKEN",
                "CXONE_GITLAB_TOKEN", "CXONE_BITBUCKET_TOKEN", "CXONE_WORKERS"):
        val = os.environ.get(var)
        if val:
            cmd += ["-e", f"{var}={val}"]
    if until:
        cmd += ["-e", f"CXONE_AGENT_UNTIL={until}"]
    tz, tz_src = _resolve_timezone()
    if tz:
        cmd += ["-e", f"TZ={tz}"]
        logger.info("Timezone: %s (%s) - container clock + business-hours timing "
                    "will match this.", tz, tz_src)
    else:
        logger.warning("Timezone: could not detect host zone; container runs in UTC. "
                       "Logs and business-hours activity may not match your clock. "
                       "Set TZ=Area/City (e.g. America/Chicago) to fix.")
    cmd += [_IMAGE, "--max-lateness", max_lateness]
    if live:
        cmd += ["--live"]
    # Forward the resolved scope as flags. The image carries its own baked
    # activity.yaml, which cannot know about flags (or env vars) given on the
    # host — without this, a host-side --exclude-projects would be silently
    # dropped and the container would happily scan everything.
    if scope is not None and scope.active:
        cmd += scope.as_cli_args()
        logger.info("Project scope passed to the container: %s", scope.describe())
    # Same trap as scope: the image's baked activity.yaml cannot see host-side
    # flags, so per-run behavior has to travel as flags or it is silently lost.
    if behavior is not None and behavior.active:
        cmd += behavior.as_cli_args()
        logger.info("Behavior passed to the container: %s",
                    " ".join(behavior.as_cli_args()))
    try:
        r = _run(cmd, capture_output=True, text=True)
    finally:
        # The transient identities env-file has served its purpose the moment
        # the runtime has read it — remove it whether the launch worked or not.
        if env_file_path:
            try:
                os.unlink(env_file_path)
            except OSError:
                logger.warning("Could not remove transient env-file %s - it "
                               "contains API keys; delete it manually.",
                               env_file_path)
    if r.returncode != 0:
        logger.error("Container start failed (rc=%d): %s", r.returncode,
                     (r.stderr or "").strip()[:400])
        return r.returncode
    logger.info("Agent container '%s' started [%s] until=%s.",
                _CONTAINER, "LIVE" if live else "DRY-RUN", until or "(stopped manually)")
    logger.info("Follow the activity log with:  %s logs -f %s", rt.name, _CONTAINER)
    logger.info("Stop with:                     %s stop %s", rt.name, _CONTAINER)
    return 0


def cmd_run(cfg: CxConfig, model: ActivityModel, api: ApiClient, live: bool,
            until: str | None, max_lateness_s: int, seed: int | None,
            substrate: str | None, max_lateness_raw: str, scope=None,
            behavior=None) -> int:
    """The single executor: real activity over real time, re-planning each
    (internal) 24h horizon, until --until or stopped.

    Substrate: 'container' launches Docker/Podman (durable; survives host sleep);
    'process' runs the loop here. With neither specified, auto-detect: if a
    container runtime exists, ask the user to choose; otherwise run as a process.
    """
    if substrate is None:
        rt = _detect_container_runtime()
        if rt:
            if sys.stdin.isatty():
                ans = input(f"{rt.name} is available. Run in a container (recommended for "
                            f"multi-day runs; survives host sleep) or as a process? "
                            f"[container/process] ").strip().lower()
                substrate = "container" if ans.startswith("c") else "process"
            else:
                logger.info("%s is available. Choose how to run:", rt.name)
                logger.info("  --container   durable %s container (recommended for "
                            "multi-day runs; survives host sleep/restarts)", rt.name)
                logger.info("  --process     long-lived process in this session "
                            "(simpler; dies with the host/session)")
                logger.info("Re-run with one of the flags above.")
                return 3
        else:
            logger.info("No container runtime (docker/podman) found - running as a "
                        "long-lived process. For multi-day runs, a container is "
                        "recommended if you can install one.")
            substrate = "process"

    if substrate == "container":
        rt = _detect_container_runtime()
        if not rt:
            logger.error("--container requested but no working docker/podman found. "
                         "Use --process instead.")
            return 2
        return _launch_container(rt, cfg, until, max_lateness_raw, live, scope,
                                behavior)

    return _run_loop(cfg, model, api, live, until, max_lateness_s, _HORIZON_S,
                     seed, scope, behavior)


def _run_loop(cfg: CxConfig, model: ActivityModel, api: ApiClient, live: bool,
               until: str | None, max_lateness_s: float, horizon_s: float,
               seed: int | None, scope=None, behavior=None) -> int:
    """
    Long-lived, scheduler-free mode — the primary deployment target (container).

    Loop: (re)generate a plan for the next `horizon_s` seconds from *now* (seeded
    from the persisted ledger so restarts never double-act), sleep in short chunks
    until the next event, execute it, persist the ledger. Two safety behaviors:

      * Lateness policy: an event more than `max_lateness_s` past its scheduled
        time is DROPPED (host was asleep/down) — planning resumes forward from
        now. Minutes late executes; a long outage becomes a quiet gap, never a
        late burst. Chunked sleeps make clock jumps (suspend/resume) detectable.
      * Until-guard: past `until` (YYYY-MM-DD) the daemon idles quietly instead of
        exiting, so restart policies don't spin it in a loop. Stop the container
        (or extend --until) to finish.

    Transient API failures back off and retry rather than crashing; a supervisor
    (docker --restart) covers anything fatal. SIGTERM exits cleanly.
    """
    stop = {"flag": False}

    def _sigterm(_sig, _frm):
        stop["flag"] = True
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _sigterm)
    cfg.dry_run = not live
    rng = random.Random(seed)
    ledger = _load_ledger()
    from cxone.identity_pool import IdentityPool
    pool = IdentityPool(cfg, affinity=_effective_affinity(behavior))
    mode = "LIVE" if live else "DRY-RUN"
    _log_behavior(model, behavior)
    logger.info("Agent run loop starting [%s] until=%s lateness-tolerance=%dm horizon=%dh state=%s",
                mode, until or "(none)", max_lateness_s // 60, horizon_s // 3600, _STATE)

    plan: list[Event] = []
    plan_end: datetime | None = None
    _CHUNK = 600           # max seconds per sleep chunk (keeps guards responsive)
    _RETRY = 300           # back-off after a transient API failure

    # Restart recovery: a committed plan is a promise, so a restart resumes it
    # rather than silently re-planning over it (previously the whole in-memory
    # window — including still-future events — was discarded on restart). Live
    # only, in both directions: dry-run plans are previews that must never leak
    # into a live run (we never save them), and a dry-run must not clear or
    # consume a crashed live run's persisted promise (we never load it either).
    if live:
        resumed = _load_resumable_plan(max_lateness_s)
        if resumed:
            plan, plan_end = resumed
            logger.info("Resumed committed plan from %s: %d remaining event(s) "
                        "through %s (restart recovery).",
                        _PLAN_STATE, len(plan), plan_end.strftime("%a %H:%M"))
            for e in plan:
                logger.info("  resumed %s  %s", e.at.strftime("%a %H:%M:%S"), e.describe())

    try:
        while not stop["flag"]:
            now = datetime.now()

            if until and now.strftime("%Y-%m-%d") > until:
                logger.info("Past until-date %s - idling (no activity). Extend --until "
                            "or stop the container to finish.", until)
                time.sleep(6 * 3600)
                continue

            if not plan or plan_end is None or now >= plan_end:
                try:
                    projects = _projects(api, scope)
                except Exception as exc:
                    logger.warning("Could not fetch projects (%s); retrying in %ds.",
                                   exc, _RETRY)
                    time.sleep(_RETRY)
                    continue
                if not projects:
                    if scope is not None and scope.active:
                        # Don't say "no projects in tenant" when a scope is what
                        # emptied the list — that sends people hunting the wrong
                        # problem (scope.apply already logged the counts).
                        logger.error(
                            "No projects match the configured scope (%s); nothing to "
                            "plan. Fix the scope and restart - retrying in %ds.",
                            scope.describe(), _RETRY)
                    else:
                        logger.info("No projects in tenant yet; checking again in %ds.", _RETRY)
                    time.sleep(_RETRY)
                    continue
                plan = model.generate_plan(now, horizon_s, projects, rng, history=ledger)
                _assign_identities(plan, pool, rng, behavior)
                plan_end = now + timedelta(seconds=horizon_s)
                if live:
                    _save_plan(plan, plan_end)  # commit the promise before announcing it
                logger.info("Planned %d event(s) through %s:",
                            len(plan), plan_end.strftime("%a %H:%M"))
                # Enumerate the committed window so the log shows WHAT was planned,
                # not just how many. This is the reviewable record of each re-plan;
                # actual execution is still logged per-event as it fires.
                for e in plan:
                    logger.info("  planned %s  %s", e.at.strftime("%a %H:%M:%S"), e.describe())
                if not plan:
                    logger.info("  (no events this window - quiet period)")

            if not plan:
                remaining = (plan_end - datetime.now()).total_seconds()
                if remaining > 0:
                    time.sleep(min(remaining, _CHUNK))
                continue

            wait = (plan[0].at - datetime.now()).total_seconds()
            if wait > 0:
                time.sleep(min(wait, _CHUNK))
                continue  # re-check guards/lateness after every chunk

            e = plan.pop(0)
            if live:
                # The file always mirrors what's still owed: consumed events —
                # executed, failed, OR dropped-stale — never resume after a crash.
                _save_plan(plan, plan_end)
            late = (datetime.now() - e.at).total_seconds()
            if late > max_lateness_s:
                logger.info("Dropped stale %s event scheduled %s (%.0f min late - host "
                            "asleep/down); resuming forward.", e.type,
                            e.at.strftime("%a %H:%M"), late / 60)
                continue
            # Detailed per-event diagnostics: scheduled vs actual time, duration,
            # outcome. Failures log the exception message at INFO and the full
            # traceback at DEBUG (run with --debug when diagnosing).
            logger.info("[%s] executing %s (%.0fs after schedule)",
                        e.at.strftime("%a %H:%M"), e.describe(), max(late, 0))
            t_start = time.monotonic()
            try:
                did_work = _execute(e, cfg, api, pool=pool)
                logger.info("  done %s in %.1fs%s", e.type,
                            time.monotonic() - t_start,
                            "" if did_work else " (NO-OP - nothing resolved)")
                # Only real work updates cadence memory. Recording a no-op
                # would tell the planner these projects were just handled and
                # suppress them for a full interval — turning a transient
                # outage into a lasting gap in coverage.
                if live and did_work:
                    _record_in_ledger(ledger, e)
                    _save_ledger(ledger)
                    logger.debug("  ledger updated + saved (%s)", _STATE)
                elif live:
                    logger.info(
                        "  not recorded in the cadence ledger - this event "
                        "resolved nothing, so the project(s) stay due and the "
                        "next re-plan can pick them up again.")
            except Exception as exc:
                logger.warning("  event FAILED (%s after %.1fs): %s: %s",
                               e.type, time.monotonic() - t_start,
                               type(exc).__name__, exc)
                logger.debug("  traceback:", exc_info=True)
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        if live:
            _save_ledger(ledger)
        logger.info("Agent run stopped [%s].", mode)
    return 0


# --------------------------------------------------------------------- CLI
def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="agent",
        description="Real-world tenant activity: real scans/triage over real time.")
    p.add_argument("--env", default=None)
    p.add_argument("--debug", action="store_true",
                   help="verbose diagnostics (tracebacks, substrate detection detail)")
    p.add_argument("--seed", type=int, default=None, help="reproducible planning RNG")

    def _add_scope_args(sp):
        """Project scoping — same flags on `run` and `plan`, so what you preview
        is what you run. Excludes always beat includes; see ops/project_scope.py."""
        g = sp.add_argument_group("project scope")
        g.add_argument("--include-projects", default=None, metavar="PATTERNS",
                       help="comma-separated name patterns; only matching projects "
                            "are in scope. Substring by default ('Shop'), glob if it "
                            "contains * ? [ ('ShopWorthy/*')")
        g.add_argument("--exclude-projects", default=None, metavar="PATTERNS",
                       help="comma-separated name patterns to exclude (wins over "
                            "--include-projects), e.g. 'Istio'")
        g.add_argument("--include-tags", default=None, metavar="TAGS",
                       help="comma-separated tag filters: 'Demo' (key present) or "
                            "'Demo:T&R' (key:value)")
        g.add_argument("--exclude-tags", default=None, metavar="TAGS",
                       help="comma-separated tag filters to exclude (wins over includes)")

    def _add_behavior_args(sp):
        """Per-run behavior — same flags on `run` and `plan`, so a preview
        reflects the agent you are about to start. CLI > env > activity.yaml;
        nothing here edits the shared config file. See ops/agent_behavior.py."""
        g = sp.add_argument_group("agent behavior (this run only)")
        tg = g.add_mutually_exclusive_group()
        tg.add_argument("--triage", dest="triage", action="store_true", default=None,
                        help="run triage passes. NOTE these are triage-simulate: "
                             "FABRICATED states, not a real review (the agent has no "
                             "assistant in its loop). Off by default.")
        tg.add_argument("--no-triage", dest="triage", action="store_false", default=None,
                        help="scans only (the shipped default)")
        g.add_argument("--triage-weight", type=float, default=None, metavar="W",
                       help="explicit triage weight in the event mix (implies --triage; "
                            "0 implies --no-triage). Default when --triage is given: 0.53")
        g.add_argument("--identities", default=None, choices=["all", "secondaries"],
                       help="who performs events: 'all' includes the primary/admin key, "
                            "'secondaries' restricts to registered secondary identities")
        g.add_argument("--affinity", type=float, default=None, metavar="F",
                       help="0..1 stickiness of each project's owner (1.0 = always the "
                            "same person, 0.85 = realistic hand-offs)")
        g.add_argument("--scans-per-hour", type=float, default=None, metavar="N",
                       help="target scans per BUSINESS hour (default ~1.2 from config). "
                            "Raises the arrival rate, the tenant-wide caps, and "
                            "per-project cadence together, since any one of the three "
                            "alone would silently throttle the others")

    sub = p.add_subparsers(dest="mode", required=True)

    rn = sub.add_parser("run", help="run the agent: real activity over real time, "
                        "re-planning internally every 24h, until --until or stopped")
    rn.add_argument("--live", action="store_true", help="actually act (default dry-run)")
    rn.add_argument("--until", default=os.environ.get("CXONE_AGENT_UNTIL") or None,
                    help="YYYY-MM-DD; idle after this date (env: CXONE_AGENT_UNTIL)")
    rn.add_argument("--max-lateness", default="2h",
                    help="drop events later than this (host asleep/down); default 2h")
    grp = rn.add_mutually_exclusive_group()
    grp.add_argument("--container", action="store_true",
                     help="run in a docker/podman container (durable; survives host "
                          "sleep; recommended for multi-day runs)")
    grp.add_argument("--process", action="store_true",
                     help="run as a long-lived process in this session")
    _add_scope_args(rn)
    _add_behavior_args(rn)

    pl = sub.add_parser("plan", help="preview the committed next-24h events + general "
                        "behavior beyond (no execution)")
    pl.add_argument("--until", default=os.environ.get("CXONE_AGENT_UNTIL") or None,
                    help="agent end date (YYYY-MM-DD) to state in the summary; "
                         "defaults to CXONE_AGENT_UNTIL if set")
    _add_scope_args(pl)
    _add_behavior_args(pl)

    args = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    model = _load_activity()
    from ops.agent_behavior import AgentBehavior
    behavior = AgentBehavior.resolve(
        cli={"triage": args.triage, "triage_weight": args.triage_weight,
             "identities": args.identities, "affinity": args.affinity,
             "scans_per_hour": args.scans_per_hour},
        env=os.environ,
    )
    behavior.apply_to_model(model)
    cfg = CxConfig.from_env(args.env)
    if args.debug:
        cfg.debug = True

    # Scope: CLI flags > env vars > activity.yaml `projects:` (per field).
    from ops.project_scope import ProjectScope
    scope = ProjectScope.resolve(
        cli={"include_names": args.include_projects,
             "exclude_names": args.exclude_projects,
             "include_tags": args.include_tags,
             "exclude_tags": args.exclude_tags},
        env=os.environ,
        config=_activity_projects_cfg(),
    )

    # plan can run without auth (placeholder projects); run needs the tenant.
    if args.mode == "plan":
        api = None
        try:
            api = ApiClient(cfg); api.auth.token()
        except Exception:
            logger.info("Not authenticated - planning with placeholder projects.")
            api = None
        if api is None and scope.active:
            logger.warning("Project scope is set (%s) but planning is using "
                           "placeholder projects, so it will not be applied.",
                           scope.describe())
        return cmd_plan(cfg, model, args.seed, api, args.until, scope, behavior)

    api = ApiClient(cfg)
    if not args.live:
        logger.info("DRY-RUN (no tenant changes). Re-run with --live to act.")
    substrate = "container" if args.container else ("process" if args.process else None)
    return cmd_run(cfg, model, api, args.live, args.until,
                   int(parse_window(args.max_lateness)), args.seed,
                   substrate, args.max_lateness, scope, behavior)


if __name__ == "__main__":
    sys.exit(main())
