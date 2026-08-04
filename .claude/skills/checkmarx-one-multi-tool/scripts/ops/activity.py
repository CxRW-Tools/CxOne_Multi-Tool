"""
Activity model — when things happen.

Real tenants don't run every scan and triage at once. Activity clusters in
business hours, tapers overnight and on weekends, and arrives at irregular
(Poisson-like) intervals rather than on round numbers. Some projects are scanned
often (active development), others rarely (legacy).

This module turns those facts into a concrete, staggered stream of timed events
that the agent executes. It is pure and testable (no network): you give it a list
of projects and a time window, it returns a list of `Event(at, type, detail)`.

Event types: 'scan', 'triage', 'onboard', 'idle' (idle = a sampled gap with no
action, which keeps the stream from being too uniform). Destructive actions are
intentionally NOT part of the autonomous model.
"""

from __future__ import annotations

import math
import random
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Any

DEFAULTS: dict[str, Any] = {
    "business_hours": [8, 18],        # local hours with peak activity
    "overnight_factor": 0.1,          # activity rate outside business hours
    "weekday_weights": {              # mon..sun
        "0": 1.0, "1": 1.0, "2": 1.0, "3": 1.0, "4": 0.9, "5": 0.15, "6": 0.1
    },
    "events_per_business_hour": 2.0,  # peak arrival rate (events/hour)
    "event_mix": {"scan": 0.55, "triage": 0.35, "onboard": 0.02, "idle": 0.08},
    "scan": {"projects_per_event": [1, 2],
             "interval_hours": [8, 312], "interval_skew": 1.3,
             "max_per_project_per_day": 3},
    "triage": {"scan_types": "sast,sca,iac,containers,secrets",
               "interval_hours": [16, 384], "interval_skew": 1.3,
               "max_per_project_per_day": 2, "follow_scan": True,
               "fraction_jitter": [0.6, 1.5],
               "engine_fractions": {"sast": 0.20, "sca": 0.12, "iac": 0.08,
                                    "secrets": 0.06, "containers": 0.04},
               "max_results_per_day": 750},
    "onboard": {"enabled": False, "repos": []},   # ["org/Repo", ...]; off by default
    "caps": {"max_events_per_hour": 6, "max_scans_per_day": 20, "max_triage_per_day": 12},
}


@dataclass
class Event:
    at: datetime
    type: str
    detail: dict = field(default_factory=dict)

    def describe(self) -> str:
        as_who = self.detail.get("as")
        suffix = f" as {as_who}" if as_who and as_who != "primary" else ""
        if self.type == "scan":
            names = ", ".join(self.detail.get("projects", []))
            return f"scan {names}{suffix}"
        if self.type == "triage":
            fr = self.detail.get("fractions", {})
            engs = ",".join(f"{e}~{int(round(v*100))}%" for e, v in fr.items())
            return f"triage {self.detail.get('project','')} [{engs}]{suffix}"
        if self.type == "onboard":
            return f"onboard {self.detail.get('repo','')}"
        return "idle"


class ActivityModel:
    def __init__(self, cfg_block: dict | None = None):
        cfg = dict(DEFAULTS)
        for k, v in (cfg_block or {}).items():
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                m = dict(cfg[k]); m.update(v); cfg[k] = m
            else:
                cfg[k] = v
        self.bh_start, self.bh_end = cfg["business_hours"]
        self.overnight_factor = float(cfg["overnight_factor"])
        self.weekday_weights = {int(k): float(v) for k, v in cfg["weekday_weights"].items()}
        self.peak_rate_per_hour = float(cfg["events_per_business_hour"])
        self.event_mix = dict(cfg["event_mix"])
        self.scan_cfg = dict(cfg["scan"])
        self.triage_cfg = dict(cfg["triage"])
        self.onboard_cfg = dict(cfg["onboard"])
        self.caps = dict(cfg["caps"])
        # Set by a per-run --scans-per-hour override (ops/agent_behavior.py) to
        # request more scans/day than the cohort's default cadence can supply.
        # None = leave the configured per-project intervals alone.
        self.scan_target_per_day: float | None = None

    # ----------------------------------------------------- rate shaping
    def hour_weight(self, hour: int) -> float:
        return 1.0 if self.bh_start <= hour < self.bh_end else self.overnight_factor

    def weekday_weight(self, weekday: int) -> float:
        return self.weekday_weights.get(weekday, 1.0)

    def rate_per_second(self, when: datetime) -> float:
        per_hour = self.peak_rate_per_hour * self.hour_weight(when.hour) * self.weekday_weight(when.weekday())
        return max(per_hour / 3600.0, 0.0)

    # ------------------------------------------------- per-project cadence
    def interval_map(self, project_keys: list[str], kind: str,
                     rank_by: str | None = None) -> dict[str, float]:
        """Minimum spacing (hours) between actions of `kind` ('scan'|'triage'), per
        project, assigned by stable RANK across the cohort rather than independent
        draws. Ranking guarantees a realistic spread at any tenant size — there's
        always a busiest project (~the floor) and a most-legacy one (~the ceiling),
        with the rest geometrically spaced — instead of every project happening to
        land in the same band by hash luck. `interval_skew` > 1 widens the quiet
        end so most projects are infrequent and 'busy' is the exception.

        `rank_by` chooses which ordering to rank by (default = `kind`). Passing
        rank_by='scan' for triage makes a project's triage cadence track its scan
        cadence — active projects get reviewed more, like real work.

        Deterministic given the project set; uses no external/tenant history."""
        cfg = self.scan_cfg if kind == "scan" else self.triage_cfg
        lo, hi = cfg.get("interval_hours", [8, 312] if kind == "scan" else [16, 384])
        skew = float(cfg.get("interval_skew", 1.3))
        lo = max(float(lo), 0.5)
        ln_lo, ln_hi = math.log(lo), math.log(float(hi))
        order = rank_by or kind
        ranked = sorted(project_keys,
                        key=lambda k: hashlib.sha256(f"{order}:{k}".encode()).hexdigest())
        n = len(ranked)
        out: dict[str, float] = {}
        for i, key in enumerate(ranked):
            r = (i + 0.5) / n if n else 0.5        # percentile in (0,1); 0=busiest
            t = r ** (1.0 / max(skew, 1e-6))        # skew>1 biases toward longer
            out[key] = math.exp(ln_lo + (ln_hi - ln_lo) * t)
        if kind == "scan":
            out = self._fit_scan_capacity(out, cfg)
        return out

    def _fit_scan_capacity(self, intervals: dict[str, float], cfg: dict) -> dict[str, float]:
        """Compress per-project scan intervals until the cohort can actually
        supply `scan_target_per_day` scans.

        Per-project spacing is a CEILING on how much scanning can happen: with
        19 projects whose intervals run out to 13 days, the schedule runs out of
        eligible projects long before it runs out of planned events, and a
        raised arrival rate produces nothing extra. Scaling the whole range
        preserves the busy/legacy SHAPE (project ranking and relative spacing
        are untouched) — every project simply scans proportionally more often.
        """
        target = getattr(self, "scan_target_per_day", None)
        if not target or not intervals:
            return intervals
        per_project_cap = int(cfg.get("max_per_project_per_day", 3))
        # Headroom: capacity is an upper bound that jitter and the arrival
        # process never fully realize, so aim above the target rather than at it.
        need = float(target) * 1.5
        capacity = sum(min(24.0 / v, per_project_cap) for v in intervals.values() if v > 0)
        if capacity <= 0 or capacity >= need:
            return intervals
        shrink = need / capacity
        # 1h floor: below that "cadence" stops being a plausible human rhythm.
        return {k: max(v / shrink, 1.0) for k, v in intervals.items()}

    def triage_fractions(self, rng: random.Random) -> dict[str, float]:
        """Per-engine fraction of currently-untriaged results a single triage pass
        clears. A pass touches every engine the project has, each at its own biased
        fraction (SAST highest … Containers lowest), scaled by one shared jitter for
        the pass (a 'deeper' review clears more across the board)."""
        fr = self.triage_cfg.get("engine_fractions",
                                 {"sast": 0.20, "sca": 0.12, "iac": 0.08,
                                  "secrets": 0.06, "containers": 0.04})
        lo, hi = self.triage_cfg.get("fraction_jitter", [0.6, 1.5])
        j = rng.uniform(float(lo), float(hi))
        return {eng: round(max(0.0, float(f) * j), 4) for eng, f in fr.items()}

    # ----------------------------------------------------- eligibility
    def _eligible(self, pid: str, kind: str, now: datetime, interval_h: float,
                  last_at: dict, day_count: dict, rng: random.Random) -> bool:
        """A project may take an action of `kind` only if (a) its per-project
        interval has elapsed since the last one (jittered, so cadence isn't
        clockwork) and (b) it's under its per-day cap. This is what keeps any one
        project from being scanned/triaged too often."""
        cfg = self.scan_cfg if kind == "scan" else self.triage_cfg
        cap = int(cfg.get("max_per_project_per_day", 3 if kind == "scan" else 2))
        if day_count[kind].get((pid, now.date()), 0) >= cap:
            return False
        prev = last_at[kind].get(pid)
        if prev is not None:
            if (now - prev).total_seconds() < interval_h * rng.uniform(0.9, 1.1) * 3600.0:
                return False
        return True

    @staticmethod
    def _record(pid: str, kind: str, now: datetime, last_at: dict, day_count: dict) -> None:
        last_at[kind][pid] = now
        key = (pid, now.date())
        day_count[kind][key] = day_count[kind].get(key, 0) + 1

    @staticmethod
    def _seed_ledger(history: dict | None) -> tuple[dict, dict]:
        """Build (last_at, day_count) from a prior-activity history so spacing and
        daily caps carry across separate invocations (cron ticks). `history` is the
        AGENT'S OWN ledger — {'scan': {pid: [datetime...]}, 'triage': {...}} — never
        the tenant's scan history."""
        last_at = {"scan": {}, "triage": {}}
        day_count = {"scan": {}, "triage": {}}
        for kind in ("scan", "triage"):
            for pid, stamps in (history or {}).get(kind, {}).items():
                ds = [s for s in stamps if isinstance(s, datetime)]
                if not ds:
                    continue
                last_at[kind][pid] = max(ds)
                for s in ds:
                    key = (pid, s.date())
                    day_count[kind][key] = day_count[kind].get(key, 0) + 1
        return last_at, day_count

    # ----------------------------------------------------- plan generation
    def generate_plan(self, start: datetime, window_seconds: float,
                      projects: list[dict], rng: random.Random | None = None,
                      history: dict | None = None) -> list[Event]:
        """
        Non-homogeneous Poisson arrivals over [start, start+window], sampled by
        Lewis–Shedler thinning (candidates at peak rate, accepted by hour/weekday
        weight) so events are jittered, cluster in business hours, and low-rate
        stretches can't swallow the next busy period. Every scheduled action then
        passes the per-project spacing + daily-cap gate (see _eligible). `history`
        seeds that gate from prior activity so cadence holds across daemon restarts
        and ticks. Tenant-wide caps bound total per-hour/per-day volume on top.
        """
        rng = rng or random.Random()
        events: list[Event] = []

        # Canonical project key = NAME. Events carry names (that's what executes a
        # scan/triage), and the cross-tick ledger is keyed by name too, so spacing
        # must use the same key. Projects always have names in CxOne.
        def pid_of(p: dict) -> str:
            return str(p.get("name") or p.get("id"))

        keys = [pid_of(p) for p in projects]
        scan_iv = self.interval_map(keys, "scan")        # per-project scan spacing (h)
        # Triage cadence ranks by SCAN order, so busier-scanned projects are also
        # reviewed more often (correlated, like real work).
        triage_iv = self.interval_map(keys, "triage", rank_by="scan")
        # Selection weight ∝ 1/scan-interval, so busier projects are picked more.
        weighted = [(p, 1.0 / scan_iv[pid_of(p)]) for p in projects]
        onboard_pool = list(self.onboard_cfg.get("repos", [])) if self.onboard_cfg.get("enabled") else []
        follow_scan = bool(self.triage_cfg.get("follow_scan", True))

        last_at, day_count = self._seed_ledger(history)
        per_hour_count: dict[int, int] = defaultdict(int)   # tenant-wide caps by hour
        per_day_scans: dict[str, int] = defaultdict(int)
        per_day_triage: dict[str, int] = defaultdict(int)

        # Non-homogeneous Poisson via Lewis–Shedler thinning: draw candidate
        # arrivals at the PEAK rate, then accept each with probability
        # rate(t)/peak. Sampling the gap at the current (e.g. overnight) rate
        # instead would let one draw overshoot an entire business day — a daemon
        # started Sunday evening could plan zero Monday events.
        peak_rate = max(self.peak_rate_per_hour / 3600.0, 1e-9)
        t = 0.0
        max_iter = 100000
        while t < window_seconds and max_iter > 0:
            max_iter -= 1
            t += rng.expovariate(peak_rate)
            if t >= window_seconds:
                break
            now = start + timedelta(seconds=t)
            accept = self.hour_weight(now.hour) * self.weekday_weight(now.weekday())
            if rng.random() >= accept:
                continue  # thinned out (off-hours / weekend)

            etype = _weighted_choice(self.event_mix, rng)
            if etype == "idle":
                continue

            hour_bucket = int(t // 3600)
            day_key = now.strftime("%Y-%m-%d")
            if per_hour_count[hour_bucket] >= self.caps.get("max_events_per_hour", 6):
                continue

            if etype == "scan":
                if per_day_scans[day_key] >= self.caps.get("max_scans_per_day", 20):
                    continue
                lo, hi = self.scan_cfg.get("projects_per_event", [1, 2])
                n = rng.randint(lo, hi)
                # Oversample candidates, then keep only those whose spacing allows it.
                candidates = _weighted_sample(weighted, min(len(weighted), n + 3), rng)
                picks = [p for p in candidates
                         if self._eligible(pid_of(p), "scan", now, scan_iv[pid_of(p)],
                                           last_at, day_count, rng)][:n]
                if not picks:
                    continue
                for p in picks:
                    self._record(pid_of(p), "scan", now, last_at, day_count)
                events.append(Event(now, "scan",
                                    {"projects": [p.get("name") or p.get("id") for p in picks]}))
                per_day_scans[day_key] += 1
                per_hour_count[hour_bucket] += 1

            elif etype == "triage":
                if per_day_triage[day_key] >= self.caps.get("max_triage_per_day", 12):
                    continue
                # Triage reviews a scan's findings, so a project is only triageable
                # when it has an UN-reviewed scan (scanned more recently than last
                # triaged). That ties triage to scans (triage can't exceed scans) and
                # makes 'follow_scan' realistic, on top of the normal spacing gate.
                pool = []
                for p in projects:
                    pid = pid_of(p)
                    last_scan = last_at["scan"].get(pid)
                    if follow_scan and last_scan is None:
                        continue
                    last_tri = last_at["triage"].get(pid)
                    if follow_scan and last_scan is not None and last_tri is not None \
                            and last_scan <= last_tri:
                        continue  # nothing new to review
                    if self._eligible(pid, "triage", now, triage_iv[pid],
                                      last_at, day_count, rng):
                        pool.append(p)
                if not pool:
                    continue
                p = pool[rng.randrange(len(pool))]
                self._record(pid_of(p), "triage", now, last_at, day_count)
                events.append(Event(now, "triage", {
                    "project": p.get("name") or p.get("id"),
                    # per-engine fraction of untriaged to clear this pass (SAST high
                    # .. Containers low); executor/sim applies it to live counts.
                    "fractions": self.triage_fractions(rng),
                }))
                per_day_triage[day_key] += 1
                per_hour_count[hour_bucket] += 1

            elif etype == "onboard":
                if not onboard_pool:
                    continue
                repo = onboard_pool.pop(rng.randrange(len(onboard_pool)))
                events.append(Event(now, "onboard", {"repo": repo}))
                per_hour_count[hour_bucket] += 1

        events.sort(key=lambda e: e.at)
        return events


def _weighted_choice(dist: dict[str, float], rng: random.Random) -> str:
    total = sum(dist.values()) or 1.0
    roll = rng.random() * total
    cum = 0.0
    for k, w in dist.items():
        cum += w
        if roll <= cum:
            return k
    return next(iter(dist))


def _weighted_sample(weighted: list[tuple[dict, float]], n: int,
                     rng: random.Random) -> list[dict]:
    """Sample up to n distinct projects with probability ∝ activity weight."""
    pool = list(weighted)
    out: list[dict] = []
    for _ in range(min(n, len(pool))):
        total = sum(w for _, w in pool) or 1.0
        roll = rng.random() * total
        cum = 0.0
        for i, (p, w) in enumerate(pool):
            cum += w
            if roll <= cum:
                out.append(p)
                pool.pop(i)
                break
    return out


def parse_window(text: str) -> float:
    """'90m', '8h', '3d', '2w' -> seconds."""
    text = (text or "").strip().lower()
    units = {"m": 60, "h": 3600, "d": 86400, "w": 604800}
    if text and text[-1] in units:
        return float(text[:-1]) * units[text[-1]]
    return float(text) * 3600  # bare number = hours
