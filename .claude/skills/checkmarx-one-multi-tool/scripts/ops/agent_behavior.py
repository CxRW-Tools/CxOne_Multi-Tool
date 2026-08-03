"""
Per-run agent behavior overrides — configure ONE agent without editing the
shared config.

`config/activity.yaml` is the tenant-wide default: it is committed, shared, and
read by every future run. Editing it to shape a single agent has two problems —
the change silently becomes everyone's default, and the run you actually
launched is no longer described by anything you can point at afterwards. So the
knobs a person reaches for when spinning up a specific agent (does it triage?
which identities? how sticky are project owners?) resolve the same way project
scope already does:

    CLI flag  >  env var  >  activity.yaml  >  built-in default

Nothing here writes to the config file. An override applies to this invocation
and disappears with it.

**Triage is the important one.** The agent has no assistant in its loop, so any
triage it performs is `triage-simulate` — fabricated states, not a real review.
That is why the shipped default is off, and why turning it on is an explicit,
per-run act rather than a config edit someone inherits.
"""

from __future__ import annotations

from dataclasses import dataclass

# Used when triage is switched on but the config carries no usable weight (the
# shipped default is 0.0). This is the weight the model used before triage was
# turned off, so `--triage` restores the previously-tuned rhythm rather than
# inventing a new one.
DEFAULT_TRIAGE_WEIGHT = 0.53

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def _as_bool(raw: str | None) -> bool | None:
    if raw is None:
        return None
    v = str(raw).strip().lower()
    if v in _TRUE:
        return True
    if v in _FALSE:
        return False
    return None


def _as_float(raw) -> float | None:
    if raw is None or raw == "":
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


@dataclass
class AgentBehavior:
    """Resolved per-run overrides. ``None`` means "defer to activity.yaml"."""

    triage: bool | None = None            # run triage passes at all?
    triage_weight: float | None = None    # explicit event-mix weight
    include_primary: bool | None = None   # may the admin key act?
    affinity: float | None = None         # per-project owner stickiness 0..1

    # ------------------------------------------------------------- resolution
    @classmethod
    def resolve(cls, cli: dict | None = None, env=None) -> "AgentBehavior":
        cli = cli or {}
        env = env if env is not None else {}

        triage = cli.get("triage")
        if triage is None:
            triage = _as_bool(env.get("CXONE_AGENT_TRIAGE"))

        weight = _as_float(cli.get("triage_weight"))
        if weight is None:
            weight = _as_float(env.get("CXONE_AGENT_TRIAGE_WEIGHT"))
        # An explicit weight is itself a request for triage; > 0 implies on,
        # and an explicit 0 implies off, so the two flags cannot contradict.
        if weight is not None and triage is None:
            triage = weight > 0

        identities = cli.get("identities") or env.get("CXONE_AGENT_IDENTITIES")
        include_primary = None
        if identities:
            v = str(identities).strip().lower()
            if v in ("all", "any", "primary"):
                include_primary = True
            elif v in ("secondaries", "secondary", "secondaries-only"):
                include_primary = False

        affinity = _as_float(cli.get("affinity"))
        if affinity is None:
            affinity = _as_float(env.get("CXONE_AGENT_AFFINITY"))
        if affinity is not None:
            affinity = min(1.0, max(0.0, affinity))

        return cls(triage=triage, triage_weight=weight,
                   include_primary=include_primary, affinity=affinity)

    @property
    def active(self) -> bool:
        return any(v is not None for v in
                   (self.triage, self.triage_weight, self.include_primary, self.affinity))

    # ---------------------------------------------------------------- applying
    def apply_to_model(self, model) -> None:
        """Rewrite the loaded ActivityModel's event mix in place.

        Weights are relative and normalized by their sum at selection time, so
        setting triage to 0 does not reduce total activity — the other event
        types simply take its share.
        """
        if self.triage is None and self.triage_weight is None:
            return
        mix = dict(model.event_mix)
        if self.triage is False:
            mix["triage"] = 0.0
        else:
            weight = self.triage_weight
            if weight is None or weight <= 0:
                current = float(mix.get("triage") or 0.0)
                weight = current if current > 0 else DEFAULT_TRIAGE_WEIGHT
            mix["triage"] = float(weight)
        model.event_mix = mix

    def effective_affinity(self, config_value: float) -> float:
        return config_value if self.affinity is None else self.affinity

    def effective_include_primary(self, config_value: bool) -> bool:
        return config_value if self.include_primary is None else self.include_primary

    # ------------------------------------------------------------- reporting
    def describe(self, model=None, *, affinity: float | None = None,
                 include_primary: bool | None = None) -> str:
        """One line naming what this particular agent will do.

        Printed on every run and plan, overridden or not, so the log says what
        the agent's behavior actually was rather than leaving a reader to infer
        it from a config file that may since have changed.
        """
        bits = []
        weight = None if model is None else float(model.event_mix.get("triage") or 0.0)
        if weight is None:
            bits.append("triage: (config)")
        elif weight > 0:
            src = "overridden" if self.triage is not None or self.triage_weight is not None else "config"
            bits.append(f"triage: ON (weight {weight:g}, {src}) — SIMULATED/fabricated states")
        else:
            src = "overridden" if self.triage is not None or self.triage_weight is not None else "config"
            bits.append(f"triage: off ({src})")
        if include_primary is not None:
            who = "all identities incl. primary" if include_primary else "secondaries only"
            src = "overridden" if self.include_primary is not None else "config"
            bits.append(f"identities: {who} ({src})")
        if affinity is not None:
            src = "overridden" if self.affinity is not None else "config"
            bits.append(f"owner affinity: {affinity:g} ({src})")
        return "; ".join(bits)

    # --------------------------------------------------------------- container
    def as_cli_args(self) -> list[str]:
        """Re-express the overrides as flags for the containerized agent.

        The image carries its own baked activity.yaml and cannot see host-side
        flags or env vars, so anything not forwarded here is silently lost —
        the same trap project scope already documents.
        """
        args: list[str] = []
        if self.triage is False:
            args.append("--no-triage")
        elif self.triage is True:
            args.append("--triage")
        if self.triage_weight is not None:
            args += ["--triage-weight", str(self.triage_weight)]
        if self.include_primary is not None:
            args += ["--identities", "all" if self.include_primary else "secondaries"]
        if self.affinity is not None:
            args += ["--affinity", str(self.affinity)]
        return args
