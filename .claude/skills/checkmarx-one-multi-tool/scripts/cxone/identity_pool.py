"""
Multi-identity support: run scans, triage, and other actions as DIFFERENT
CxOne users so tenant history reads like a team, not one admin.

Identities are secondary API keys registered in a sidecar YAML next to the
credentials env file (or wherever CXONE_IDENTITIES_FILE points):

    # cxone-identities.yaml
    identities:
      - name: alice.dev        # optional label; derived from the JWT if omitted
        api_key: "eyJ..."
      - api_key: "eyJ..."      # name derived

Inside the agent container the pool instead arrives as CXONE_IDENTITIES_JSON
(same list, JSON-encoded), delivered via a transient --env-file at launch.

Policy decisions baked in (per operator direction):
  * Every identity can do everything — no per-identity capability config.
  * A 401/403 under a secondary identity FALLS BACK to the primary with a
    warning (a silently failed action is worse than one mis-attributed one).
  * Keys from a DIFFERENT tenant than the primary are refused at load — a
    stale foreign key chosen at random mid-run would be a cross-tenant write.

Selection semantics:
  * Explicit:  pool.client_for("alice.dev")     — --as alice.dev
  * Random:    pool.pick_random(rng)            — --as random (seed-reproducible)
  * Affinity:  pool.pick("scan", project, rng)  — --as auto / the agent
    Affinity is a stable hash of (tenant, kind, key) over ALL identities
    (primary included — the admin is a team member too), so the same person
    "owns" a project's scans and another its triage across runs and days,
    independent of the run seed. A small run-seeded wobble (1 - affinity
    strength) occasionally hands the action to someone else, because real
    teams cover for each other.
"""

from __future__ import annotations

import os
import json
import hashlib
import logging
import random
import threading
from dataclasses import dataclass, replace
from pathlib import Path

import yaml

from .config import CxConfig, is_inside_skill_dir

logger = logging.getLogger("cxone.identities")

PRIMARY = "primary"
_DEFAULT_SIDECAR = "cxone-identities.yaml"
_DEFAULT_AFFINITY = 0.85


def _decode_jwt_claims(token: str) -> dict:
    """Best-effort decode of the JWT payload (no signature verification — we
    only read claims we then verify against the configured tenant)."""
    import base64
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


def _tenant_from_claims(claims: dict) -> str | None:
    t = claims.get("tenant_name") or claims.get("tenant")
    if t:
        return t
    iss = claims.get("iss") or ""
    if "/realms/" in iss:
        return iss.rsplit("/realms/", 1)[1].split("/")[0] or None
    return None


@dataclass
class Identity:
    name: str
    api_key: str
    user_id: str | None = None   # JWT sub — used by purge protection


class FallbackClient:
    """Wraps a secondary identity's ApiClient; any call that raises HTTP
    401/403 is replayed once on the primary client with a warning. Everything
    else (attributes like .config/.auth, non-HTTP errors) passes through the
    secondary untouched."""

    def __init__(self, secondary, primary, name: str):
        self._secondary = secondary
        self._primary = primary
        self._name = name
        self._warned = False

    def __getattr__(self, attr):
        sec = getattr(self._secondary, attr)
        if not callable(sec):
            return sec
        prim = getattr(self._primary, attr, None)

        def call(*a, **k):
            import requests
            try:
                return sec(*a, **k)
            except requests.HTTPError as exc:
                status = exc.response.status_code if exc.response is not None else None
                if status in (401, 403) and callable(prim):
                    if not self._warned:
                        logger.warning(
                            "Identity '%s' got HTTP %s — its role lacks this "
                            "permission; falling back to the primary identity "
                            "for such calls (attribution note: those actions "
                            "will show as the primary user).",
                            self._name, status)
                        self._warned = True
                    return prim(*a, **k)
                raise
        return call


class IdentityPool:
    """Loads and validates secondary identities; hands out clients and picks."""

    def __init__(self, cfg: CxConfig, affinity: float = _DEFAULT_AFFINITY):
        self.cfg = cfg
        self.affinity = min(max(affinity, 0.0), 1.0)
        self._identities: dict[str, Identity] = {}
        self._clients: dict[str, object] = {}
        self._primary_client = None
        self._load()

    # ---------------------------------------------------------------- loading
    def sidecar_path(self) -> Path | None:
        explicit = os.environ.get("CXONE_IDENTITIES_FILE")
        if explicit:
            return Path(explicit)
        if self.cfg.source_env_file:
            return Path(self.cfg.source_env_file).parent / _DEFAULT_SIDECAR
        return None

    def _load(self) -> None:
        entries: list[dict] = []
        blob = os.environ.get("CXONE_IDENTITIES_JSON")
        if blob:
            try:
                entries = json.loads(blob).get("identities", [])
            except (json.JSONDecodeError, AttributeError) as exc:
                logger.error("CXONE_IDENTITIES_JSON is malformed (%s); "
                             "continuing with the primary identity only.", exc)
        else:
            path = self.sidecar_path()
            if path and path.is_file():
                if is_inside_skill_dir(str(path)):
                    # Same posture as the env file: the skill dir is shared and
                    # ephemeral — never a credential store.
                    logger.error(
                        "Refusing identities file inside the skill directory: "
                        "%s — move it next to your cxone.env (or set "
                        "CXONE_IDENTITIES_FILE).", path.resolve())
                else:
                    try:
                        entries = (yaml.safe_load(path.read_text(encoding="utf-8"))
                                   or {}).get("identities", []) or []
                    except (OSError, yaml.YAMLError) as exc:
                        logger.error("Could not read identities file %s (%s); "
                                     "continuing with the primary identity only.",
                                     path, exc)

        for i, entry in enumerate(entries):
            key = (entry or {}).get("api_key") or ""
            if not key:
                logger.warning("Identities entry #%d has no api_key; skipped.", i + 1)
                continue
            claims = _decode_jwt_claims(key)
            tenant = _tenant_from_claims(claims)
            if tenant and tenant != self.cfg.tenant_name:
                logger.error(
                    "Identities entry #%d belongs to tenant '%s' but the "
                    "configured tenant is '%s' — REFUSED (a foreign-tenant key "
                    "picked at random would write to the wrong tenant).",
                    i + 1, tenant, self.cfg.tenant_name)
                continue
            name = (entry.get("name")
                    or claims.get("preferred_username")
                    or claims.get("email")
                    or f"identity-{i + 1}")
            if name == PRIMARY or name in self._identities:
                logger.warning("Identities entry #%d: name '%s' duplicates an "
                               "existing identity; skipped.", i + 1, name)
                continue
            self._identities[name] = Identity(
                name=name, api_key=key, user_id=claims.get("sub"))
        if self._identities:
            logger.info("Identity pool: primary + %d secondary identit%s (%s).",
                        len(self._identities),
                        "y" if len(self._identities) == 1 else "ies",
                        ", ".join(sorted(self._identities)))

    # ---------------------------------------------------------------- access
    def names(self, include_primary: bool = True) -> list[str]:
        out = sorted(self._identities)
        return ([PRIMARY] + out) if include_primary else out

    def has_secondaries(self) -> bool:
        return bool(self._identities)

    def identity(self, name: str) -> Identity | None:
        return self._identities.get(name)

    def user_ids(self) -> set[str]:
        """User ids behind every loaded identity, primary included — the set
        purge must never delete."""
        ids = {i.user_id for i in self._identities.values() if i.user_id}
        sub = _decode_jwt_claims(self.cfg.api_key).get("sub")
        if sub:
            ids.add(sub)
        return ids

    def client_for(self, name: str):
        """ApiClient acting as `name`. Secondary clients are wrapped in the
        401/403->primary FallbackClient. Lazily built and cached."""
        from .api_client import ApiClient  # local import avoids a cycle
        if self._primary_client is None:
            self._primary_client = ApiClient(self.cfg)
        if name in (PRIMARY, None, ""):
            return self._primary_client
        if name not in self._identities:
            raise KeyError(
                f"Unknown identity '{name}'. Available: {', '.join(self.names())}")
        if name not in self._clients:
            sec_cfg = replace(self.cfg, api_key=self._identities[name].api_key)
            self._clients[name] = FallbackClient(
                ApiClient(sec_cfg), self._primary_client, name)
        return self._clients[name]

    # -------------------------------------------------------------- selection
    def pick_random(self, rng: random.Random,
                    include_primary: bool = True) -> str:
        names = self.names(include_primary=include_primary)
        return rng.choice(names) if names else PRIMARY

    def pick(self, kind: str, key: str, rng: random.Random | None = None,
             include_primary: bool = True) -> str:
        """Affinity pick: stable owner for (kind, key) across runs, with a
        run-seeded wobble so coverage looks human. `kind` is 'scan'/'triage';
        `key` is the project (or joined project list for batch scans).
        `include_primary=False` restricts both the owner and the wobble
        alternates to secondaries only (e.g. "only Alice and Bob should
        scan/triage, never the admin key")."""
        names = self.names(include_primary=include_primary)
        if not names:
            return PRIMARY
        if len(names) == 1:
            return names[0]
        digest = hashlib.sha256(
            f"{self.cfg.tenant_name}:{kind}:{key}".encode()).digest()
        owner = names[int.from_bytes(digest[:4], "big") % len(names)]
        if rng is not None and rng.random() > self.affinity:
            others = [n for n in names if n != owner]
            return rng.choice(others)
        return owner

    # --as vocabulary. The -secondary variants EXCLUDE the primary/admin key
    # from selection ("only registered team members act"); the plain forms
    # include it (the admin is a team member too). Excluding secondaries is
    # simply --as primary / no flag.
    SELECTION_SPECS = (PRIMARY, "random", "random-secondary", "auto", "auto-secondary")

    def resolve(self, as_spec: str | None, kind: str, key: str,
                rng: random.Random | None = None) -> str:
        """Map an --as value to an identity name.
        None/'primary' -> primary; 'random'/'random-secondary' -> seeded random
        over all/secondaries-only; 'auto'/'auto-secondary' -> stable affinity
        over all/secondaries-only; anything else -> explicit name.
        The -secondary variants raise ValueError when no secondaries are
        registered — the caller asked for "not the admin" explicitly, so a
        silent primary fallback would violate that intent."""
        if not as_spec or as_spec == PRIMARY:
            return PRIMARY
        if as_spec in self.SELECTION_SPECS:
            base, _, scope = as_spec.partition("-")
            secondaries_only = scope == "secondary"
            if secondaries_only and not self.has_secondaries():
                raise ValueError(
                    f"--as {as_spec} requires registered secondary identities, "
                    "but none are configured — register keys with "
                    "`identities add/import` or use --as random/auto.")
            rng = rng or random.Random()
            if base == "random":
                return self.pick_random(rng, include_primary=not secondaries_only)
            return self.pick(kind, key, rng, include_primary=not secondaries_only)
        if as_spec not in self._identities:
            raise KeyError(
                f"Unknown identity '{as_spec}'. Available: "
                f"{', '.join(self.names())} (or: "
                f"{', '.join(self.SELECTION_SPECS)})")
        return as_spec

    # ------------------------------------------------------------ per-project
    AUTOMATIC_SPECS = ("random", "random-secondary", "auto", "auto-secondary")

    def selector(self, as_spec: str | None, kind: str,
                 seed: int | None = None) -> "IdentitySelector | None":
        """An IdentitySelector for the AUTOMATIC specs, else None.

        None means "one fixed identity for the whole run" — the right answer for
        `primary` and for an explicit name like `--as alice`, which the user
        pinned deliberately.
        """
        if as_spec in self.AUTOMATIC_SPECS:
            return IdentitySelector(self, as_spec, kind, seed)
        return None

    def to_json(self) -> str:
        """Serialize the secondaries for container delivery.

        Lives on the POOL because the pool is what owns `_identities`. It sat on
        IdentitySelector previously, where the attribute does not exist — so the
        agent's call raised AttributeError, got swallowed by the surrounding
        `except Exception`, and every containerized run silently degraded to the
        primary/admin key while reporting only a warning.
        """
        return json.dumps({"identities": [
            {"name": i.name, "api_key": i.api_key}
            for i in self._identities.values()]})


class IdentitySelector:
    """Resolves an automatic `--as` spec to an identity PER PROJECT.

    Why per project: `--as auto` is documented as "stable per-project affinity —
    the same person owns a project across runs". Resolving it ONCE per invocation
    broke that promise for any multi-project command: the whole `--projects` list
    became a single affinity key, so one identity took every project. A 24-project
    heavy triage pass on 2026-07-30 attributed all 1330 decisions to one user for
    exactly this reason.

    Two properties this must hold, both easy to lose:

    * DETERMINISTIC per key, not per call order. Projects are triaged/scanned
      across a thread pool, so drawing from one shared Random would make
      attribution depend on which thread finished first — and `random.Random` is
      not thread-safe. Each key therefore derives its OWN Random from
      (seed, kind, key), so the result is identical whatever the interleaving,
      and a dry-run's "as bob" is the live run's "as bob".
    * SEEDED BY THE SEED THAT GETS PRINTED. The caller must pass the same seed
      the run reports, or `--seed <n>` would reproduce the findings while
      re-rolling the people.
    """

    def __init__(self, pool: "IdentityPool", as_spec: str, kind: str,
                 seed: int | None = None):
        self._pool = pool
        self._spec = as_spec
        self._kind = kind
        self._seed = seed
        self._cache: dict[str, tuple[object, str]] = {}
        self._lock = threading.Lock()

    def name_for(self, key: str) -> str:
        """The identity name owning `key` (a project name)."""
        rng = random.Random(f"{self._seed}|{self._kind}|{key}")
        return self._pool.resolve(self._spec, self._kind, key, rng)

    def for_key(self, key: str) -> tuple[object, str]:
        """(client, identity name) for `key`. Cached; safe from many threads."""
        with self._lock:
            hit = self._cache.get(key)
            if hit is None:
                name = self.name_for(key)
                hit = (self._pool.client_for(name), name)
                self._cache[key] = hit
            return hit


# --------------------------------------------------------------------------
# Sidecar write layer — the programmatic way to register identities, used by
# the `identities add/remove/import` CLI and callable directly. All writes
# validate exactly like loading does (tenant match, JWT decode) so a bad key
# can't enter the file in the first place, and all refuse skill-dir paths.
# --------------------------------------------------------------------------

def _resolve_writable_sidecar(cfg: CxConfig) -> Path:
    explicit = os.environ.get("CXONE_IDENTITIES_FILE")
    if explicit:
        path = Path(explicit)
    elif cfg.source_env_file:
        path = Path(cfg.source_env_file).parent / _DEFAULT_SIDECAR
    else:
        raise ValueError(
            "Cannot resolve an identities file: no CXONE_IDENTITIES_FILE set "
            "and the config wasn't loaded from an env file. Set "
            "CXONE_IDENTITIES_FILE=<project-dir>/cxone-identities.yaml.")
    if is_inside_skill_dir(str(path)):
        raise ValueError(
            f"Refusing to write identities inside the skill directory: "
            f"{path.resolve()} — that location is shared/ephemeral. Point "
            "CXONE_IDENTITIES_FILE at your project's own file.")
    return path


def _read_sidecar(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return list(data.get("identities") or [])


def _write_sidecar(path: Path, entries: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    header = ("# Secondary CxOne identities used for multi-user attribution "
              "(--as / agent).\n# Managed by `identities add/remove/import`; "
              "hand-editing is fine too.\n")
    path.write_text(
        header + yaml.safe_dump({"identities": entries}, sort_keys=False,
                                default_flow_style=False),
        encoding="utf-8")
    try:
        os.chmod(path, 0o600)  # credentials file — owner-only where supported
    except OSError:
        pass


def validate_key(cfg: CxConfig, api_key: str) -> tuple[str, str | None]:
    """Validate a key for THIS tenant; returns (derived_name, user_id).
    Raises ValueError on undecodable or foreign-tenant keys."""
    claims = _decode_jwt_claims(api_key)
    if not claims:
        raise ValueError("API key is not a decodable JWT.")
    tenant = _tenant_from_claims(claims)
    if tenant and tenant != cfg.tenant_name:
        raise ValueError(
            f"Key belongs to tenant '{tenant}' but the configured tenant is "
            f"'{cfg.tenant_name}' — refused.")
    name = (claims.get("preferred_username") or claims.get("email")
            or (claims.get("sub") or "identity")[:12])
    return name, claims.get("sub")


def add_identity(cfg: CxConfig, api_key: str, name: str | None = None,
                 replace: bool = False) -> str:
    """Validate and append one identity; returns the stored name.
    Same-name entries error unless replace=True; a key whose user (JWT sub)
    is already registered under another name is refused (one persona per
    user keeps attribution legible)."""
    derived, sub = validate_key(cfg, api_key)
    name = name or derived
    if name == PRIMARY:
        raise ValueError(f"'{PRIMARY}' is reserved for the cxone.env key.")
    path = _resolve_writable_sidecar(cfg)
    entries = _read_sidecar(path)
    for e in entries:
        esub = _decode_jwt_claims(e.get("api_key", "")).get("sub")
        if sub and esub == sub and e.get("name") != name:
            # Same USER under a different label — refuse: one persona per user
            # keeps attribution legible. (Same name + same user is a key
            # refresh, handled by the replace flow below.)
            raise ValueError(
                f"This key's user is already registered as "
                f"'{e.get('name', '?')}' — remove that entry first.")
    existing = next((e for e in entries if e.get("name") == name), None)
    if existing and not replace:
        raise ValueError(f"Identity '{name}' already exists "
                         "(pass replace/--replace to overwrite its key).")
    if existing:
        existing["api_key"] = api_key
    else:
        entries.append({"name": name, "api_key": api_key})
    _write_sidecar(path, entries)
    logger.info("Identity '%s' %s in %s.", name,
                "updated" if existing else "added", path)
    return name


def remove_identity(cfg: CxConfig, name: str) -> bool:
    """Remove an identity by name; returns True if something was removed."""
    path = _resolve_writable_sidecar(cfg)
    entries = _read_sidecar(path)
    kept = [e for e in entries if e.get("name") != name]
    if len(kept) == len(entries):
        return False
    _write_sidecar(path, kept)
    logger.info("Identity '%s' removed from %s.", name, path)
    return True


def import_identities(cfg: CxConfig, source: str,
                      replace: bool = False) -> tuple[list[str], list[str]]:
    """Bulk-register identities from a file. Accepts:
      * YAML/JSON with an `identities:` list of {name?, api_key} (the sidecar
        format itself — so an exported/shared team file imports directly), or
      * plain text, one API key per line (names derived), '#' comments ok.
    Returns (added_names, error_messages); partial success is fine — every
    key validates independently."""
    text = Path(source).read_text(encoding="utf-8")
    entries: list[dict] = []
    try:
        data = yaml.safe_load(text)
        if isinstance(data, dict) and isinstance(data.get("identities"), list):
            entries = data["identities"]
    except yaml.YAMLError:
        pass
    if not entries:
        entries = [{"api_key": line.strip()}
                   for line in text.splitlines()
                   if line.strip() and not line.strip().startswith("#")]
    added, errors = [], []
    for i, e in enumerate(entries):
        key = (e or {}).get("api_key") or ""
        try:
            if not key:
                raise ValueError("entry has no api_key")
            added.append(add_identity(cfg, key, e.get("name"), replace=replace))
        except ValueError as exc:
            errors.append(f"entry #{i + 1}: {exc}")
    return added, errors
