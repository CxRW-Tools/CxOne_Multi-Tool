"""
Finding references — resolve "the SQLi one in project X" to the IDs an API needs.

Every AI Assist call is keyed by identifiers you cannot see in the UI and that
`results show` never printed: a scan id, a result id, and (for triage
retrieval) a group id. This module turns a human selection — project name plus
an optional name filter, engine, severity, or state — into fully-formed
``FindingRef`` tuples carrying all three, so no one has to copy a base64 blob
by hand.

Four live-verified traps this module exists to absorb (see
``references/cxone-api.md`` "AI Assist"):

1. **The API wants ``alternateId``, not ``id``.** On SAST they happen to be the
   same string, so using ``id`` appears to work; on SCA ``id`` is the CVE
   (``CVE-2017-3589``) while ``alternateId`` is a base64 hash. Anything built on
   ``id`` therefore passes SAST testing and fails silently on SCA.

2. **Result ids are base64 and contain ``/``, ``+`` and ``=``.** They are used
   as PATH segments by the remediation-details endpoint, so they must be
   percent-encoded with ``safe=""`` or the URL structurally breaks. Use
   ``encode_path_segment``.

3. **Initiate and retrieve are keyed differently (triage only).** You POST by
   result id but read back by ``projectID`` + ``groupID``. ``GET /api/risks``
   exposes ``groupId`` directly, but its ``id`` does NOT equal ``alternateId``
   for SCA, so risks cannot be the sole source.

4. **The SAST group id depends on the tenant's grouping mode**, and a wrong one
   fails silently: the POST still triages the findings for real, so the only
   symptom is that every read 404s exactly like an analysis still in flight.
   Attack Vector ID mode needs a vector id that is absent from
   ``GET /api/results``, and ``GET /api/risks`` reports the similarityId in both
   modes — so it agrees with the wrong answer. ``_sast_group_mode_and_vectors``
   resolves mode and vector ids together.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, asdict
from urllib.parse import quote

# Label / location / engine-alias helpers live in results.py. The import is
# one-way (results.py must not import this module) so there is no cycle.
import results as _results

logger = logging.getLogger("cxone.findings")

# AI Triage and AI Remediation are documented and live-confirmed as SAST + SCA
# only. Findings from other engines are never offered to those endpoints.
AI_ENGINES = ("sast", "sca")

# GET /api/risks pages with `limit`, NOT `pageSize`: the service echoes
# whatever `pageSize` you send inside metaData but keeps serving 20 rows, so a
# naive `pageSize=100` silently truncates to the first 20 risks. `limit=100`
# genuinely returns 100. (Live-verified 2026-07-31.)
_RISKS_PAGE_LIMIT = 100

# Attack-vector resolution (see _sast_group_mode_and_vectors).
_SIMILAR_RESULTS_ENDPOINT = "sast-results/similar-results"
_SIMILAR_RESULTS_CHUNK = 100


def encode_path_segment(value: str) -> str:
    """Percent-encode a result/group id for use as a URL path segment.

    ``safe=""`` is the point: result ids are base64 (``/``, ``+``, ``=``) and
    SCA group ids embed ``#-#`` separators. A raw ``/`` would split the path
    into extra segments and a raw ``#`` would truncate the URL at a fragment.
    """
    return quote(str(value), safe="")


@dataclass(frozen=True)
class FindingRef:
    """One finding, with every identifier the AI Assist APIs need."""

    project_id: str
    project_name: str
    scan_id: str
    result_id: str          # alternateId — what triage/remediation consume
    engine: str             # 'sast' | 'sca'
    group_id: str | None    # triage retrieval key; None if underivable
    label: str              # queryName / packageIdentifier
    severity: str
    state: str
    location: str
    # The other grouping mode's key, tried as a fallback on read. Defaulted, so
    # it must stay last — a defaulted field before a required one is a TypeError.
    alt_group_id: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)

    def group_candidates(self) -> list[str]:
        """Group ids to try when reading an analysis back, best guess first.

        Detection can be wrong (or unavailable), and a wrong SAST key returns a
        404 that is indistinguishable from "still running". Reads cost nothing,
        so both candidates are tried rather than trusting detection absolutely.
        """
        return [g for g in (self.group_id, self.alt_group_id) if g]

    def describe(self) -> str:
        loc = f" — {self.location}" if self.location else ""
        return (f"[{self.severity:<8}] {self.engine.upper():<5} {self.label}{loc}\n"
                f"      scan={self.scan_id}\n"
                f"      result={self.result_id}\n"
                f"      group={self.group_id if self.group_id else '(underivable)'}")


def _sast_group_mode_and_vectors(api, scan_id: str,
                                 results: list[dict]) -> tuple[str | None, dict[str, str]]:
    """Resolve the tenant's SAST grouping mode AND each result's attack-vector id.

    ONE call to ``POST sast-results/similar-results`` answers both: the response
    carries ``groupingMode`` (in-band mode detection, no X-Source header needed)
    and a ``similarResults`` entry per result hash whose ``id`` IS the attack
    vector id. Returns ``(mode, {result_hash: attack_vector_id})`` with mode
    normalized to ``"attack-vector"`` / ``"simid"`` / None when undetermined.

    Note the request key is ``resultsHash`` (plural-s, singular-Hash) — sending
    ``resultHash`` returns 400.
    """
    hashes = [((r.get("data") or {}).get("resultHash") or r.get("alternateId"))
              for r in results if (r.get("type") or "").lower() == "sast"]
    hashes = [h for h in hashes if h]
    if not hashes:
        return None, {}
    mode: str | None = None
    vectors: dict[str, str] = {}
    for i in range(0, len(hashes), _SIMILAR_RESULTS_CHUNK):
        chunk = hashes[i:i + _SIMILAR_RESULTS_CHUNK]
        try:
            resp = api.post(_SIMILAR_RESULTS_ENDPOINT,
                            json_body={"scanId": scan_id, "resultsHash": chunk},
                            idempotent=True) or {}   # a pure read despite being POST
        except Exception as exc:                     # noqa: BLE001 - never fatal
            status = getattr(getattr(exc, "response", None), "status_code", None)
            code = None
            if getattr(exc, "response", None) is not None:
                try:
                    code = (exc.response.json() or {}).get("code")
                except ValueError:
                    code = None
            if status == 405 and code == 4005:
                # SAST_ADVANCED_GROUPING_ENABLED is off — this is a Similarity ID
                # tenant answering normally, NOT a failure. Same signal
                # ops/triage/sast_handler.py keys off. Warning here would fire on
                # every run for every simid tenant.
                logger.debug("similar-results: advanced grouping off (405/4005) — "
                             "tenant groups by Similarity ID.")
                return "simid", vectors
            logger.warning("Could not resolve SAST attack-vector ids (%s). If this "
                           "tenant groups by Attack Vector, AI triage retrieval will "
                           "return 404 for SAST findings.", exc)
            return mode, vectors
        raw = str(resp.get("groupingMode") or "").lower()
        if raw:
            mode = "attack-vector" if "attack" in raw else "simid"
        for item in resp.get("similarResults") or []:
            if item.get("resultHash") and item.get("id"):
                vectors[item["resultHash"]] = str(item["id"])
    return mode, vectors


def group_id_for(result: dict, project_id: str) -> str | None:
    """The AI Triage ``group_id`` for a result, or None if underivable.

    Formulas are the documented ones, each confirmed against this tenant's live
    ``GET /api/risks`` output (2026-07-31):

    * **SAST** — depends on the TENANT'S GROUPING MODE, and getting this wrong
      is silent: the write succeeds and only the read 404s.
      - *Similarity ID mode*: the ``similarityId``.
      - *Attack Vector ID mode*: the attack-vector id, which is NOT present on
        ``GET /api/results`` at all and must be resolved via
        ``_sast_group_mode_and_vectors``. ``GET /api/risks`` is no help either —
        its ``groupId`` stays the similarityId in BOTH modes, so it agrees with
        the wrong answer.
      This function only sees one result, so it returns the similarityId (or an
      ``attackVectorID`` if one happens to be attached). ``FindingResolver.find``
      is what applies the mode-aware override; prefer it.
    * **SCA** — ``<similarityId>#-#<packageIdentifier>#-#<projectId>``.
      Verified against live risk group ids.
    """
    engine = (result.get("type") or "").lower()
    data = result.get("data") or {}
    sim = result.get("similarityId")
    if engine == "sast":
        vector = data.get("attackVectorID") or data.get("attackVectorId") \
            or result.get("attackVectorID") or result.get("attackVectorId")
        return str(vector) if vector else (str(sim) if sim is not None else None)
    if engine == "sca":
        package = data.get("packageIdentifier")
        if sim is None or not package:
            return None
        return f"{sim}#-#{package}#-#{project_id}"
    return None


class FindingResolver:
    """Resolves project + filters -> FindingRef list (read-only)."""

    def __init__(self, api):
        self.api = api

    # ------------------------------------------------------------- resolution
    def resolve_project(self, name: str) -> dict | None:
        projects = self.api.paginate("projects", results_key="projects")
        wanted = (name or "").strip().lower()
        exact = next((p for p in projects if (p.get("name") or "").lower() == wanted), None)
        if exact:
            return exact
        # Fall back to a unique substring match so partial project names work
        # the way they do elsewhere in the tool. Ambiguity is an error, never a
        # silent pick — acting on the wrong project is the expensive mistake.
        partial = [p for p in projects if wanted and wanted in (p.get("name") or "").lower()]
        if len(partial) == 1:
            return partial[0]
        if len(partial) > 1:
            logger.error("Project name '%s' is ambiguous — matches %d projects: %s",
                         name, len(partial),
                         ", ".join(sorted(p.get("name", "") for p in partial)[:8]))
            return None
        from ops.project_resolve import warn_unresolved_projects
        warn_unresolved_projects(logger, [name], projects, set())
        return None

    def latest_scan_id(self, project_id: str) -> str | None:
        scan = self.api.get_latest_scan_for_project(
            project_id, statuses=["Completed", "Partial"])
        return scan.get("id") if scan else None

    def find(self, project_name: str, *, engine: str | None = None,
             match: str | None = None, severities: list[str] | None = None,
             states: list[str] | None = None, result_ids: list[str] | None = None,
             scan_id: str | None = None, limit: int | None = None,
             ai_engines_only: bool = True) -> list[FindingRef]:
        """Findings in a project's latest scan (or ``scan_id``), most severe first.

        ``match`` is a case-insensitive substring test against the finding's
        label (SAST query name, SCA package identifier) and its description, so
        ``--match "SQL Injection"`` selects the SQLi findings.
        """
        project = self.resolve_project(project_name)
        if not project:
            return []
        pid, pname = project.get("id"), project.get("name") or project_name
        sid = scan_id or self.latest_scan_id(pid)
        if not sid:
            logger.warning("%s: no Completed/Partial scan to read findings from", pname)
            return []

        result_type = _results.ENGINE_ALIASES.get((engine or "").lower()) if engine else None
        results = self.api.fetch_results(sid, result_type=result_type)

        if ai_engines_only:
            results = [r for r in results if (r.get("type") or "").lower() in AI_ENGINES]
        if severities:
            sev_set = {s.upper() for s in severities}
            results = [r for r in results if _results._norm_sev(r.get("severity")) in sev_set]
        if states:
            state_set = {s.upper().replace(" ", "_") for s in states}
            results = [r for r in results if (r.get("state") or "").upper() in state_set]
        if result_ids:
            wanted_ids = set(result_ids)
            results = [r for r in results
                       if r.get("alternateId") in wanted_ids or r.get("id") in wanted_ids]
        if match:
            needle = match.lower()
            results = [r for r in results if needle in _results._finding_label(r).lower()
                       or needle in (r.get("description") or "").lower()]

        results.sort(key=lambda r: _results._SEV_RANK.get(
            _results._norm_sev(r.get("severity")), 99))
        if limit is not None:
            results = results[:limit]

        # SAST group ids depend on the tenant's grouping mode, so resolve it here
        # (one call, and it doubles as mode detection) rather than guessing
        # per-result. Wrong mode = the AI triage write lands but the read 404s.
        mode, vectors = _sast_group_mode_and_vectors(self.api, sid, results)
        if mode == "attack-vector":
            logger.debug("Tenant groups SAST by Attack Vector ID; using vector ids "
                         "as AI triage group ids (%d resolved).", len(vectors))

        refs = []
        for r in results:
            # alternateId is the identifier the AI Assist APIs accept; `id`
            # differs on SCA and would be rejected. Never substitute it.
            rid = r.get("alternateId")
            if not rid:
                logger.warning("Skipping a %s finding with no alternateId (cannot be "
                               "submitted): %s", r.get("type"), _results._finding_label(r))
                continue
            gid = group_id_for(r, pid)
            alt = None
            if (r.get("type") or "").lower() == "sast":
                vector = vectors.get((r.get("data") or {}).get("resultHash") or rid)
                if mode == "attack-vector":
                    if vector:
                        gid, alt = vector, gid      # vector first, similarityId as backup
                    else:
                        logger.warning("No attack-vector id resolved for '%s' on an "
                                       "Attack-Vector tenant — falling back to its "
                                       "similarityId, which will likely 404 on read.",
                                       _results._finding_label(r))
                elif vector and vector != gid:
                    # Similarity ID mode (or undetected): similarityId leads, but keep
                    # the vector as a fallback so a detection miss is still readable.
                    alt = vector
            refs.append(FindingRef(
                project_id=pid, project_name=pname, scan_id=sid, result_id=rid,
                engine=(r.get("type") or "").lower(),
                group_id=gid, alt_group_id=alt,
                label=_results._finding_label(r),
                severity=_results._norm_sev(r.get("severity")),
                state=(r.get("state") or "").replace("_", " ").title(),
                location=_results._location(r),
            ))
        return refs

    # ------------------------------------------------------------------ risks
    def risks(self, project_id: str) -> list[dict]:
        """GET /api/risks for a project — carries ``groupId`` per risk directly.

        Used as a cross-check for derived group ids. Not the primary source:
        ``risk.id`` equals a SAST result's ``alternateId`` but NOT an SCA one,
        so risks alone cannot drive the initiate path.
        """
        out: list[dict] = []
        offset = 0
        while True:
            page = self.api.get("risks", params={"projectId": project_id,
                                                 "limit": _RISKS_PAGE_LIMIT,
                                                 "offset": offset}) or {}
            chunk = page.get("risks") or []
            out.extend(chunk)
            meta = page.get("metaData") or {}
            total = meta.get("filteredResults") or meta.get("totalResults") or 0
            if len(chunk) < _RISKS_PAGE_LIMIT or len(out) >= total:
                break
            offset += _RISKS_PAGE_LIMIT
        return out


def buckets_from(refs: list[FindingRef]) -> list[dict]:
    """Group refs into the ``buckets`` payload both AI Assist POSTs take.

    One bucket per engine: ``{"scannerType": "sast", "resultIDs": [...]}``.
    """
    by_engine: dict[str, list[str]] = {}
    for ref in refs:
        by_engine.setdefault(ref.engine, [])
        if ref.result_id not in by_engine[ref.engine]:
            by_engine[ref.engine].append(ref.result_id)
    return [{"scannerType": eng, "resultIDs": ids} for eng, ids in sorted(by_engine.items())]
