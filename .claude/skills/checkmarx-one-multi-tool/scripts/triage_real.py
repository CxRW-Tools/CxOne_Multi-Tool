"""
triage-real — genuine review of findings by the coding assistant, then real triage.

The third triage option, and the one that is neither fabricated nor billed:

    triage-simulate    nobody judges — weighted dice pick a state and a canned
                       comment. Fast, free, and entirely made up.
    triage-real        THIS assistant reads the actual scanned source and the
                       data flow, reaches a verdict, and writes a real comment.
    ai-assist triage   Checkmarx's own AI agent judges. Real, and spends credits.

**Why this is two commands, not one.** The Python cannot call the assistant —
the review happens in the chat turn. So the flow is deliberately split, and the
decision file in the middle is the point rather than a workaround: it is
inspectable and editable before anything touches the tenant, and it doubles as
the audit trail of what was decided and why.

    triage-real prepare --project "X" --match "SQL"   -> review packet (JSON)
    <the assistant reviews it and writes decisions JSON>
    triage-real apply --decisions decisions.json      -> dry-run, confirm, write

``apply`` writes through the SAME per-engine handlers as ``triage-simulate``
(``ops/triage/*``), so attack-vector grouping, idempotency, bulk predicates and
dry-run behave identically — only the source of the decision differs.

Two safety properties, both deliberate:

* **No source, no verdict.** If the scanned source can't be fetched and a
  finding therefore can't be genuinely reviewed, it is reported as undecided
  and left untouched. A guess dressed as a review is worse than no review.
* **Supply-chain writes are verified against the GraphQL action store.**
  Malicious / typosquat risk state does not appear in ``GET /api/risks`` or the
  SCA export, so those surfaces cannot be used to confirm a write.
* **Never "Not Exploitable".** That state suppresses a finding outright, which
  is a human's call. A reviewer proposes dismissal with "Proposed Not
  Exploitable" and leaves ratification to a person.

One write-time policy sits on top of the reviewer's verdict:

* **A Critical confirmed by review is written as Urgent.** The reviewer still
  answers the question they are qualified to answer ("is this real?") with
  Confirmed; promoting a confirmed-exploitable Critical into the
  drop-everything tier is a reporting decision, applied once at the write
  boundary so it cannot be forgotten per finding. Severity is read from the
  live result, never from the decisions file. Nothing else is rewritten - other
  severities, and every non-Confirmed verdict (notably dismissals), pass
  through untouched. ``--no-escalate-critical`` records the verdict verbatim.
"""

from __future__ import annotations

import sys
import json
import logging
import argparse
from pathlib import Path

from cxone import CxConfig, ApiClient
from ops.logger import get_logger
from ops.source_fetch import fetch_scan_source, code_window
from ops.triage.base_handler import TriageSummary
from ops.state_normalize import sca_risk_state_to_api
from ops.triage.sast_handler import SASTHandler
from ops.triage.iac_handler import IaCHandler
from ops.triage.sca_handler import (
    SCAHandler, _VULN_BULK as SCA_VULN_BULK,
    _SUPPLY_CHAIN_BULK as SCA_SUPPLY_CHAIN_BULK,
)
from ops.triage.secrets_handler import SecretsHandler
from ops.triage.containers_handler import ContainersHandler
import results as _results

logger = logging.getLogger("cxone.triage_real")

PACKET_VERSION = 1

# States a review may assign. "Not Exploitable" is deliberately absent: it
# suppresses a finding, and that ratification belongs to a person. A reviewer
# proposes with PROPOSED_NOT_EXPLOITABLE instead.
ALLOWED_STATES = ["Confirmed", "Proposed Not Exploitable", "To Verify", "Urgent"]
_ALLOWED_CANON = {s.lower().replace("_", " "): s for s in ALLOWED_STATES}
FORBIDDEN_STATES = {"not exploitable"}

# Real review is slow and token-expensive; a whole project is not reviewable in
# one pass. This bounds a packet to something an assistant can actually read.
DEFAULT_LIMIT = 20

# result `type` -> the handler that owns its predicate writes.
_ENGINE_HANDLERS = {
    "sast": SASTHandler,
    "kics": IaCHandler,
    "sca": SCAHandler,
    "sscs-secret-detection": SecretsHandler,
    "containers": ContainersHandler,
}
# Engines whose verdict genuinely depends on reading code.
_CODE_ENGINES = {"sast", "kics", "sscs-secret-detection"}


def _canon_state(raw: str) -> str | None:
    return _ALLOWED_CANON.get((raw or "").strip().lower().replace("_", " "))


# --------------------------------------------------------------- write policy
# A confirmed-exploitable CRITICAL is not the same class of item as a confirmed
# MEDIUM: it is the queue's "drop everything" tier, and Urgent is the state the
# UI and the analytics KPIs use to say so. Reviewers reason about truth
# ("is this real?") and answer Confirmed; the escalation to Urgent is a
# reporting-policy decision, so it belongs here at the write boundary rather
# than in every reviewer's head. Verdicts other than Confirmed are untouched —
# in particular this never escalates a dismissal.
ESCALATE_SEVERITIES = {"CRITICAL"}
ESCALATE_FROM_STATE = "Confirmed"
ESCALATE_TO_STATE = "Urgent"


def escalated_state(state: str, severity: str) -> str:
    """The state to actually write, applying the critical-confirmed rule."""
    if state == ESCALATE_FROM_STATE and (severity or "").upper() in ESCALATE_SEVERITIES:
        return ESCALATE_TO_STATE
    return state


class TriageRealManager:
    def __init__(self, api: ApiClient):
        self.api = api
        self.cfg = api.config

    # ------------------------------------------------------------- selection
    def _resolve_project(self, name: str) -> dict | None:
        projects = self.api.paginate("projects", results_key="projects")
        wanted = (name or "").strip().lower()
        exact = next((p for p in projects if (p.get("name") or "").lower() == wanted), None)
        if exact:
            return exact
        partial = [p for p in projects if wanted and wanted in (p.get("name") or "").lower()]
        if len(partial) == 1:
            return partial[0]
        if len(partial) > 1:
            logger.error("Project '%s' is ambiguous — %d matches: %s", name, len(partial),
                         ", ".join(sorted(p.get("name", "") for p in partial)[:8]))
        else:
            logger.error("Project not found: '%s'", name)
        return None

    def _select_results(self, project: dict, args) -> tuple[str | None, list[dict]]:
        scan_id = args.scan_id
        if not scan_id:
            scan = self.api.get_latest_scan_for_project(
                project["id"], statuses=["Completed", "Partial"])
            scan_id = scan.get("id") if scan else None
        if not scan_id:
            logger.error("%s: no Completed/Partial scan to review.", project.get("name"))
            return None, []

        result_type = _results.ENGINE_ALIASES.get((args.engine or "").lower()) if args.engine else None
        rows = self.api.fetch_results(scan_id, result_type=result_type)
        rows = [r for r in rows if (r.get("type") or "").lower() in _ENGINE_HANDLERS]
        # SCA state on /api/results is as-of-scan; use the current one so --state
        # filters and "already triaged" reasoning match reality.
        from ops.sca_live_state import enrich_results
        enrich_results(self.api, scan_id, project["id"], rows)

        if args.severity:
            sev = {s.strip().upper() for s in args.severity.split(",") if s.strip()}
            rows = [r for r in rows if _results._norm_sev(r.get("severity")) in sev]
        if args.state:
            st = {s.strip().upper().replace(" ", "_") for s in args.state.split(",") if s.strip()}
            rows = [r for r in rows if (r.get("state") or "").upper() in st]
        if args.result_ids:
            wanted = {s.strip() for s in args.result_ids.split(",") if s.strip()}
            rows = [r for r in rows if r.get("alternateId") in wanted or r.get("id") in wanted]
        if args.match:
            needle = args.match.lower()
            rows = [r for r in rows if needle in _results._finding_label(r).lower()
                    or needle in (r.get("description") or "").lower()]

        rows.sort(key=lambda r: _results._SEV_RANK.get(_results._norm_sev(r.get("severity")), 99))
        if args.limit and len(rows) > args.limit:
            logger.warning("%d findings matched; packing the %d most severe (--limit %d).",
                           len(rows), args.limit, args.limit)
            rows = rows[:args.limit]
        return scan_id, rows

    # --------------------------------------------------------------- prepare
    def prepare(self, args) -> int:
        project = self._resolve_project(args.project)
        if not project:
            return 1
        scan_id, rows = self._select_results(project, args)
        if not scan_id:
            return 1
        if not rows:
            logger.info("No findings matched — nothing to review.")
            return 0

        source_root = None
        if not args.no_source:
            source_root = fetch_scan_source(
                self.api, scan_id, Path(args.source_dir) if args.source_dir
                else Path(args.out).resolve().parent / ".cxone-source")
        if source_root is None and not args.no_source:
            logger.warning("Scanned source unavailable — findings that need code to judge "
                           "will be packed as NOT REVIEWABLE and must be left untriaged.")

        findings = []
        for r in rows:
            engine = (r.get("type") or "").lower()
            data = r.get("data") or {}
            nodes = data.get("nodes") or []
            primary_file = data.get("fileName") or (nodes[0].get("fileName") if nodes else None)
            primary_line = data.get("line") or (nodes[0].get("line") if nodes else None)

            windows = []
            if source_root is not None:
                seen = set()
                # Source, sink and the primary location: the three a reviewer
                # actually needs. Sink last so it reads in flow order.
                spots = []
                if nodes:
                    spots.append((nodes[0].get("fileName"), nodes[0].get("line")))
                    if len(nodes) > 1:
                        spots.append((nodes[-1].get("fileName"), nodes[-1].get("line")))
                spots.append((primary_file, primary_line))
                for f, ln in spots:
                    if not f or not ln or (f, ln) in seen:
                        continue
                    seen.add((f, ln))
                    w = code_window(source_root, f, ln)
                    if w:
                        windows.append(w)

            reviewable = bool(windows) or engine not in _CODE_ENGINES
            findings.append({
                "engine": engine,
                "result_id": r.get("alternateId"),
                "similarity_id": r.get("similarityId"),
                "label": _results._finding_label(r),
                "severity": _results._norm_sev(r.get("severity")),
                "current_state": r.get("state"),
                "location": _results._location(r),
                "description": (r.get("description") or "").strip(),
                "cwe": (r.get("vulnerabilityDetails") or {}).get("cweId"),
                "package": data.get("packageIdentifier"),
                "data_flow": [{"file": n.get("fileName"), "line": n.get("line"),
                               "name": n.get("name"), "method": n.get("method"),
                               "type": n.get("domType")} for n in nodes],
                "code": windows,
                "reviewable": reviewable,
                "not_reviewable_reason": None if reviewable else
                    ("no scanned source available for this file — cannot judge "
                     "this engine's finding without reading the code"),
            })

        packet = {
            "packet_version": PACKET_VERSION,
            "tenant": self.cfg.tenant_name,
            "project": {"id": project["id"], "name": project.get("name")},
            "scan_id": scan_id,
            "source": {"available": source_root is not None,
                       "root": str(source_root) if source_root else None},
            "allowed_states": ALLOWED_STATES,
            "instructions": (
                "Review each finding against its code windows and data flow. For each, "
                "emit {result_id, engine, state, comment} into a decisions file — state "
                "MUST be one of allowed_states ('Not Exploitable' is not permitted; use "
                "'Proposed Not Exploitable' to propose dismissal). The comment is written "
                "in a plain analyst voice, cites the specific code reason, and carries no "
                "AI/tool attribution. If a finding cannot be judged from what is here, "
                "OMIT it or set state to null with a reason — never guess. "
                "Judge exploitability only: answer 'Confirmed' for anything you find "
                "genuinely exploitable regardless of its severity. Critical findings you "
                "confirm are written to the tenant as 'Urgent' automatically — that "
                "promotion is applied at write time, so do not pre-empt it by answering "
                "'Urgent' yourself."
            ),
            "findings": findings,
        }
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(packet, indent=2))
        n_review = sum(1 for f in findings if f["reviewable"])
        logger.info("Review packet: %d finding(s) (%d reviewable, %d not) -> %s",
                    len(findings), n_review, len(findings) - n_review, out)
        if n_review < len(findings):
            logger.warning("%d finding(s) have no readable source and MUST NOT be triaged.",
                           len(findings) - n_review)
        return 0

    # ----------------------------------------------------------------- apply
    def apply(self, args) -> int:
        escalate = not getattr(args, "no_escalate_critical", False)
        path = Path(args.decisions)
        if not path.is_file():
            logger.error("Decisions file not found: %s", path)
            return 1
        try:
            doc = json.loads(path.read_text())
        except ValueError as exc:
            logger.error("Decisions file is not valid JSON: %s", exc)
            return 1
        decisions = doc.get("decisions") if isinstance(doc, dict) else doc
        if not isinstance(decisions, list) or not decisions:
            logger.error("Decisions file carries no 'decisions' list.")
            return 1

        project_id = (doc.get("project") or {}).get("id") if isinstance(doc, dict) else None
        project_name = (doc.get("project") or {}).get("name") if isinstance(doc, dict) else None
        scan_id = doc.get("scan_id") if isinstance(doc, dict) else None
        if not project_id or not scan_id:
            if not args.project:
                logger.error("Decisions file lacks project/scan_id — pass --project.")
                return 1
            project = self._resolve_project(args.project)
            if not project:
                return 1
            project_id, project_name = project["id"], project.get("name")
            scan = self.api.get_latest_scan_for_project(project_id,
                                                        statuses=["Completed", "Partial"])
            scan_id = scan.get("id") if scan else None
        if not scan_id:
            logger.error("No scan to apply against.")
            return 1

        # Validate every decision BEFORE touching the tenant — a half-applied
        # batch is worse than a rejected one.
        valid, skipped = [], []
        for d in decisions:
            rid = d.get("result_id") or d.get("resultId")
            raw_state = d.get("state")
            comment = (d.get("comment") or "").strip()
            if not rid:
                skipped.append(("(no result_id)", "missing result_id")); continue
            if raw_state in (None, "", "undecided"):
                skipped.append((rid, d.get("reason") or "undecided — left untriaged")); continue
            if (raw_state or "").strip().lower() in FORBIDDEN_STATES:
                skipped.append((rid, "'Not Exploitable' is not permitted from a review; "
                                     "use 'Proposed Not Exploitable'")); continue
            state = _canon_state(raw_state)
            if not state:
                skipped.append((rid, f"unknown state '{raw_state}' (allowed: "
                                     f"{', '.join(ALLOWED_STATES)})")); continue
            if not comment:
                skipped.append((rid, "no comment — a real review must say why")); continue
            valid.append({"result_id": rid, "state": state, "comment": comment})

        if skipped:
            logger.warning("%d decision(s) will NOT be applied:", len(skipped))
            for rid, why in skipped:
                logger.warning("  %-46s %s", str(rid)[:46], why)
        if not valid:
            logger.error("Nothing valid to apply.")
            return 1

        rows = {r.get("alternateId"): r for r in self.api.fetch_results(scan_id)}
        by_engine: dict[str, list[dict]] = {}
        missing = []
        escalated = []
        for d in valid:
            row = rows.get(d["result_id"])
            if not row:
                missing.append(d["result_id"]); continue
            row = dict(row)
            state = d["state"]
            if escalate:
                # Severity comes from the live result, not the decisions file, so
                # a reviewer cannot mis-state it and the rule can't be sidestepped.
                promoted = escalated_state(state, row.get("severity") or "")
                if promoted != state:
                    escalated.append(_results._finding_label(row)[:46])
                    state = promoted
            row["_matched_rule"] = {"state": state, "comment": d["comment"]}
            by_engine.setdefault((row.get("type") or "").lower(), []).append(row)
        if escalated:
            logger.info("Policy: %d Critical finding(s) confirmed by review are being "
                        "written as '%s' rather than '%s' (pass --no-escalate-critical "
                        "to record the reviewer's verdict verbatim):",
                        len(escalated), ESCALATE_TO_STATE, ESCALATE_FROM_STATE)
            for label in escalated:
                logger.info("    %s", label)
        if missing:
            logger.warning("%d decision(s) reference results not in scan %s: %s",
                           len(missing), scan_id, ", ".join(missing[:5]))

        logger.info("Applying %d reviewed decision(s) to '%s' (scan %s)%s",
                    sum(len(v) for v in by_engine.values()), project_name or project_id,
                    scan_id, " [DRY-RUN]" if self.cfg.dry_run else "")
        summaries = []
        for engine, batch in sorted(by_engine.items()):
            handler_cls = _ENGINE_HANDLERS.get(engine)
            if not handler_cls:
                logger.warning("No handler for engine '%s' — skipping %d.", engine, len(batch))
                continue
            for row in batch:
                logger.info("  [%s] %-34s -> %-26s %s", engine.upper(),
                            _results._finding_label(row)[:34],
                            row["_matched_rule"]["state"],
                            row["_matched_rule"]["comment"][:70])
            handler = self._build_handler(engine, handler_cls)
            summary = TriageSummary(engine=engine, project_name=project_name or "",
                                    project_id=project_id, scan_id=scan_id)
            # The handlers normally reach apply_triage via their own process()
            # pipeline, which primes per-engine context first. We bypass that
            # (the decisions come from a file, not from rules), so prime the
            # bits apply_triage actually reads.
            handler._ctx_key = (project_id, scan_id)
            if engine == "sca":
                self._apply_sca(handler, batch, project_id, project_name or "",
                                scan_id, summary)
                summaries.append(summary)
                continue
            if engine == "sast":
                batch = self._prime_sast(handler, batch, scan_id, summary)
                if not batch:
                    summaries.append(summary)
                    continue
            try:
                handler.apply_triage(project_id, batch, summary)
            except Exception as exc:                      # noqa: BLE001
                logger.error("[%s] apply failed: %s", engine, exc)
                summary.errors.append(str(exc))
            summaries.append(summary)

        applied = sum(s.results_applied for s in summaries)
        errors = sum(len(s.errors) for s in summaries)
        logger.info("=" * 60)
        logger.info("Reviewed triage %s: %d applied, %d skipped by validation, %d error(s)",
                    "planned" if self.cfg.dry_run else "complete",
                    applied, len(skipped), errors)
        for s in summaries:
            for e in s.errors:
                logger.error("  [%s] %s", s.engine, e)
        return 1 if errors else 0

    def _apply_sca(self, handler, batch: list[dict], project_id: str,
                   project_name: str, scan_id: str, summary: TriageSummary) -> None:
        """Write SCA decisions through the handler's management-of-risk bulk path.

        SCA is the one engine with no ``apply_triage``: it overrides ``process``
        and writes via ``sca/management-of-risk/*`` bulk endpoints, which need
        PackageName / PackageVersion / PackageManager plus the risk id — fields
        that live in the SCA export, NOT in ``GET /api/results``. So fetch the
        export and join on the risk id (the export's ``Id`` equals the result's
        ``id`` — the CVE or Cx advisory id; note that is `id`, NOT `alternateId`,
        which is the reverse of what the AI Assist endpoints want).

        Regular CVEs and supply-chain risks (malicious packages) post to
        different endpoints with different id fields, so they are split by the
        handler's own ``_is_supply_chain``.
        """
        report = handler._get_sca_report(scan_id, project_name)
        if not report:
            summary.errors.append("SCA export unavailable — cannot resolve package "
                                  "identifiers, so no SCA decision was written.")
            return
        by_id = {}
        for key in ("Vulnerabilities", "vulnerabilities", "Risks", "risks"):
            for item in (report.get(key) or []):
                if item.get("Id"):
                    by_id.setdefault(str(item["Id"]), item)
        vuln_groups: dict[tuple, list[dict]] = {}
        chain_groups: dict[tuple, list[dict]] = {}
        for row in batch:
            rid = str(row.get("id") or "")        # CVE / Cx id, the export's key
            item = by_id.get(rid)
            if not item:
                msg = (f"No SCA export entry for '{rid}' — cannot resolve its package "
                       "identifiers; left untriaged.")
                logger.warning(msg)
                summary.errors.append(msg)
                continue
            rule = row["_matched_rule"]
            key = (sca_risk_state_to_api(rule["state"]), rule["comment"])
            target = chain_groups if handler._is_supply_chain(item) else vuln_groups
            target.setdefault(key, []).append(item)
            summary.results_matched += 1
        intended: dict[str, str] = {}
        if vuln_groups:
            handler._post_risk_groups(
                SCA_VULN_BULK, "packageVulnerabilitiesProfile", "vulnerabilityId",
                project_id, vuln_groups, summary, "vuln")
            for (state_api, _c), items in vuln_groups.items():
                intended.update({str(i.get("Id")): state_api for i in items})
        if chain_groups:
            handler._post_risk_groups(
                SCA_SUPPLY_CHAIN_BULK, "packageSupplyChainRisks", "supplyChainRiskId",
                project_id, chain_groups, summary, "supply-chain")
            # Supply-chain state is NOT visible in /api/risks — verify it against
            # the GraphQL action store instead (see sca_handler.supply_chain_state).
            from ops.sca_live_state import supply_chain_state, risk_uuid_map
            uuids = risk_uuid_map(self.api, project_id)
            for (state_api, _c), items in chain_groups.items():
                for i in items:
                    got = supply_chain_state(
                        self.api, scan_id, project_id,
                        package_name=i.get("PackageName"),
                        package_version=i.get("PackageVersion"),
                        package_manager=i.get("PackageManager"),
                        risk_uuid=uuids.get(str(i.get("Id")), str(i.get("Id"))))
                    if got and got.replace("_", "").lower() == state_api.replace("_", "").lower():
                        continue
                    logger.warning("Supply-chain risk %s reads back as %s (wanted %s).",
                                   i.get("Id"), got or "no action recorded", state_api)
                    summary.results_applied = max(0, summary.results_applied - 1)
                    summary.results_unresolved += 1
        if intended and not self.cfg.dry_run:
            self._verify_sca(scan_id, intended, summary)

    def _verify_sca(self, scan_id: str, intended: dict[str, str],
                    summary: TriageSummary) -> None:
        """Confirm SCA writes landed, and un-count any that did not.

        Verification reads the CURRENT state, not the scan's. SCA scans are
        immutable, so `/api/results` and the SCA export keep reporting the
        as-of-scan value however the risk is triaged — checking those reports
        perfectly good writes as failures, which is exactly the mistake this
        method exists to prevent (see ops/sca_live_state.py).

        Supply-chain risks are verified separately by the caller, since they are
        absent from the bulk view and need one action-store query each.
        """
        import time
        time.sleep(4)                      # the state store lags the write slightly
        from ops.sca_live_state import live_vuln_states, to_result_state
        actual = live_vuln_states(self.api, scan_id)
        if not actual:
            logger.warning("Could not read current SCA states; counts are unconfirmed.")
            return
        unlanded = []
        for rid, want in intended.items():
            got = actual.get(rid)
            if got is None:
                continue                   # not in this view (supply-chain) — checked elsewhere
            if to_result_state(got) != to_result_state(want):
                unlanded.append((rid, want, got))
        if unlanded:
            summary.results_applied = max(0, summary.results_applied - len(unlanded))
            summary.results_unresolved += len(unlanded)
            msg = (f"{len(unlanded)} SCA decision(s) did not take effect — they remain "
                   f"untriaged.")
            logger.error(msg)
            summary.errors.append(msg)
            for rid, want, got in unlanded:
                logger.error("    %-22s wanted %-26s still %s", rid, want, got)

    def _prime_sast(self, handler, batch: list[dict], scan_id: str,
                    summary: TriageSummary) -> list[dict]:
        """Annotate SAST rows so the handler's attack-vector path can write them.

        In Attack Vector mode the handler groups by ``_av_id``, which normally
        arrives from its own fetch + similar-results resolution. Results straight
        off ``GET /api/results`` carry the hash under ``data.resultHash``, so
        lift it, then let the handler resolve vectors exactly as it would
        natively. Rows that still have no vector are dropped with a clear
        message rather than crashing the whole batch.
        """
        for row in batch:
            data = row.get("data") or {}
            row.setdefault("resultHash", data.get("resultHash") or row.get("alternateId"))
            row.setdefault("languageName", data.get("languageName"))
            row.setdefault("_av_severity", row.get("severity"))
        if handler._effective_mode() != "attack-vector":
            return batch
        handler._resolve_vector_ids(scan_id, batch)
        usable = [r for r in batch if r.get("_av_id")]
        for r in batch:
            if not r.get("_av_id"):
                msg = (f"No attack-vector id for '{_results._finding_label(r)}' — this "
                       "tenant groups SAST by Attack Vector and the write needs one; "
                       "left untriaged.")
                logger.warning(msg)
                summary.errors.append(msg)
        return usable

    def _build_handler(self, engine: str, handler_cls):
        """A handler with NO rules and NO realism — decisions come from the file.

        The rule/realism machinery is what fabricates states in
        ``triage-simulate``; here only ``apply_triage`` is used, which reads
        ``_matched_rule`` off each result.
        """
        kwargs = dict(config=self.cfg, api=self.api, dry_run=self.cfg.dry_run,
                      logger=get_logger(f"triage-real.{engine}"), realism=None)
        if handler_cls is SCAHandler:
            return handler_cls(risk_rules=[], package_rules=[], **kwargs)
        if handler_cls is SASTHandler:
            return handler_cls(rules=[], grouping=None, **kwargs)
        return handler_cls(rules=[], **kwargs)


def _peek_project_key(decisions_path: str) -> str | None:
    """Read just enough of a decisions file to get its project name/id, so
    `--as auto` can key its affinity pick the same way it would for a
    triage-simulate pass on that project. Best-effort: a bad path/JSON here
    just falls through to the generic 'triage-real' affinity key."""
    try:
        doc = json.loads(Path(decisions_path).read_text())
    except (OSError, ValueError):
        return None
    if isinstance(doc, dict):
        proj = doc.get("project") or {}
        return proj.get("name") or proj.get("id")
    return None


def _resolve_identity(cfg: CxConfig, args) -> tuple[ApiClient, str | None]:
    """Map `apply --as ...` to an ApiClient acting as that identity.

    Mirrors multitool.py's scan/triage-simulate resolution (same
    IdentityPool, same seeded 'random'/'auto' + '-secondary' specs), adapted
    to the fact that one `apply` call already targets a single project/scan
    rather than a batch: an explicit name, or the default (no --as), pins one
    identity for the whole call; 'random'/'auto' resolve ONCE, keyed by the
    decisions file's project so 'auto' hands a project to the same stable
    owner triage-simulate would. No secondaries configured -> 'random'/'auto'
    fall back to primary with a log line; the '-secondary' variants fail
    loudly instead, since that's an explicit "not the admin" request.
    """
    as_spec = getattr(args, "as_identity", None)
    if not as_spec:
        return ApiClient(cfg), None
    from cxone.identity_pool import IdentityPool
    import random as _random
    pool = IdentityPool(cfg)
    if as_spec in ("random", "auto") and not pool.has_secondaries():
        logger.info("No secondary identities configured (%s missing or empty) — "
                    "acting as primary.", pool.sidecar_path() or "identities file")
        return ApiClient(cfg), None
    key = args.project or _peek_project_key(args.decisions) or "triage-real"
    seed = args.seed if args.seed is not None else _random.SystemRandom().randint(0, 2**31 - 1)
    try:
        name = pool.resolve(as_spec, "triage", key, _random.Random(seed))
    except (KeyError, ValueError) as exc:
        print(f"error: {exc.args[0]}", file=sys.stderr)
        raise SystemExit(2)
    if as_spec in pool.AUTOMATIC_SPECS:
        logger.info("Identity seed: %d (pass --seed %d to reproduce this pick)", seed, seed)
    logger.info("Acting as identity '%s' (--as %s)", name, as_spec)
    return pool.client_for(name), name


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="triage-real",
        description="Real review of findings by the coding assistant, then real triage. "
                    "Not simulated (see triage-simulate) and not Checkmarx Assist "
                    "(see ai-assist triage).")
    p.add_argument("--env", default=None)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--debug", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("prepare", help="build a review packet (findings + scanned source)")
    pr.add_argument("--project", required=True)
    pr.add_argument("--match", default=None, help="substring of the finding name/description")
    pr.add_argument("--engine", default=None,
                    choices=["sast", "sca", "iac", "kics", "secrets", "containers"])
    pr.add_argument("--severity", default=None, help="comma-separated: Critical,High,...")
    pr.add_argument("--state", default=None, help="comma-separated current states")
    pr.add_argument("--result-ids", default=None, help="comma-separated alternateId values")
    pr.add_argument("--scan-id", default=None)
    pr.add_argument("--limit", type=int, default=DEFAULT_LIMIT,
                    help=f"max findings per packet (default {DEFAULT_LIMIT})")
    pr.add_argument("--out", default="review-packet.json", help="where to write the packet")
    pr.add_argument("--source-dir", default=None, help="where to extract scanned source")
    pr.add_argument("--no-source", action="store_true",
                    help="skip the source download (findings needing code become unreviewable)")

    ap = sub.add_parser("apply", help="apply reviewed decisions (dry-run first)")
    ap.add_argument("--decisions", required=True, help="decisions JSON from the review")
    ap.add_argument("--project", default=None, help="only if the file lacks project/scan")
    ap.add_argument("--as", dest="as_identity", default=None, metavar="IDENTITY",
                    help="act as this identity from cxone-identities.yaml; 'random'/'auto' "
                         "pick over ALL identities (seeded random / stable per-project "
                         "affinity, same as scan/triage-simulate); 'random-secondary'/"
                         "'auto-secondary' do the same EXCLUDING the primary/admin key; "
                         "default: primary")
    ap.add_argument("--seed", type=int, default=None,
                    help="reproduce a prior apply's identity pick with --as random/auto "
                         "(the dry-run prints the seed it used; pass it here for the live run)")
    ap.add_argument("--no-escalate-critical", action="store_true",
                    help="write a reviewer's 'Confirmed' verdict verbatim on Critical "
                         "findings. By default a Critical confirmed by review is written "
                         "as 'Urgent', since a confirmed-exploitable Critical is the "
                         "drop-everything tier; other severities and other verdicts are "
                         "never changed.")

    args = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = CxConfig.from_env(args.env)
    cfg.dry_run = cfg.dry_run or args.dry_run
    if args.cmd == "apply":
        api, _acting = _resolve_identity(cfg, args)
    else:
        api = ApiClient(cfg)
    mgr = TriageRealManager(api)
    return mgr.prepare(args) if args.cmd == "prepare" else mgr.apply(args)


if __name__ == "__main__":
    sys.exit(main())
