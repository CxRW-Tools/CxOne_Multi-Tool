#!/usr/bin/env python3
"""
OpenAPI spec validator for the Checkmarx One Multi-Tool.

Cross-checks the endpoints the skill actually uses against a Checkmarx One
OpenAPI document, in both directions:

  1. CODE -> SPEC : every endpoint our handlers/managers call should exist in the
     spec (flags drift when Checkmarx changes a path, and surfaces paths we rely
     on that the published export omits, e.g. repos-manager projectScan).
  2. DOCS -> SPEC : every concrete `/api/...` path written in references/*.md
     should exist in the spec (catches stale/guessed paths in planned-features.md
     and cxone-api.md).

It also reports template-path matches (so `/api/projects/{id}` matches our
`projects/{pid}`), and lists spec endpoints we don't use (informational only).

Usage:
    python validate_spec.py --spec /path/to/cxone_openapi.json
    python validate_spec.py --spec spec/cxone_openapi.json --strict   # nonzero exit on CODE->SPEC misses

Exit codes: 0 = clean (or only known-omitted/among allowlist); 1 = drift found
(in --strict, any unexplained CODE->SPEC miss). Network-free, stdlib + the spec.
"""

from __future__ import annotations

import re
import sys
import json
import argparse
from pathlib import Path

# Endpoints the platform has but the published OpenAPI export is known to omit.
# These are live-validated in our code; absence in the spec is expected, not drift.
KNOWN_SPEC_OMISSIONS = {
    ("POST", "/api/repos-manager/scms/{}/orgs/{}/repo/projectScan"),
    # Attack-vector SAST triage (AST-87380 / FR-022): newer than the bundled
    # OpenAPI export. Schema per the feature spec; flag-gated
    # (SAST_ADVANCED_GROUPING_ENABLED). Refresh the bundled spec when a new
    # export includes it.
    ("POST", "/api/sast-results-predicates/attack-vector"),
    # NOTE (not scraper-visible, listed for the reader): sast_handler.py also
    # calls, via constants the endpoint scraper does not pick up:
    #   GET  /api/sast-configuration            (mode read; X-Source gated)
    #   GET  /api/sast-results/                 (AV-mode listing)
    #   POST /api/sast-results/similar-results  (hash -> vector-id resolver)
    #   GET  /api/sast-results/compare          (fallback id source)
    # Same newer-than-spec status.
}

# Paths that are intentionally non-/api (auth plane, cloud insights base, etc.)
NON_API_OK_PREFIXES = ("/auth/realms/", "/accounts/")


# --------------------------------------------------------------------------- spec
def load_spec_paths(spec_path: Path) -> dict[str, set[str]]:
    """Return {normalized_path: {METHODS}} from an OpenAPI doc."""
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    out: dict[str, set[str]] = {}
    for raw, item in spec.get("paths", {}).items():
        methods = {m.upper() for m in item
                   if m.lower() in ("get", "post", "put", "patch", "delete", "head", "options")}
        out[_norm(raw)] = methods
    return out


def _norm(path: str) -> str:
    """Normalize a path for comparison: strip /api prefix, lowercase the fixed
    segments, and replace any {param} or our f-string {expr} with a {} wildcard."""
    p = path.strip()
    # Collapse python f-string expressions first (e.g. {p['id']}, {user["id"]}),
    # including ones that lost their closing brace to the regex, then {param}.
    p = re.sub(r"\{[^}/]*$", "{}", p)          # dangling '{p[' at end of capture
    p = re.sub(r"\{[^}]*\}", "{}", p)          # {scanId}, {p['id']} -> {}
    p = re.sub(r"\{[^/]*\[.*", "{}", p)        # any residual {x[... -> {}
    if not p.startswith("/"):
        p = "/" + p
    if p.startswith("/api/"):
        p = p[len("/api"):]
    return p.rstrip("/") or "/"


# Normalized paths that are dynamically built at runtime (signed URLs, status
# URLs returned by the API) rather than static endpoints — not validatable.
DYNAMIC_PATHS = {
    "/{}/{}",          # download_sca_export(file_url): GETs a runtime signed URL
}
IAM_PLANE_PATHS = {
    "/groups", "/groups/{}", "/users", "/users/{}",
    "/users/{}/groups", "/users/{}/groups/{}", "/users/{}/reset-password",
    "/users/{}/role-mappings/realm", "/roles",
    # Client (ast-app) role assignment for demo personas — Keycloak admin API.
    "/clients", "/clients/{}/roles", "/users/{}/role-mappings/clients/{}",
}


# ------------------------------------------------------------------- code endpoints
# Maps each module's verb-call to an HTTP method.
_VERB_METHOD = {"get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH",
                "delete": "DELETE", "paginate": "GET"}

# Calls like api.post("applications", ...) / self.api.get(f"projects/{pid}")
_CALL_RE = re.compile(
    r"""(?:^|[^A-Za-z_])(?:self\.)?(?:api|client)\.(get|post|put|patch|delete|paginate)\(\s*f?["']([^"']+)["']""",
    re.MULTILINE,
)
# Explicit endpoint string constants used by handlers (e.g. _VULN_BULK = "sca/.../bulk")
_CONST_RE = re.compile(r'^[A-Z_]+\s*=\s*"([a-z][a-z0-9/_-]*(?:predicates|bulk|update|requests|changelog|imports|projectScan)[a-z0-9/_-]*)"', re.MULTILINE)


def collect_code_endpoints(scripts_dir: Path) -> set[tuple[str, str]]:
    """Return {(METHOD, normalized_path)} discovered in the skill's scripts."""
    found: set[tuple[str, str]] = set()
    const_paths: dict[str, str] = {}     # CONST name -> path (for handlers that post(_CONST))
    for py in scripts_dir.rglob("*.py"):
        text = py.read_text(encoding="utf-8", errors="replace")
        for verb, path in _CALL_RE.findall(text):
            if not _looks_like_path(path):
                continue
            found.add((_VERB_METHOD[verb], _norm(path)))
        for cpath in _CONST_RE.findall(text):
            found.add(("POST", _norm(cpath)))   # these constants are all POST targets
    return found


def _looks_like_path(s: str) -> bool:
    # Exclude obvious non-endpoint first args (dict keys, env names, headers).
    if not s or s != s.strip():
        return False
    if s.isupper() or "_" in s.split("/")[0] and "/" not in s:
        # things like CXONE_API_KEY, Content-Length handled below
        pass
    if re.match(r"^[A-Z][A-Za-z]+$", s):        # 'Severity', 'Handler', etc.
        return False
    if s in ("api", "data", "value", "name", "type", "status", "result", "error"):
        return False
    # Must look like an API path: a known root or a slash.
    roots = ("applications", "projects", "scans", "groups", "users", "roles",
             "configuration/", "repos-manager", "sca/", "sast-results", "kics-results",
             "micro-engines", "containers/", "results", "reports", "audit",
             "custom-states", "feedback", "byor", "uploads", "policy")
    return "/" in s or s in ("applications", "projects", "scans", "groups", "users", "roles") \
        or s.startswith(roots)


# ------------------------------------------------------------------- doc endpoints
_DOC_PATH_RE = re.compile(r"(GET|POST|PUT|PATCH|DELETE)\s+(/api/[A-Za-z0-9_{}\-/]+)")


def collect_doc_endpoints(refs_dir: Path) -> set[tuple[str, str, str]]:
    """Return {(METHOD, normalized_path, file)} for concrete /api paths in docs."""
    found: set[tuple[str, str, str]] = set()
    for md in refs_dir.rglob("*.md"):
        text = md.read_text(encoding="utf-8", errors="replace")
        for method, path in _DOC_PATH_RE.findall(text):
            found.add((method, _norm(path), md.name))
    return found


# ------------------------------------------------------------------- matching
def spec_has(spec: dict[str, set[str]], method: str, npath: str) -> str:
    """Return 'exact', 'method-missing', or 'absent' for a normalized path."""
    if npath in spec:
        return "exact" if method in spec[npath] else "method-missing"
    return "absent"


# ------------------------------------------------------------------- main
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Validate skill endpoints against an OpenAPI spec")
    here = Path(__file__).resolve().parent
    ap.add_argument("--spec", default=str(here / "spec" / "cxone_openapi.json"))
    ap.add_argument("--scripts", default=str(here / "scripts"))
    ap.add_argument("--refs", default=str(here / "references"))
    ap.add_argument("--strict", action="store_true",
                    help="exit nonzero if any CODE->SPEC mismatch isn't a known omission")
    ap.add_argument("--show-unused", action="store_true",
                    help="also list spec endpoints the skill doesn't call")
    args = ap.parse_args(argv)

    spec_file = Path(args.spec)
    if not spec_file.is_file():
        print(f"ERROR: spec not found at {spec_file}")
        return 2
    spec = load_spec_paths(spec_file)
    print(f"Loaded {len(spec)} paths from {spec_file.name}\n")

    # 1) CODE -> SPEC
    code = sorted(collect_code_endpoints(Path(args.scripts)))
    print("=" * 70)
    print("CODE -> SPEC  (endpoints the skill calls)")
    print("=" * 70)
    code_misses = []
    for method, npath in code:
        full = "/api" + npath
        if npath in DYNAMIC_PATHS:
            continue  # runtime-built signed/status URL, not a static endpoint
        if npath in IAM_PLANE_PATHS:
            print(f"  IAM-PLANE  {method:6} {full}   (Keycloak admin; not in AST spec)")
            continue
        status = spec_has(spec, method, npath)
        if status == "exact":
            print(f"  OK        {method:6} {full}")
        elif status == "method-missing":
            print(f"  METHOD?   {method:6} {full}   (path exists, method not listed)")
            code_misses.append((method, npath, "method-missing"))
        else:
            known = (method, npath) in {(m, _norm(p)) for m, p in KNOWN_SPEC_OMISSIONS}
            tag = "KNOWN-OMIT" if known else "ABSENT"
            print(f"  {tag:9} {method:6} {full}" + ("   (live-validated; spec omits)" if known else ""))
            if not known:
                code_misses.append((method, npath, "absent"))

    # 2) DOCS -> SPEC
    docs = sorted(collect_doc_endpoints(Path(args.refs)))
    print("\n" + "=" * 70)
    print("DOCS -> SPEC  (concrete /api paths written in references/*.md)")
    print("=" * 70)
    doc_misses = []
    seen = set()
    for method, npath, fname in docs:
        key = (method, npath)
        if key in seen:
            continue
        seen.add(key)
        status = spec_has(spec, method, npath)
        full = "/api" + npath
        if status == "exact":
            continue  # quiet on matches to keep output focused
        known = (method, npath) in {(m, _norm(p)) for m, p in KNOWN_SPEC_OMISSIONS}
        if known:
            continue
        tag = "METHOD?" if status == "method-missing" else "ABSENT"
        print(f"  {tag:8} {method:6} {full}   ({fname})")
        doc_misses.append((method, npath, fname, status))
    if not doc_misses:
        print("  (all concrete doc paths resolve to the spec)")

    # 3) optional: unused spec endpoints
    if args.show_unused:
        used = {np for _, np in code}
        print("\n" + "=" * 70)
        print("SPEC endpoints not called by the skill (informational)")
        print("=" * 70)
        for np in sorted(set(spec) - used):
            print(f"  {','.join(sorted(spec[np])):16} /api{np}")

    # summary
    print("\n" + "=" * 70)
    print(f"SUMMARY: {len(code)} code endpoints, {len(seen)} doc paths checked. "
          f"CODE misses: {len(code_misses)} | DOC misses: {len(doc_misses)}")
    print("=" * 70)
    if args.strict and code_misses:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
