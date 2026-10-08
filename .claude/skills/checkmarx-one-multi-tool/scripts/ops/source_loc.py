"""
Line counts for a scanned source snapshot — application code AND IaC.

Checkmarx One reports LOC for **SAST only** (``GET /api/sast-metadata``). KICS,
the IaC engine, reports how many files it scanned but never how many lines they
held, and nothing reports a whole-repo line count to compare SAST's number
against. This module fills both gaps by counting the exact snapshot a scan ran
against (``ops/source_fetch.fetch_scan_source``), so the numbers line up with
the scan rather than with branch HEAD.

What it is, and what it is not:

* A cloc-style count: every file is ``total = code + comment + blank``. Comment
  detection is per language family and deliberately simple (line comments plus
  ``/* … */``-style blocks). Good to within a few percent of cloc; it is NOT the
  SAST engine's own count and will not match ``sast-metadata.loc`` exactly — the
  engine applies file exclusions, preset language filters, and its own parser.
* IaC files are classified into KICS's platform names (Terraform,
  CloudFormation, Kubernetes, Ansible, Dockerfile, …) by name and by sniffing
  content, the way KICS itself does. A YAML file is only IaC if it LOOKS like
  one of those platforms; a plain config YAML is counted as ``YAML (other)``.
  KICS's own file filter may still differ at the edges.

Pure stdlib, no network: give it a directory, get a dict back.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

# Directories that are never source (VCS metadata). Everything else in the
# snapshot is counted: the snapshot already reflects what was uploaded.
_SKIP_DIRS = {".git", ".hg", ".svn"}

# Content sniffing reads at most this many bytes per candidate file.
_SNIFF_BYTES = 64 * 1024
# Files larger than this are counted by newlines only (no comment parsing) —
# minified bundles and data dumps would otherwise dominate the runtime.
_PARSE_LIMIT = 4 * 1024 * 1024

# Comment syntax per family: (line-comment prefixes, block (open, close) or None)
_C_STYLE = (("//",), ("/*", "*/"))
_HASH = (("#",), None)
_FAMILIES: dict[str, tuple[tuple[str, ...], tuple[str, str] | None]] = {
    "c": _C_STYLE,
    "hash": _HASH,
    "sql": (("--",), ("/*", "*/")),
    "lua": (("--",), ("--[[", "]]")),
    "markup": ((), ("<!--", "-->")),
    "python": (("#",), None),          # docstrings count as code, as cloc does
    "ruby": (("#",), ("=begin", "=end")),
    "vb": (("'", "REM "), None),
    "batch": (("REM ", "::"), None),
    "lisp": ((";",), None),
    "haskell": (("--",), ("{-", "-}")),
    "erlang": (("%",), None),
    "cobol": (("*",), None),
    "hcl": (("#", "//"), ("/*", "*/")),
    "none": ((), None),
}

# extension (lowercase, with dot) -> (language, family)
_EXT: dict[str, tuple[str, str]] = {}


def _reg(lang: str, family: str, *exts: str) -> None:
    for e in exts:
        _EXT[e] = (lang, family)


_reg("Java", "c", ".java")
_reg("JavaScript", "c", ".js", ".jsx", ".mjs", ".cjs")
_reg("TypeScript", "c", ".ts", ".tsx", ".mts", ".cts")
_reg("C#", "c", ".cs")
_reg("Go", "c", ".go")
_reg("Kotlin", "c", ".kt", ".kts")
_reg("Scala", "c", ".scala", ".sc")
_reg("Swift", "c", ".swift")
_reg("Objective-C", "c", ".m", ".mm")
_reg("C/C++", "c", ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx", ".inl")
_reg("Groovy", "c", ".groovy", ".gradle", ".gvy")
_reg("Rust", "c", ".rs")
_reg("Dart", "c", ".dart")
_reg("Apex", "c", ".cls", ".trigger")
_reg("PHP", "c", ".php", ".phtml", ".php5", ".inc")
_reg("Solidity", "c", ".sol")
_reg("Protocol Buffers", "c", ".proto")
_reg("Python", "python", ".py", ".pyw", ".pyi")
_reg("Ruby", "ruby", ".rb", ".rake", ".erb", ".gemspec")
_reg("Perl", "hash", ".pl", ".pm", ".t")
_reg("Shell", "hash", ".sh", ".bash", ".zsh", ".ksh")
_reg("PowerShell", "hash", ".ps1", ".psm1", ".psd1")
_reg("R", "hash", ".r")
_reg("Elixir", "hash", ".ex", ".exs")
_reg("VB.NET", "vb", ".vb")
_reg("VB6/VBScript", "vb", ".bas", ".frm", ".vbs")
_reg("Batch", "batch", ".bat", ".cmd")
_reg("SQL / PL-SQL", "sql", ".sql", ".pks", ".pkb", ".pck", ".prc", ".fnc", ".trg")
_reg("Lua", "lua", ".lua")
_reg("Haskell", "haskell", ".hs")
_reg("Erlang", "erlang", ".erl", ".hrl")
_reg("Clojure", "lisp", ".clj", ".cljs", ".cljc", ".edn")
_reg("COBOL", "cobol", ".cbl", ".cob", ".cpy")
_reg("HTML", "markup", ".html", ".htm", ".xhtml")
_reg("JSP", "markup", ".jsp", ".jspx", ".tag")
_reg("ASP.NET", "markup", ".aspx", ".ascx", ".asax", ".cshtml", ".vbhtml", ".master", ".asp")
_reg("Vue", "markup", ".vue")
_reg("Svelte", "markup", ".svelte")
_reg("XML", "markup", ".xml", ".xsd", ".xsl", ".xslt", ".config", ".plist", ".wsdl")
_reg("CSS", "c", ".css", ".scss", ".less", ".sass")
_reg("Markdown", "none", ".md", ".markdown", ".rst")
_reg("JSON", "none", ".json")
_reg("YAML", "hash", ".yml", ".yaml")
# IaC-native extensions (classified as IaC below, regardless of content)
_reg("Terraform", "hcl", ".tf", ".tfvars", ".hcl")
_reg("Bicep", "c", ".bicep")
_reg("Jinja", "none", ".jinja", ".j2")

# Languages kept out of the application-code total: documentation/data formats
# (so a docs-heavy repo doesn't inflate it) and IaC-native languages (which are
# reported in the separate IaC total instead of being counted twice).
NON_CODE_LANGUAGES = {"Markdown", "JSON", "YAML", "YAML (other)", "XML"}
IAC_LANGUAGES = {"Terraform", "Bicep", "Dockerfile", "Jinja"}

# --------------------------------------------------------------- IaC detection
# KICS platform names, as they appear in kicsCounters.platformSummary.
_IAC_NAME_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(^|/)(dockerfile|containerfile)([.-][^/]*)?$", re.I), "Dockerfile"),
    (re.compile(r"\.dockerfile$", re.I), "Dockerfile"),
    (re.compile(r"(^|/)(docker-)?compose([.-][^/]*)?\.ya?ml$", re.I), "DockerCompose"),
    (re.compile(r"\.tf(\.json)?$|\.tfvars(\.json)?$", re.I), "Terraform"),
    (re.compile(r"\.bicep$", re.I), "Bicep"),
    (re.compile(r"(^|/)serverless\.ya?ml$", re.I), "ServerlessFW"),
    (re.compile(r"(^|/)pulumi(\.[^/]+)?\.ya?ml$", re.I), "Pulumi"),
    (re.compile(r"(^|/)\.github/workflows/[^/]+\.ya?ml$", re.I), "CICD"),
    (re.compile(r"\.proto$", re.I), "GRPC"),
]
_YAML_JSON = re.compile(r"\.(ya?ml|json|template)$", re.I)

_SNIFF_RULES: list[tuple[str, list[re.Pattern]]] = [
    # order matters: most specific first
    ("CloudFormation", [re.compile(r"AWSTemplateFormatVersion"),
                        re.compile(r"[\"']?Type[\"']?\s*:\s*[\"']?AWS::")]),
    ("AzureResourceManager", [re.compile(r"schema\.management\.azure\.com/schemas/[^\"']*deploymentTemplate", re.I)]),
    ("OpenAPI", [re.compile(r"^\s*[\"']?(openapi|swagger)[\"']?\s*:\s*[\"']?[23]", re.M)]),
    ("Crossplane", [re.compile(r"apiVersion\s*:\s*\S*crossplane\.io")]),
    ("Knative", [re.compile(r"apiVersion\s*:\s*\S*knative\.dev")]),
    ("Kubernetes", [re.compile(r"^\s*apiVersion\s*:", re.M),
                    re.compile(r"^\s*kind\s*:", re.M)]),
    ("GoogleDeploymentManager", [re.compile(r"^resources\s*:", re.M),
                                 re.compile(r"type\s*:\s*\S*(compute|gcp-types|storage)\.v1", re.I)]),
    ("Ansible", [re.compile(r"^-\s+(hosts|import_playbook)\s*:", re.M)]),
]


def _sniff(path: Path) -> str:
    try:
        with open(path, "rb") as fh:
            return fh.read(_SNIFF_BYTES).decode("utf-8", errors="replace")
    except OSError:
        return ""


def classify_iac(rel: str, path: Path, helm_roots: set[str]) -> str | None:
    """KICS platform for a file, or None if it isn't IaC."""
    for rx, platform in _IAC_NAME_RULES:
        if rx.search(rel):
            return platform
    # Helm: anything under a chart directory (one holding Chart.yaml)
    parts = rel.split("/")
    for i in range(len(parts) - 1, 0, -1):
        if "/".join(parts[:i]) in helm_roots:
            if rel.lower().endswith((".yaml", ".yml", ".tpl")):
                return "Helm"
            break
    if not _YAML_JSON.search(rel):
        return None
    lower = rel.lower()
    # Ansible role layout: roles/<r>/{tasks,handlers}/*.yml
    if re.search(r"(^|/)roles/[^/]+/(tasks|handlers|meta)/[^/]+\.ya?ml$", lower):
        return "Ansible"
    text = _sniff(path)
    if not text:
        return None
    for platform, rules in _SNIFF_RULES:
        if all(r.search(text) for r in rules):
            return platform
    return None


# --------------------------------------------------------------- line counting
def _count_lines(path: Path, family: str) -> tuple[int, int, int]:
    """(code, comment, blank) for one file."""
    try:
        size = path.stat().st_size
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return (0, 0, 0)
    if b"\x00" in raw[:8192]:
        return (0, 0, 0)                      # binary
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if size > _PARSE_LIMIT:
        blank = sum(1 for ln in lines if not ln.strip())
        return (len(lines) - blank, 0, blank)

    line_prefixes, block = _FAMILIES.get(family, _FAMILIES["none"])
    code = comment = blank = 0
    in_block = False
    for ln in lines:
        s = ln.strip()
        if not s:
            blank += 1
            continue
        if in_block:
            comment += 1
            if block and block[1] in s:
                in_block = False
                tail = s.split(block[1], 1)[1].strip()
                if tail and not any(tail.startswith(p) for p in line_prefixes):
                    comment -= 1
                    code += 1
            continue
        if block and s.startswith(block[0]):
            rest = s[len(block[0]):]
            if block[1] not in rest:
                in_block = True
            comment += 1
            continue
        if line_prefixes and any(s.startswith(p) for p in line_prefixes):
            # A shebang is code-ish metadata; cloc counts it as a comment too.
            comment += 1
            continue
        code += 1
        if block and block[0] in s and block[1] not in s.split(block[0], 1)[1]:
            in_block = True
    return (code, comment, blank)


def _language_for(name: str) -> tuple[str, str] | None:
    lower = name.lower()
    if lower in ("dockerfile", "containerfile") or lower.startswith("dockerfile."):
        return ("Dockerfile", "hash")
    if lower == "makefile":
        return ("Makefile", "hash")
    if lower.endswith(".tf.json"):
        return ("Terraform", "none")
    if lower.endswith(".dockerfile") or lower.startswith("containerfile"):
        return ("Dockerfile", "hash")
    return _EXT.get(os.path.splitext(lower)[1])


def _blank_bucket() -> dict:
    return {"files": 0, "code": 0, "comment": 0, "blank": 0}


def _add(bucket: dict, code: int, comment: int, blank: int) -> None:
    bucket["files"] += 1
    bucket["code"] += code
    bucket["comment"] += comment
    bucket["blank"] += blank


def count_tree(root: Path, *, top_files: int = 10) -> dict:
    """Count a source tree. Returns a JSON-friendly dict:

    ``languages``  {lang: {files, code, comment, blank}} for every recognised file
    ``iac``        {platform: {files, code, comment, blank}} for IaC files
    ``iac_files``  the ``top_files`` largest IaC files by code lines
    ``totals``     application-code totals (excluding docs/data formats and
                   IaC-native languages, which ``iac_totals`` covers)
    ``unrecognised_files`` count of files with no known language
    """
    root = Path(root)
    languages: dict[str, dict] = {}
    iac: dict[str, dict] = {}
    iac_files: list[dict] = []
    unrecognised = 0
    all_files = 0

    # First pass: list files and find Helm chart roots.
    files: list[tuple[str, Path]] = []
    helm_roots: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.is_symlink():
                continue
            rel = p.relative_to(root).as_posix()
            files.append((rel, p))
            if fn == "Chart.yaml":
                helm_roots.add(p.parent.relative_to(root).as_posix())

    for rel, p in files:
        all_files += 1
        lang = _language_for(p.name)
        platform = classify_iac(rel, p, helm_roots)
        if lang is None and platform is None:
            unrecognised += 1
            continue
        family = lang[1] if lang else "hash"
        code, comment, blank = _count_lines(p, family)
        if lang:
            name = lang[0]
            if name == "YAML" and platform is None:
                name = "YAML (other)"
            _add(languages.setdefault(name, _blank_bucket()), code, comment, blank)
        if platform:
            _add(iac.setdefault(platform, _blank_bucket()), code, comment, blank)
            iac_files.append({"file": rel, "platform": platform, "code": code,
                              "total": code + comment + blank})

    totals = _blank_bucket()
    for name, b in languages.items():
        if name in NON_CODE_LANGUAGES or name in IAC_LANGUAGES:
            continue
        totals["files"] += b["files"]
        totals["code"] += b["code"]
        totals["comment"] += b["comment"]
        totals["blank"] += b["blank"]
    iac_totals = _blank_bucket()
    for b in iac.values():
        for k in iac_totals:
            iac_totals[k] += b[k]

    iac_files.sort(key=lambda f: f["code"], reverse=True)
    return {
        "files_in_snapshot": all_files,
        "unrecognised_files": unrecognised,
        "languages": dict(sorted(languages.items(), key=lambda kv: -kv[1]["code"])),
        "totals": totals,
        "iac": dict(sorted(iac.items(), key=lambda kv: -kv[1]["code"])),
        "iac_totals": iac_totals,
        "iac_files": iac_files[:top_files],
    }
