"""
Shared input/output helpers for the scan-level read commands
(`scan workflow`, `scan log`, `scan stats`).

* ID lists come from the command line, a .txt / .csv / .json file, or stdin
  (`-`), the same three shapes the standalone CxOne scan tools accept.
* Anything written to disk goes to the USER'S directory, never into the skill
  folder: that folder is fast-forwarded by `selfcheck --sync` and staged by
  publish, so a file left there can be overwritten or committed.
"""

from __future__ import annotations

import contextlib
import csv
import io
import json
import logging
import os
import re
import sys
from pathlib import Path

logger = logging.getLogger("cxone.scaninputs")

SKILL_ROOT = Path(__file__).resolve().parents[2]
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_ID_KEYS = ("scan_id", "scanId", "id")
_NAME_KEYS = ("name", "project_name", "projectName")
_MAX_INPUT_BYTES = 50 * 1024 * 1024        # an id/name list is never this big


def abs_path(value: str) -> Path:
    """Normalise an operator-supplied path before any file access."""
    return Path(os.path.abspath(os.path.normpath(os.path.expanduser(str(value)))))


def split_csv(value: str | None) -> list[str]:
    return [v.strip() for v in (value or "").split(",") if v.strip()]


def is_scan_id(value: str) -> bool:
    return bool(_UUID.match(value or ""))


def _read_text(source: str) -> str:
    if source == "-":
        return sys.stdin.read()
    path = abs_path(source)
    if not path.is_file():
        raise SystemExit(f"error: '{source}' is not a file")
    if path.stat().st_size > _MAX_INPUT_BYTES:
        raise SystemExit(f"error: '{source}' is too large to be an id/name list")
    with open(path, encoding="utf-8-sig") as handle:
        return handle.read()


def read_column(source: str, keys: tuple[str, ...]) -> list[str]:
    """Values from a .txt (one per line, # comments), .csv (a named column, else
    the first) or .json (a list of strings, or of objects with one of `keys`)."""
    text = _read_text(source)
    suffix = Path(source).suffix.lower() if source != "-" else ""
    stripped = text.lstrip()
    out: list[str] = []
    if suffix == ".json" or (source == "-" and stripped[:1] in "[{"):
        data = json.loads(text)
        if isinstance(data, dict):
            data = next((v for v in data.values() if isinstance(v, list)), [])
        for item in data:
            if isinstance(item, str):
                out.append(item.strip())
            elif isinstance(item, dict):
                out.append(str(next((item[k] for k in keys if item.get(k)), "")).strip())
    elif suffix == ".csv":
        rows = list(csv.reader(io.StringIO(text)))
        if rows:
            header = [h.strip() for h in rows[0]]
            col = next((header.index(k) for k in keys if k in header), None)
            body = rows[1:] if col is not None else rows
            col = 0 if col is None else col
            out = [r[col].strip() for r in body if len(r) > col]
    else:
        out = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    return [v for v in out if v]


def collect_scan_ids(scan_ids: list[str] | None, ids_file: str | None) -> list[str]:
    """IDs from --scan-id/--scan-ids plus a file; invalid ones are dropped loudly."""
    raw = list(scan_ids or [])
    if ids_file:
        raw += read_column(ids_file, _ID_KEYS)
    good, seen = [], set()
    for value in raw:
        if not is_scan_id(value):
            logger.warning("Ignoring '%s': not a scan id (expected a UUID)", value)
        elif value.lower() not in seen:
            seen.add(value.lower())
            good.append(value)
    return good


def collect_names(names: list[str] | None, names_file: str | None) -> list[str]:
    raw = list(names or [])
    if names_file:
        raw += read_column(names_file, _NAME_KEYS)
    return list(dict.fromkeys(v for v in raw if v))


def inside_skill_tree(path: Path) -> bool:
    try:
        resolved = path.resolve()
    except (OSError, ValueError):
        return False
    return resolved == SKILL_ROOT or SKILL_ROOT in resolved.parents


def output_dir(value: str | None, *, default_name: str) -> Path | None:
    """The directory to write into, created if needed, or None when it would sit
    inside the skill folder (the caller reports and exits)."""
    base = abs_path(value or default_name)
    if inside_skill_tree(base):
        return None
    base.mkdir(parents=True, exist_ok=True)
    return base


def output_file(value: str) -> Path | None:
    target = abs_path(value)
    if inside_skill_tree(target.parent):
        return None
    target.parent.mkdir(parents=True, exist_ok=True)
    return target


@contextlib.contextmanager
def open_output(target: Path, mode: str = "w", **kwargs):
    """Open a file whose directory output_dir()/output_file() already validated.

    Every command writes through this, so the "never inside the skill folder"
    rule is enforced in one place instead of being remembered by each caller.
    """
    if inside_skill_tree(target.parent):
        raise SystemExit(REFUSED_INSIDE_SKILL)
    with open(target, mode, **kwargs) as handle:
        yield handle


REFUSED_INSIDE_SKILL = ("Refused: won't write inside the skill directory (it is fast-forwarded "
                        "by `selfcheck --sync` and staged by publish). Name a folder in your own "
                        "working directory instead.")
