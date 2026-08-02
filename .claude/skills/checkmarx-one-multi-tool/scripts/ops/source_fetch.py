"""
Scanned source retrieval — the exact code a scan ran against.

``GET /api/repostore/code/{scanId}`` is what the CxOne UI's "Download source
code" uses. It answers **302** with a redirect to a pre-signed archive URL;
fetching that yields a zip of the precise snapshot that was scanned.

Why this beats cloning the repo — and why `triage-real` depends on it:

* It is the SCANNED snapshot, so **line numbers match the findings exactly**.
  A clone gives you branch HEAD, which may have moved since the scan, silently
  shifting every line number a reviewer relies on.
* It works for zip-upload scans, which have no repo to clone at all.
* It needs no SCM token and no network access to GitHub/GitLab.

**The redirect gotcha (live-verified 2026-08-01).** The `Location` carries
`X-Amz-Algorithm`/`X-Amz-Signature` query params and looks exactly like an S3
pre-signed URL — but on this deployment it points back at the CxOne gateway
(`{base_url}/storage/...`) and **still requires the Authorization header**.
Following it the way you would a real pre-signed URL (no auth) returns 401.

So the rule implemented below: follow the redirect manually, and send the
bearer token **only when the redirect host matches the configured base_url**.
Blindly attaching auth would leak the token if Checkmarx ever moves this to a
genuine third-party storage host; blindly omitting it fails today.
"""

from __future__ import annotations

import io
import zipfile
import logging
from pathlib import Path
from urllib.parse import urlsplit

logger = logging.getLogger("cxone.source")

_SOURCE_ENDPOINT = "repostore/code"
_DOWNLOAD_TIMEOUT = 300


def fetch_scan_source(api, scan_id: str, dest_dir: Path) -> Path | None:
    """Download + extract the scanned source for ``scan_id`` into ``dest_dir``.

    Returns the extraction root, or None when the archive is unavailable (aged
    out, never stored, or the caller lacks permission) — callers must treat
    None as "no source", never as an empty project.
    """
    import requests

    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    base = api.config.base_url.rstrip("/")
    token = api.auth.token()

    try:
        first = requests.get(f"{base}/api/{_SOURCE_ENDPOINT}/{scan_id}",
                             headers={"Authorization": f"Bearer {token}"},
                             allow_redirects=False, timeout=60)
    except requests.exceptions.RequestException as exc:
        logger.warning("Source download failed for scan %s: %s", scan_id, exc)
        return None

    if first.status_code in (401, 403):
        logger.warning("Not permitted to download source for scan %s (HTTP %d). The "
                       "API key's account needs the source-code download permission.",
                       scan_id, first.status_code)
        return None
    if first.status_code == 404:
        logger.warning("No stored source for scan %s (archives age out).", scan_id)
        return None

    location = first.headers.get("Location")
    if first.status_code in (301, 302, 303, 307, 308) and location:
        same_host = urlsplit(location).netloc == urlsplit(base).netloc
        headers = {"Authorization": f"Bearer {token}"} if same_host else {}
        if not same_host:
            logger.debug("Redirect target is a third-party host; sending no credentials.")
        try:
            blob = requests.get(location, headers=headers, timeout=_DOWNLOAD_TIMEOUT)
            blob.raise_for_status()
        except requests.exceptions.RequestException as exc:
            logger.warning("Source archive fetch failed for scan %s: %s", scan_id, exc)
            return None
        payload = blob.content
    elif first.status_code == 200:
        payload = first.content          # some deployments may serve it directly
    else:
        logger.warning("Unexpected HTTP %d fetching source for scan %s.",
                       first.status_code, scan_id)
        return None

    root = dest_dir / scan_id
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as zf:
            _safe_extract(zf, root)
    except zipfile.BadZipFile:
        logger.warning("Source archive for scan %s is not a readable zip.", scan_id)
        return None
    logger.info("Scanned source for %s extracted to %s (%d files)",
                scan_id, root, sum(1 for _ in root.rglob("*") if _.is_file()))
    return root


def _safe_extract(zf: zipfile.ZipFile, root: Path) -> None:
    """Extract, refusing entries that escape ``root``.

    The archive is attacker-influenced in the sense that it mirrors a scanned
    repository — a path like ``../../.ssh/authorized_keys`` in a crafted repo
    would otherwise write outside the destination (Zip Slip).
    """
    root.mkdir(parents=True, exist_ok=True)
    resolved_root = root.resolve()
    for member in zf.infolist():
        target = (root / member.filename).resolve()
        if not str(target).startswith(str(resolved_root)):
            logger.warning("Skipping archive entry outside the destination: %s",
                           member.filename)
            continue
        if member.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(member) as src, open(target, "wb") as out:
            out.write(src.read())


def resolve_in_source(root: Path, file_path: str) -> Path | None:
    """Map a finding's file path (``/src/main/...``) to a file on disk.

    Finding paths are archive-relative and lead with ``/``; the archive may or
    may not carry a top-level wrapper directory, so a suffix match is the
    fallback.
    """
    if not root or not file_path:
        return None
    rel = file_path.lstrip("/")
    direct = root / rel
    if direct.is_file():
        return direct
    tail = Path(rel).name
    candidates = [p for p in root.rglob(tail) if p.is_file() and str(p).endswith(rel)]
    if not candidates:
        candidates = [p for p in root.rglob(tail) if p.is_file()]
    return candidates[0] if len(candidates) == 1 else (candidates[0] if candidates else None)


def code_window(root: Path, file_path: str, line: int, *, before: int = 12,
                after: int = 12) -> dict | None:
    """A numbered slice of source around ``line``, for review.

    Returns ``{"file", "start_line", "end_line", "focus_line", "lines": [...]}``
    where each entry is ``{"n": <line no>, "text": ...}``, or None when the file
    or line can't be resolved — which is the signal that this finding cannot be
    reviewed from source.
    """
    path = resolve_in_source(root, file_path)
    if not path:
        return None
    try:
        text = path.read_text(errors="replace").splitlines()
    except OSError:
        return None
    if not text or line is None or line < 1 or line > len(text):
        return None
    start = max(1, line - before)
    end = min(len(text), line + after)
    return {
        "file": file_path,
        "start_line": start,
        "end_line": end,
        "focus_line": line,
        "lines": [{"n": n, "text": text[n - 1]} for n in range(start, end + 1)],
    }
