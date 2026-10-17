"""Typed-placeholder masking and atomic output writes."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from zguard.findings import Finding
from zguard.policy import Policy


def placeholder(ftype: str) -> str:
    return f"[REDACTED:{ftype}]"


def _split_eol(line: str) -> tuple[str, str]:
    body = line.rstrip("\r\n")
    return body, line[len(body) :]


def mask_line(line: str, findings: list[Finding]) -> str:
    body, eol = _split_eol(line)
    for f in sorted(findings, key=lambda x: x.start, reverse=True):
        body = body[: f.start] + placeholder(f.type) + body[f.end :]
    return body + eol


def mask_lines(lines: list[str], findings: list[Finding], policy: Policy) -> list[str]:
    by_line: dict[int, list[Finding]] = {}
    for f in findings:
        if policy.should_mask(f):
            by_line.setdefault(f.line, []).append(f)
    return [mask_line(raw, by_line.get(i + 1, [])) for i, raw in enumerate(lines)]


def atomic_write_text(path: str | Path, lines: list[str]) -> None:
    """Write to a temp file in the same folder, fsync, then rename into place."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".zguard-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.writelines(lines)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
