"""Deterministic detectors with exact character spans (API keys, e-mail, IPv4, user IDs)."""

from __future__ import annotations

import math
import re
from collections import Counter

Span = tuple[str, int, int]  # (type, start, end)


def _entropy(value: str) -> float:
    counts = Counter(value)
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _looks_like_secret(value: str) -> bool:
    """Reject plain words such as 'refill_rate_per_second': need letters, digits, entropy."""
    return (
        any(ch.isdigit() for ch in value)
        and any(ch.isalpha() for ch in value)
        and _entropy(value) >= 3.0
    )


def _has_digit(value: str) -> bool:
    return any(ch.isdigit() for ch in value)


_LABEL = (
    r"(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|refresh[_-]?token|"
    r"session[_-]?token|client[_-]?secret|secret[_-]?key|secret|token)"
)

# (regex, capture group holding the secret, optional validator)
_API_PATTERNS = [
    (re.compile(r"\bzgk_(?:live|test)_[A-Za-z0-9]{16,}\b"), 0, None),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 0, None),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), 0, None),
    (re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/\-]{20,})"), 1, _looks_like_secret),
    (
        re.compile(rf"(?i){_LABEL}[\"']?\s*[=:]\s*[\"']?([A-Za-z0-9_\-./+]{{16,}})"),
        1,
        _looks_like_secret,
    ),
]

_EMAIL = re.compile(r"(?<![\w.+\-])[A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,}(?![\w\-])")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
_USER_ID = re.compile(
    r"(?i)(?:user[_-]?id|userid|uid|account[_-]?id|customer[_-]?id)"
    r"[\"']?\s*[=:]\s*[\"']?([A-Za-z0-9_\-]{3,64})"
)


def _valid_ipv4(value: str) -> bool:
    for octet in value.split("."):
        if int(octet) > 255 or (len(octet) > 1 and octet.startswith("0")):
            return False
    return True


def _resolve_overlaps(candidates: list[Span]) -> list[Span]:
    """Keep the longest span first; drop anything that overlaps an accepted span."""
    accepted: list[Span] = []
    for cand in sorted(candidates, key=lambda c: (-(c[2] - c[1]), c[1])):
        if all(cand[2] <= a[1] or cand[1] >= a[2] for a in accepted):
            accepted.append(cand)
    return sorted(accepted, key=lambda c: c[1])


def detect_line(line: str) -> list[Span]:
    """Return non-overlapping (type, start, end) spans for one line."""
    cands: list[Span] = []
    for pattern, group, validator in _API_PATTERNS:
        for m in pattern.finditer(line):
            if validator and not validator(m.group(group)):
                continue
            cands.append(("API_KEY", *m.span(group)))
    for m in _EMAIL.finditer(line):
        cands.append(("EMAIL", *m.span()))
    for m in _IPV4.finditer(line):
        if _valid_ipv4(m.group()):
            cands.append(("IPV4", *m.span()))
    for m in _USER_ID.finditer(line):
        if _has_digit(m.group(1)):
            cands.append(("USER_ID", *m.span(1)))
    return _resolve_overlaps(cands)
