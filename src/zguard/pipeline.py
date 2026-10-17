"""Read -> detect (rules + ML) -> merge. No decisions are made here."""

from __future__ import annotations

from pathlib import Path

from zguard.audit import fingerprint
from zguard.findings import ML_TYPE, Finding
from zguard.ml import predict_scores
from zguard.policy import Policy
from zguard.rules import detect_line


def read_lines(path: str | Path) -> list[str]:
    """Read strictly as UTF-8, keeping line endings. Undecodable input raises (fail-closed)."""
    with open(path, encoding="utf-8", errors="strict", newline="") as f:
        return f.readlines()


def scan_lines(
    lines: list[str], policy: Policy, model=None, hmac_key: bytes = b""
) -> list[Finding]:
    findings: list[Finding] = []
    ml_candidates: list[int] = []
    for idx, raw in enumerate(lines):
        line = raw.rstrip("\r\n")
        spans = detect_line(line)
        for ftype, start, end in spans:
            findings.append(
                Finding(
                    type=ftype,
                    line=idx + 1,
                    start=start,
                    end=end,
                    source="rule",
                    fingerprint=fingerprint(line[start:end], hmac_key),
                )
            )
        # Lines already handled by rules are not re-scored: ML only covers what rules cannot span.
        if model is not None and not spans and line.strip():
            ml_candidates.append(idx)
    if model is not None and ml_candidates:
        scores = predict_scores(model, [lines[i].rstrip("\r\n") for i in ml_candidates])
        for idx, score in zip(ml_candidates, scores, strict=True):
            if score >= policy.ml_review_threshold:
                findings.append(
                    Finding(type=ML_TYPE, line=idx + 1, source="ml", score=round(score, 4))
                )
    findings.sort(key=lambda f: (f.line, f.start if f.start is not None else -1))
    return findings


def verify_masked(masked_lines: list[str]) -> bool:
    """Defence in depth: the rules must find nothing left in the masked output."""
    return all(not detect_line(line.rstrip("\r\n")) for line in masked_lines)
