"""TOML policy engine. This is the ONLY component that decides ALLOW or BLOCK."""

from __future__ import annotations

import tomllib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from zguard.findings import RULE_TYPES, Finding

SEVERITIES = ("low", "medium", "high")
MODES = ("standard", "strict")


class PolicyError(ValueError):
    """Invalid or unreadable policy. Treated as BLOCK by the CLI (fail-closed)."""


@dataclass
class Decision:
    action: str  # "ALLOW" or "BLOCK"
    reasons: list[str] = field(default_factory=list)
    masked: list[Finding] = field(default_factory=list)
    blocking: list[Finding] = field(default_factory=list)
    review: list[Finding] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.action == "ALLOW"


@dataclass(frozen=True)
class Policy:
    mode: str
    auto_mask: frozenset
    ml_review_threshold: float
    ml_high_risk_threshold: float
    severity: dict
    block_on: frozenset

    @classmethod
    def load(cls, path: str | Path) -> Policy:
        try:
            with open(path, "rb") as f:
                raw = tomllib.load(f)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise PolicyError(f"cannot read policy file ({type(exc).__name__})") from exc
        try:
            mode = raw.get("mode", "standard")
            auto_mask = frozenset(raw.get("auto_mask", []))
            review = float(raw["ml_review_threshold"])
            high = float(raw["ml_high_risk_threshold"])
            severity = dict(raw.get("severity", {}))
            block_on = frozenset(raw.get("decision", {}).get("block_on", ["high"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise PolicyError(f"malformed policy ({type(exc).__name__})") from exc
        if mode not in MODES:
            raise PolicyError(f"mode must be one of {MODES}")
        if not auto_mask <= set(RULE_TYPES):
            raise PolicyError("auto_mask contains an unknown type")
        if not (0.0 <= review <= high <= 1.0):
            raise PolicyError("thresholds must satisfy 0 <= review <= high <= 1")
        if any(v not in SEVERITIES for v in severity.values()):
            raise PolicyError("severity values must be low, medium or high")
        if not block_on <= set(SEVERITIES) or not block_on:
            raise PolicyError("block_on must be a non-empty subset of low/medium/high")
        return cls(mode, auto_mask, review, high, severity, block_on)

    def severity_of(self, f: Finding) -> str:
        if f.source == "ml":
            score = f.score if f.score is not None else 1.0  # unknown score: assume worst
            if score >= self.ml_high_risk_threshold:
                return "high"
            if score >= self.ml_review_threshold:
                return "medium"
            return "low"
        return self.severity.get(f.type, "high")  # unknown type: fail closed

    def should_mask(self, f: Finding) -> bool:
        return f.source == "rule" and f.start is not None and f.type in self.auto_mask

    def decide(self, findings: list[Finding]) -> Decision:
        d = Decision("ALLOW")
        for f in findings:
            if self.should_mask(f):
                d.masked.append(f)
            elif self.severity_of(f) in self.block_on:
                d.blocking.append(f)
            else:
                d.review.append(f)
        if d.blocking:
            d.action = "BLOCK"
            counts = Counter(f.type for f in d.blocking)
            kinds = ", ".join(f"{t} x{n}" for t, n in sorted(counts.items()))
            lines = ", ".join(str(n) for n in sorted({f.line for f in d.blocking})[:10])
            d.reasons.append(f"unresolved finding(s) at blocking severity: {kinds}")
            d.reasons.append(f"first affected line(s): {lines}")
        if d.review:
            d.reasons.append(f"{len(d.review)} finding(s) need human review (non-blocking)")
        return d
