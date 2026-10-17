"""Finding schema shared by every layer. A Finding never stores the raw value."""

from __future__ import annotations

from dataclasses import asdict, dataclass

RULE_TYPES = ("API_KEY", "EMAIL", "IPV4", "USER_ID")
ML_TYPE = "ML_RISK"


@dataclass(frozen=True)
class Finding:
    type: str
    line: int  # 1-based
    start: int | None = None  # character offsets inside the line (rules only)
    end: int | None = None
    source: str = "rule"  # "rule" or "ml"
    score: float | None = None  # ML probability (ml only)
    fingerprint: str | None = None  # truncated HMAC of the value (rules only)

    def to_dict(self) -> dict:
        return asdict(self)
