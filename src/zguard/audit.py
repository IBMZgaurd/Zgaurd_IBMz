"""JSON + Markdown audit summaries. Never contains raw scanned values."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from zguard import __version__
from zguard.findings import Finding
from zguard.mask import atomic_write_text, placeholder
from zguard.policy import Decision, Policy

MAX_TABLE_ROWS = 200


def get_hmac_key() -> bytes:
    """Per-run random key unless ZGUARD_HMAC_KEY is set (then fingerprints are comparable)."""
    env = os.environ.get("ZGUARD_HMAC_KEY")
    return env.encode("utf-8") if env else os.urandom(32)


def fingerprint(value: str, key: bytes) -> str:
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:12]


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _preview(f: Finding) -> str:
    if f.source == "ml":
        return f"ML risk score {f.score:.2f} (no span)"
    return placeholder(f.type)


def build_audit(
    input_path: str | Path,
    n_lines: int,
    findings: list[Finding],
    decision: Decision,
    policy: Policy,
    ml_enabled: bool,
    model_sha256: str | None,
) -> dict:
    input_path = Path(input_path)
    rows = []
    for f in findings:
        rows.append(
            {
                "line": f.line,
                "type": f.type,
                "source": f.source,
                "severity": policy.severity_of(f),
                "action": "masked" if policy.should_mask(f) else "unresolved",
                "preview": _preview(f),
                "fingerprint": f.fingerprint,
                "score": f.score,
            }
        )
    return {
        "zguard_version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "input_file": input_path.name,
        "input_sha256": _file_sha256(input_path),
        "lines_scanned": n_lines,
        "policy_mode": policy.mode,
        "ml_enabled": ml_enabled,
        "model_sha256": model_sha256,
        "decision": decision.action,
        "reasons": decision.reasons,
        "counts_by_type": dict(Counter(f.type for f in findings)),
        "counts_by_source": dict(Counter(f.source for f in findings)),
        "findings": rows,
    }


def to_markdown(audit: dict) -> str:
    out = [
        "# ZGuard audit summary",
        "",
        f"- **Decision:** {audit['decision']}",
        f"- **Input:** `{audit['input_file']}` (sha256 `{audit['input_sha256'][:16]}...`)",
        f"- **Lines scanned:** {audit['lines_scanned']}",
        f"- **Policy mode:** {audit['policy_mode']}",
        f"- **ML layer:** {'on' if audit['ml_enabled'] else 'off'}",
        f"- **Generated:** {audit['generated_at']}",
        "",
        "Raw values are never written here. Fingerprints are truncated HMAC-SHA256 values.",
        "",
    ]
    if audit["reasons"]:
        out += ["## Reasons", ""] + [f"- {r}" for r in audit["reasons"]] + [""]
    out += ["## Counts by type", "", "| Type | Count |", "|---|---|"]
    out += [f"| {t} | {n} |" for t, n in sorted(audit["counts_by_type"].items())] or []
    out += [
        "",
        "## Findings",
        "",
        "| Line | Type | Source | Severity | Action | Preview | Fingerprint |",
    ]
    out += ["|---|---|---|---|---|---|---|"]
    for r in audit["findings"][:MAX_TABLE_ROWS]:
        out.append(
            f"| {r['line']} | {r['type']} | {r['source']} | {r['severity']} | {r['action']} "
            f"| {r['preview']} | {r['fingerprint'] or ''} |"
        )
    extra = len(audit["findings"]) - MAX_TABLE_ROWS
    if extra > 0:
        out += ["", f"_{extra} more finding(s) are in audit.json._"]
    return "\n".join(out) + "\n"


def write_audit(out_dir: str | Path, audit: dict) -> tuple[Path, Path]:
    out_dir = Path(out_dir)
    json_path, md_path = out_dir / "audit.json", out_dir / "audit.md"
    atomic_write_text(json_path, [json.dumps(audit, indent=2) + "\n"])
    atomic_write_text(md_path, [to_markdown(audit)])
    return json_path, md_path
