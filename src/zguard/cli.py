"""Command line: scan | review | sanitize | audit.

Exit codes: 0 = ALLOW, 1 = BLOCK, 2 = error (also BLOCK: fail-closed, no output written).
Messages never echo scanned values.
"""

from __future__ import annotations

import argparse
import os
import sys
import traceback
from collections import Counter
from pathlib import Path

from zguard import __version__
from zguard.audit import build_audit, get_hmac_key, write_audit
from zguard.mask import atomic_write_text, mask_lines
from zguard.ml import ModelIntegrityError, load_model, sha256_file
from zguard.pipeline import read_lines, scan_lines, verify_masked
from zguard.policy import Policy, PolicyError

EXIT_ALLOW, EXIT_BLOCK, EXIT_ERROR = 0, 1, 2
DEFAULT_POLICY = "configs/policy.toml"
DEFAULT_MODEL = "models/zguard_lr.pkl"


class _Scan:
    def __init__(self, args):
        self.policy = Policy.load(args.policy)
        self.ml_enabled = not args.no_ml
        self.model = load_model(args.model) if self.ml_enabled else None
        self.model_sha = sha256_file(args.model) if self.ml_enabled else None
        self.lines = read_lines(args.input)
        self.findings = scan_lines(self.lines, self.policy, self.model, get_hmac_key())
        self.decision = self.policy.decide(self.findings)


def _summary(args, s: _Scan) -> None:
    by_source = Counter(f.source for f in s.findings)
    print(f"zguard {args.command}: {Path(args.input).name}")
    print(f"  lines scanned : {len(s.lines)}")
    print(f"  ML layer      : {'on' if s.ml_enabled else 'OFF (--no-ml)'}")
    print(f"  policy mode   : {s.policy.mode}")
    print(
        f"  findings      : {len(s.findings)} "
        f"(rules {by_source.get('rule', 0)}, ml {by_source.get('ml', 0)})"
    )
    for t, n in sorted(Counter(f.type for f in s.findings).items()):
        print(f"    {t:<10} {n}")
    print(f"  masked        : {len(s.decision.masked)}")
    print(f"  needs review  : {len(s.decision.review)}")
    print(f"  DECISION      : {s.decision.action}")
    for reason in s.decision.reasons:
        print(f"    - {reason}")


def _code(s: _Scan) -> int:
    return EXIT_ALLOW if s.decision.allowed else EXIT_BLOCK


def _maybe_audit(args, s: _Scan) -> None:
    if getattr(args, "audit_dir", None):
        audit = build_audit(
            args.input, len(s.lines), s.findings, s.decision, s.policy, s.ml_enabled, s.model_sha
        )
        j, m = write_audit(args.audit_dir, audit)
        print(f"  audit written : {j} , {m}")


def cmd_scan(args) -> int:
    s = _Scan(args)
    _summary(args, s)
    if args.verbose:
        for f in s.findings:
            extra = f"score={f.score}" if f.source == "ml" else f"fp={f.fingerprint}"
            span = f"{f.start}-{f.end}" if f.start is not None else "-"
            print(f"  line {f.line:<6} {f.type:<9} {f.source:<4} span={span:<9} {extra}")
    return _code(s)


def cmd_review(args) -> int:
    s = _Scan(args)
    _summary(args, s)
    items = s.decision.blocking + s.decision.review
    print(f"\nItems for human review: {len(items)}")
    masked = mask_lines(s.lines, s.findings, s.policy) if args.show_lines else None
    for f in sorted(items, key=lambda x: x.line):
        sev = s.policy.severity_of(f)
        detail = f"score={f.score:.2f}" if f.score is not None else "rule finding"
        print(f"  line {f.line:<6} {f.type:<9} severity={sev:<6} {detail}")
        if masked is not None:
            print(f"      > {masked[f.line - 1].rstrip()}")
    if masked is not None:
        print("\nNote: ML-flagged lines have no span, so they are shown UNMASKED above.")
    return _code(s)


def cmd_sanitize(args) -> int:
    if Path(args.out).resolve() == Path(args.input).resolve():
        raise ValueError("output path must differ from input path")
    s = _Scan(args)
    _summary(args, s)
    _maybe_audit(args, s)
    if not s.decision.allowed:
        print("BLOCKED: no output file was written.")
        return EXIT_BLOCK
    masked = mask_lines(s.lines, s.findings, s.policy)
    if not verify_masked(masked):
        print("BLOCKED: residual sensitive pattern after masking; no output file written.")
        return EXIT_BLOCK
    atomic_write_text(args.out, masked)
    print(f"ALLOWED: sanitized copy written to {args.out}")
    return EXIT_ALLOW


def cmd_audit(args) -> int:
    s = _Scan(args)
    _summary(args, s)
    args.audit_dir = args.out_dir
    _maybe_audit(args, s)
    return _code(s)


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("input", help="log, CSV or JSONL file (scanned line by line)")
    p.add_argument(
        "--policy", default=DEFAULT_POLICY, help=f"policy TOML (default {DEFAULT_POLICY})"
    )
    p.add_argument("--model", default=DEFAULT_MODEL, help=f"model .pkl (default {DEFAULT_MODEL})")
    p.add_argument("--no-ml", action="store_true", help="rules only (explicit opt-out of ML layer)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="zguard", description="Privacy firewall for AI workloads."
    )
    parser.add_argument("--version", action="version", version=f"zguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan", help="detect findings and show the policy decision")
    _common(p)
    p.add_argument("-v", "--verbose", action="store_true", help="list every finding")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("review", help="list items that need a human look")
    _common(p)
    p.add_argument("--show-lines", action="store_true", help="print the (masked) lines")
    p.set_defaults(func=cmd_review)

    p = sub.add_parser("sanitize", help="write a masked copy, only if policy says ALLOW")
    _common(p)
    p.add_argument("--out", required=True, help="output file (must differ from input)")
    p.add_argument("--audit-dir", help="also write audit.json and audit.md here")
    p.set_defaults(func=cmd_sanitize)

    p = sub.add_parser("audit", help="write JSON and Markdown audit summaries")
    _common(p)
    p.add_argument("--out-dir", default="out/audit", help="folder for audit.json / audit.md")
    p.set_defaults(func=cmd_audit)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ModelIntegrityError as exc:
        msg = f"model check failed: {exc}"
    except PolicyError as exc:
        msg = f"policy error: {exc}"
    except UnicodeDecodeError:
        msg = "input is not valid UTF-8"
    except OSError as exc:
        msg = f"I/O error ({type(exc).__name__})"
    except Exception as exc:  # noqa: BLE001 - fail closed on anything unexpected
        msg = f"unexpected {type(exc).__name__}"
        if os.environ.get("ZGUARD_DEBUG") == "1":  # may expose values; opt-in only
            traceback.print_exc()
    print(f"BLOCKED (fail-closed): {msg}. No output file was written.", file=sys.stderr)
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
