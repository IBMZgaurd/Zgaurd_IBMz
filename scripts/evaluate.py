"""Compare rules-only, ML-only and hybrid on the held-out test split. Honest, as measured."""

import argparse
import json
import platform
import sys
import time
from pathlib import Path

import numpy as np
import sklearn

from zguard.audit import get_hmac_key
from zguard.ml import load_model, predict_scores, sha256_file
from zguard.pipeline import scan_lines
from zguard.policy import Policy
from zguard.rules import detect_line
from zguard.synth import read_jsonl


def prf(tp: int, fp: int, fn: int, tn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(p, 4),
        "recall": round(r, 4),
        "f1": round(2 * p * r / (p + r), 4) if p + r else 0.0,
        "fpr": round(fp / (fp + tn), 4) if fp + tn else 0.0,
    }  # fmt: skip


def line_metrics(labels: list[int], flags: list[bool]) -> dict:
    tp = sum(1 for y, f in zip(labels, flags, strict=True) if y and f)
    fp = sum(1 for y, f in zip(labels, flags, strict=True) if not y and f)
    fn = sum(1 for y, f in zip(labels, flags, strict=True) if y and not f)
    tn = sum(1 for y, f in zip(labels, flags, strict=True) if not y and not f)
    return prf(tp, fp, fn, tn)


def overlaps(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return a[0] < b[1] and b[0] < a[1]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", default="data/generated")
    ap.add_argument("--model", default="models/zguard_lr.pkl")
    ap.add_argument("--policy", default="configs/policy.toml")
    ap.add_argument("--out", default="results")
    ap.add_argument("--bench-lines", type=int, default=100000)
    a = ap.parse_args()

    policy = Policy.load(a.policy)
    model = load_model(a.model)  # checksum verified before unpickling
    test = read_jsonl(Path(a.data) / "test.jsonl")
    texts = [r["text"] for r in test]
    labels = [r["label"] for r in test]

    rule_spans = [detect_line(t) for t in texts]
    scores = predict_scores(model, texts)
    rule_flag = [bool(s) for s in rule_spans]
    ml_flag = [s >= policy.ml_review_threshold for s in scores]
    hybrid_flag = [r or m for r, m in zip(rule_flag, ml_flag, strict=True)]
    line_level = {
        "rules_only": line_metrics(labels, rule_flag),
        "ml_only": line_metrics(labels, ml_flag),
        "hybrid": line_metrics(labels, hybrid_flag),
    }

    # Span-level redaction: does a rule span overlap each gold span?
    per_type: dict[str, dict] = {}
    residual_lines = residual_ml_review = residual_ml_high = 0
    for rec, spans, score in zip(test, rule_spans, scores, strict=True):
        missed_here = False
        for g in rec["spans"]:
            row = per_type.setdefault(g["type"], {"gold": 0, "caught": 0, "exact": 0})
            row["gold"] += 1
            hit = [s for s in spans if overlaps((s[1], s[2]), (g["start"], g["end"]))]
            row["caught"] += bool(hit)
            row["exact"] += any((s[1], s[2]) == (g["start"], g["end"]) for s in hit)
            missed_here |= not hit
        if missed_here:
            residual_lines += 1
            residual_ml_review += score >= policy.ml_review_threshold
            residual_ml_high += score >= policy.ml_high_risk_threshold
    gold_total = sum(r["gold"] for r in per_type.values())
    caught_total = sum(r["caught"] for r in per_type.values())
    span_level = {
        "per_type": per_type,
        "gold_spans": gold_total,
        "redaction_misses_by_rules": gold_total - caught_total,
        "residual_lines": residual_lines,
        "residual_lines_flagged_for_review_by_ml": int(residual_ml_review),
        "residual_lines_that_trigger_block_by_ml": int(residual_ml_high),
    }

    # End-to-end policy decisions on the whole test file and on its clean subset.
    key = get_hmac_key()
    clean = [t for t, y in zip(texts, labels, strict=True) if not y]
    all_lines = [t + "\n" for t in texts]
    clean_lines = [t + "\n" for t in clean]
    e2e = {}
    for name, m in (("rules_only", None), ("hybrid", model)):
        d_all = policy.decide(scan_lines(all_lines, policy, m, key))
        d_clean = policy.decide(scan_lines(clean_lines, policy, m, key))
        e2e[name] = {
            "full_test_file": d_all.action,
            "full_test_blocking_findings": len(d_all.blocking),
            "clean_subset_file": d_clean.action,
            "clean_subset_blocking_findings": len(d_clean.blocking),
        }

    # Throughput (measured on THIS machine; record hardware alongside).
    n = a.bench_lines
    bench_lines = [all_lines[i % len(all_lines)] for i in range(n)]
    t0 = time.perf_counter()
    scan_lines(bench_lines, policy, None, key)
    t_rules = time.perf_counter() - t0
    t0 = time.perf_counter()
    scan_lines(bench_lines, policy, model, key)
    t_hybrid = time.perf_counter() - t0
    bench = {
        "lines": n,
        "rules_only_seconds": round(t_rules, 2),
        "hybrid_seconds": round(t_hybrid, 2),
        "hybrid_lines_per_second": round(n / t_hybrid),
        "target_100k_lines_under_60s_met": bool(n >= 100000 and t_hybrid < 60),
    }
    hardware = {
        "machine": platform.machine(),
        "processor": platform.processor(),
        "system": platform.platform(),
        "python": sys.version.split()[0],
        "sklearn": sklearn.__version__,
        "numpy": np.__version__,
        "byteorder": sys.byteorder,
        "model_sha256": sha256_file(a.model),
    }
    results = {
        "policy_mode": policy.mode,
        "thresholds": [policy.ml_review_threshold, policy.ml_high_risk_threshold],
        "test_lines": len(test),
        "line_level": line_level,
        "span_level": span_level,
        "end_to_end_policy": e2e,
        "throughput": bench,
        "hardware": hardware,
    }

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "metrics.json").write_text(json.dumps(results, indent=2) + "\n")

    md = ["# ZGuard evaluation (synthetic data, as measured)", ""]
    md += [f"Policy mode `{policy.mode}`, ML thresholds review/high = {results['thresholds']}.", ""]
    md += ["## Line-level detection", ""]
    md += [
        "| System | Precision | Recall | F1 | FPR | TP | FP | FN | TN |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for name, m in line_level.items():
        md.append(
            f"| {name} | {m['precision']} | {m['recall']} | {m['f1']} | {m['fpr']} "
            f"| {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} |"
        )
    md += ["", "## Span-level redaction by the rule layer", ""]
    md += ["| Gold type | Gold spans | Caught | Exact span | Missed |", "|---|---|---|---|---|"]
    for t, r in sorted(per_type.items()):
        md.append(
            f"| {t} | {r['gold']} | {r['caught']} | {r['exact']} | {r['gold'] - r['caught']} |"
        )
    md += [
        "",
        f"Redaction misses by rules: **{span_level['redaction_misses_by_rules']}** of {gold_total} "
        f"gold spans. Lines with a miss: {residual_lines}; of those, ML flags "
        f"{span_level['residual_lines_flagged_for_review_by_ml']} for review and "
        f"{span_level['residual_lines_that_trigger_block_by_ml']} at BLOCK level.",
        "",
        "## End-to-end policy decision",
        "",
        "| System | Full test file | Clean subset |",
        "|---|---|---|",
    ]
    for name, e in e2e.items():
        md.append(
            f"| {name} | {e['full_test_file']} ({e['full_test_blocking_findings']} blocking) "
            f"| {e['clean_subset_file']} ({e['clean_subset_blocking_findings']} blocking) |"
        )
    md += [
        "",
        "## Throughput",
        "",
        f"{n} lines: rules-only {bench['rules_only_seconds']} s, "
        f"hybrid {bench['hybrid_seconds']} s "
        f"({bench['hybrid_lines_per_second']} lines/s). Target (100k lines < 60 s): "
        f"{'met' if bench['target_100k_lines_under_60s_met'] else 'not met / not tested at 100k'}.",
        "",
        "## Hardware and versions",
        "",
    ]
    md += [f"- {k}: {v}" for k, v in hardware.items()]
    md += ["", "Synthetic data is easier than real logs; see docs/limitations.md.", ""]
    (out / "RESULTS.md").write_text("\n".join(md), encoding="utf-8")
    print("\n".join(md))


if __name__ == "__main__":
    main()
