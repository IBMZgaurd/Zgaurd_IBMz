"""Train the TF-IDF + Logistic Regression model; write the artefact and its SHA-256 file."""

import argparse
import json
import platform
import sys
from pathlib import Path

import numpy as np
import sklearn

from zguard.ml import predict_scores, save_model, suggest_thresholds, train_model
from zguard.synth import read_jsonl


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", default="data/generated")
    ap.add_argument("--out", default="models")
    ap.add_argument("--name", default="zguard_lr", help="e.g. zguard_lr_s390x on LinuxONE")
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()

    train = read_jsonl(Path(a.data) / "train.jsonl")
    val = read_jsonl(Path(a.data) / "val.jsonl")
    model = train_model([r["text"] for r in train], [r["label"] for r in train], a.seed)

    y_val = [r["label"] for r in val]
    scores = predict_scores(model, [r["text"] for r in val])
    thresholds = suggest_thresholds(y_val, scores)

    path = Path(a.out) / f"{a.name}.pkl"
    digest = save_model(model, path)
    meta = {
        "seed": a.seed,
        "n_train": len(train),
        "n_val": len(val),
        "sha256": digest,
        "suggested_thresholds_from_validation": thresholds,
        "python": sys.version.split()[0],
        "sklearn": sklearn.__version__,
        "numpy": np.__version__,
        "machine": platform.machine(),
        "byteorder": sys.byteorder,
    }
    (Path(a.out) / f"{a.name}.meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    print(f"model   : {path}")
    print(f"sha256  : {digest}")
    print(f"suggested thresholds (validation only): {thresholds}")
    print("If you change configs/policy.toml, freeze it before running evaluate.py.")


if __name__ == "__main__":
    main()
