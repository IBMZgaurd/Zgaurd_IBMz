"""TF-IDF + Logistic Regression line scorer with checksum-verified model loading.

The model outputs a probability per line and no exact span. It never decides ALLOW/BLOCK.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import pickle
import tempfile
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline


class ModelIntegrityError(RuntimeError):
    """Model file missing, checksum missing, or checksum mismatch."""


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _sidecar(path: Path) -> Path:
    return path.with_name(path.name + ".sha256")


def train_model(texts: list[str], labels: list[int], seed: int = 42) -> Pipeline:
    model = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    analyzer="char_wb",
                    ngram_range=(2, 5),
                    min_df=2,
                    sublinear_tf=True,
                    max_features=30000,
                ),
            ),
            (
                "clf",
                LogisticRegression(
                    C=4.0, max_iter=1000, class_weight="balanced", random_state=seed
                ),
            ),
        ]
    )
    model.fit(texts, labels)
    return model


def save_model(model: Pipeline, path: str | Path) -> str:
    """Pickle the model atomically and write '<path>.sha256'. Returns the digest."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            pickle.dump(model, f)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    digest = sha256_file(path)
    _sidecar(path).write_text(f"{digest}  {path.name}\n", encoding="ascii")
    return digest


def load_model(path: str | Path) -> Pipeline:
    """Verify SHA-256 BEFORE unpickling. Refuse anything unverified."""
    path = Path(path)
    side = _sidecar(path)
    if not path.is_file():
        raise ModelIntegrityError(f"model file not found: {path}")
    if not side.is_file():
        raise ModelIntegrityError(f"checksum file not found: {side}")
    expected = side.read_text(encoding="ascii").split()[0].strip().lower()
    actual = sha256_file(path)
    if not hmac.compare_digest(expected, actual):
        raise ModelIntegrityError(f"checksum mismatch for {path.name}; refusing to load")
    with open(path, "rb") as f:
        return pickle.load(f)  # noqa: S301 - verified, self-trained artefact only


def predict_scores(model: Pipeline, texts: list[str], batch: int = 20000) -> list[float]:
    out: list[float] = []
    for i in range(0, len(texts), batch):
        proba = model.predict_proba(texts[i : i + batch])[:, 1]
        out.extend(float(p) for p in proba)
    return out


def suggest_thresholds(y_true: list[int], scores: list[float]) -> dict:
    """Pick thresholds on the VALIDATION set only. Freeze them before touching the test set."""
    y = np.asarray(y_true)
    s = np.asarray(scores)
    best_f1, review = -1.0, 0.5
    high = 0.9
    for t in np.arange(0.05, 0.96, 0.05):
        pred = s >= t
        tp = int(np.sum(pred & (y == 1)))
        fp = int(np.sum(pred & (y == 0)))
        fn = int(np.sum(~pred & (y == 1)))
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * p * r / (p + r) if p + r else 0.0
        if f1 > best_f1:
            best_f1, review = f1, float(round(t, 2))
    for t in np.arange(0.5, 0.99, 0.05):
        pred = s >= t
        tp = int(np.sum(pred & (y == 1)))
        fp = int(np.sum(pred & (y == 0)))
        if tp + fp and tp / (tp + fp) >= 0.98:
            high = float(round(t, 2))
            break
    return {"ml_review_threshold": review, "ml_high_risk_threshold": max(high, review)}
