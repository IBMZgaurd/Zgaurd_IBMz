from pathlib import Path

import pytest

from zguard.ml import save_model, train_model
from zguard.synth import generate

ROOT = Path(__file__).resolve().parents[1]
CONFIGS = ROOT / "configs"


@pytest.fixture(scope="session")
def model_path(tmp_path_factory) -> Path:
    """Small deterministic model trained on synthetic data, with its checksum file."""
    recs = generate(1500, seed=7)
    model = train_model([r["text"] for r in recs], [r["label"] for r in recs], seed=7)
    path = tmp_path_factory.mktemp("model") / "m.pkl"
    save_model(model, path)
    return path


@pytest.fixture()
def policy_path() -> Path:
    return CONFIGS / "policy.toml"
