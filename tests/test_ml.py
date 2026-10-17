import pytest

from zguard.ml import ModelIntegrityError, load_model, predict_scores, save_model


def test_roundtrip_and_scores(model_path):
    model = load_model(model_path)
    risky = "2026-02-01T10:00:00Z INFO svc temporary password for new hire is Xk9#mQ2vLp!4"
    safe = "2026-02-01T10:00:00Z INFO svc health check ok uptime_s=3600"
    hi, lo = predict_scores(model, [risky, safe])
    assert hi > 0.5 > lo


def test_tampered_model_is_refused(model_path, tmp_path):
    copy = tmp_path / "m.pkl"
    copy.write_bytes(model_path.read_bytes() + b"x")
    (tmp_path / "m.pkl.sha256").write_text((model_path.parent / "m.pkl.sha256").read_text())
    with pytest.raises(ModelIntegrityError):
        load_model(copy)


def test_missing_checksum_is_refused(model_path, tmp_path):
    copy = tmp_path / "m.pkl"
    copy.write_bytes(model_path.read_bytes())
    with pytest.raises(ModelIntegrityError):
        load_model(copy)


def test_missing_model_is_refused(tmp_path):
    with pytest.raises(ModelIntegrityError):
        load_model(tmp_path / "none.pkl")


def test_save_writes_checksum_file(model_path):
    assert (model_path.parent / "m.pkl.sha256").read_text().split()[1] == "m.pkl"
    assert save_model  # public API present
