import socket

import zguard
from zguard.cli import main

KEY = "zgk_test_" + "Ab3dEf6hIj9kLm2nOp5qRs8t"
EMAIL = "jane.doe42@example.com"
SECRET_LINE = "2026-02-01T10:00:00Z INFO svc temporary password for new hire is Xk9#mQ2vLp!4"
LOW_ML_POLICY = (
    'mode = "standard"\nauto_mask = ["API_KEY","EMAIL","IPV4","USER_ID"]\n'
    "ml_review_threshold = 0.3\nml_high_risk_threshold = 0.5\n"
    '[severity]\nAPI_KEY="high"\nEMAIL="medium"\nIPV4="low"\nUSER_ID="low"\n'
    '[decision]\nblock_on=["high"]\n'
)


def write(path, text):
    path.write_text(text, encoding="utf-8")
    return str(path)


def base_args(cmd, src, model, policy):
    return [cmd, src, "--model", str(model), "--policy", str(policy)]


def test_package_imports():
    assert zguard.__version__


def test_sanitize_allow_masks_and_audits(tmp_path, model_path, policy_path):
    src = write(
        tmp_path / "in.log",
        f"2026-02-01T10:00:00Z INFO svc sent to {EMAIL} key={KEY} ok\n"
        "2026-02-01T10:00:01Z INFO svc health check ok uptime_s=3600\n",
    )
    out, audit_dir = tmp_path / "out.log", tmp_path / "audit"
    rc = main(
        base_args("sanitize", src, model_path, policy_path)
        + ["--out", str(out), "--audit-dir", str(audit_dir)]
    )
    assert rc == 0
    text = out.read_text()
    assert "[REDACTED:EMAIL]" in text and "[REDACTED:API_KEY]" in text
    assert EMAIL not in text and KEY not in text
    audit = (audit_dir / "audit.json").read_text() + (audit_dir / "audit.md").read_text()
    assert EMAIL not in audit and KEY not in audit  # never raw values
    assert (tmp_path / "in.log").read_text().count(EMAIL) == 1  # input untouched


def test_sanitize_block_writes_no_file(tmp_path, model_path):
    policy = write(tmp_path / "p.toml", LOW_ML_POLICY)
    src = write(tmp_path / "in.log", SECRET_LINE + "\n")
    out = tmp_path / "out.log"
    rc = main(base_args("sanitize", src, model_path, policy) + ["--out", str(out)])
    assert rc == 1
    assert not out.exists()
    assert [p.name for p in tmp_path.iterdir() if p.suffix == ".tmp"] == []


def test_block_with_audit_still_writes_audit_but_no_output(tmp_path, model_path):
    policy = write(tmp_path / "p.toml", LOW_ML_POLICY)
    src = write(tmp_path / "in.log", SECRET_LINE + "\n")
    out, audit_dir = tmp_path / "out.log", tmp_path / "a"
    main(
        base_args("sanitize", src, model_path, policy)
        + ["--out", str(out), "--audit-dir", str(audit_dir)]
    )
    assert not out.exists() and "BLOCK" in (audit_dir / "audit.json").read_text()


def test_missing_model_fails_closed(tmp_path, policy_path):
    src = write(tmp_path / "in.log", "hello\n")
    out = tmp_path / "out.log"
    rc = main(
        base_args("sanitize", src, tmp_path / "missing.pkl", policy_path) + ["--out", str(out)]
    )
    assert rc == 2 and not out.exists()


def test_corrupt_model_fails_closed(tmp_path, model_path, policy_path):
    bad = tmp_path / "m.pkl"
    bad.write_bytes(model_path.read_bytes() + b"!")
    (tmp_path / "m.pkl.sha256").write_text((model_path.parent / "m.pkl.sha256").read_text())
    src = write(tmp_path / "in.log", "hello\n")
    out = tmp_path / "out.log"
    assert main(base_args("sanitize", src, bad, policy_path) + ["--out", str(out)]) == 2
    assert not out.exists()


def test_bad_policy_and_unreadable_input_fail_closed(tmp_path, model_path, policy_path):
    out = tmp_path / "out.log"
    src = write(tmp_path / "in.log", "hello\n")
    bad_pol = write(tmp_path / "bad.toml", "nonsense [[[")
    assert main(base_args("sanitize", src, model_path, bad_pol) + ["--out", str(out)]) == 2
    binary = tmp_path / "bin.log"
    binary.write_bytes(b"\xff\xfe\x00bad bytes\n")
    assert (
        main(base_args("sanitize", str(binary), model_path, policy_path) + ["--out", str(out)]) == 2
    )
    assert (
        main(
            base_args("sanitize", str(tmp_path / "nope"), model_path, policy_path)
            + ["--out", str(out)]
        )
        == 2
    )
    assert not out.exists()


def test_output_must_differ_from_input(tmp_path, model_path, policy_path):
    src = write(tmp_path / "in.log", "hello\n")
    rc = main(base_args("sanitize", src, model_path, policy_path) + ["--out", src])
    assert rc == 2 and (tmp_path / "in.log").read_text() == "hello\n"


def test_scan_review_audit_commands(tmp_path, model_path, policy_path, capsys):
    src = write(tmp_path / "in.log", f"sent to {EMAIL}\nplain line\n")
    assert main(base_args("scan", src, model_path, policy_path) + ["-v"]) == 0
    assert EMAIL not in capsys.readouterr().out
    assert main(base_args("review", src, model_path, policy_path) + ["--show-lines"]) == 0
    assert (
        main(base_args("audit", src, model_path, policy_path) + ["--out-dir", str(tmp_path / "au")])
        == 0
    )
    assert (tmp_path / "au" / "audit.json").exists() and (tmp_path / "au" / "audit.md").exists()


def test_no_ml_flag_runs_without_model(tmp_path, policy_path):
    src = write(tmp_path / "in.log", f"sent to {EMAIL}\n")
    out = tmp_path / "o.log"
    rc = main(
        base_args("sanitize", src, tmp_path / "none.pkl", policy_path)
        + ["--no-ml", "--out", str(out)]
    )
    assert rc == 0 and EMAIL not in out.read_text()


def test_no_network_calls_at_runtime(tmp_path, model_path, policy_path, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("network access attempted")

    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    src = write(tmp_path / "in.log", f"sent to {EMAIL}\n")
    out = tmp_path / "o.log"
    assert main(base_args("sanitize", src, model_path, policy_path) + ["--out", str(out)]) == 0


def test_error_messages_do_not_echo_values(tmp_path, model_path, capsys):
    bad = write(tmp_path / "p.toml", f"junk {EMAIL} [[[")
    src = write(tmp_path / "in.log", "x\n")
    main(base_args("scan", src, model_path, bad))
    err = capsys.readouterr()
    assert EMAIL not in err.out + err.err
