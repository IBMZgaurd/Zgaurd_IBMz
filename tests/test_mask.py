from zguard.findings import Finding
from zguard.mask import atomic_write_text, mask_line, mask_lines, placeholder
from zguard.pipeline import scan_lines, verify_masked
from zguard.policy import Policy


def test_placeholder_format():
    assert placeholder("EMAIL") == "[REDACTED:EMAIL]"


def test_mask_line_multiple_spans_and_eol():
    fs = [Finding("EMAIL", 1, 0, 7), Finding("IPV4", 1, 13, 20)]
    assert mask_line("a@b.com from 1.2.3.4\r\n", fs) == "[REDACTED:EMAIL] from [REDACTED:IPV4]\r\n"


def test_end_to_end_mask_and_verify(policy_path):
    policy = Policy.load(policy_path)
    lines = ["mail jane@example.com ok\n", "nothing here\n", "from 8.8.4.4"]
    masked = mask_lines(lines, scan_lines(lines, policy), policy)
    assert masked == ["mail [REDACTED:EMAIL] ok\n", "nothing here\n", "from [REDACTED:IPV4]"]
    assert verify_masked(masked)
    assert not verify_masked(["still jane@example.com\n"])


def test_atomic_write_leaves_no_temp_files(tmp_path):
    out = tmp_path / "sub" / "out.log"
    atomic_write_text(out, ["x\n", "y\n"])
    assert out.read_text() == "x\ny\n"
    assert [p.name for p in out.parent.iterdir()] == ["out.log"]


def test_atomic_write_preserves_old_file_on_failure(tmp_path):
    out = tmp_path / "out.log"
    out.write_text("old")
    try:
        atomic_write_text(out, [object()])  # not a str -> write fails mid-way
    except TypeError:
        pass
    assert out.read_text() == "old"
    assert [p.name for p in tmp_path.iterdir()] == ["out.log"]
