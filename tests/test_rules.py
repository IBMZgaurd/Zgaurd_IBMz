from zguard.rules import detect_line


def found(line):
    return [(t, line[s:e]) for t, s, e in detect_line(line)]


def test_email():
    assert found("sent to jane.doe@example.com now") == [("EMAIL", "jane.doe@example.com")]


def test_email_trailing_period():
    assert found("contact bob@corp.example.org.") == [("EMAIL", "bob@corp.example.org")]


def test_ipv4_valid_and_invalid():
    assert found("login from 10.2.3.4 ok") == [("IPV4", "10.2.3.4")]
    assert found("bad 999.1.1.1 value") == []
    assert found("release 3.1.4.1.5 tagged") == []
    assert found("padded 01.02.03.04 value") == []


def test_zgk_key():
    key = "zgk_test_" + "Ab3dEf6hIj9kLm2nOp5qRs8t"
    assert found(f"rejected {key}") == [("API_KEY", key)]


def test_aws_style_key_built_at_runtime():
    key = "AKIA" + "ABCDEFGH12345678"
    assert found(f"id {key} seen") == [("API_KEY", key)]


def test_bearer_token():
    tok = "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z"
    assert found(f"Authorization: Bearer {tok}") == [("API_KEY", tok)]


def test_labeled_key_requires_secret_like_value():
    assert found("token=refill_rate_per_second") == []
    assert found("api_key=<redacted> rotation") == []
    tok = "k9Xv2Lm8Qa4Zp7Rt1Wc3"
    assert found(f"api_key={tok} loaded") == [("API_KEY", tok)]


def test_user_id_plain_and_json():
    assert found("profile user_id=U123456 done") == [("USER_ID", "U123456")]
    assert found('{"user_id":"U654321","x":1}') == [("USER_ID", "U654321")]
    assert found("user_id=null unauthenticated") == []


def test_overlapping_matches_collapse_to_one():
    key = "zgk_test_" + "Ab3dEf6hIj9kLm2nOp5qRs8t"
    assert found(f"api_key={key}") == [("API_KEY", key)]


def test_spans_are_exact_for_multiple_findings():
    line = "a@b.com from 1.2.3.4"
    assert [(t, s, e) for t, s, e in detect_line(line)] == [("EMAIL", 0, 7), ("IPV4", 13, 20)]


def test_clean_line_has_no_findings():
    assert detect_line("2026-01-01T00:00:00Z INFO svc request completed status=200") == []
