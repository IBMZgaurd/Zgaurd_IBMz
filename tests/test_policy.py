import pytest

from tests.conftest import CONFIGS
from zguard.findings import ML_TYPE, Finding
from zguard.policy import Policy, PolicyError

standard = Policy.load(CONFIGS / "policy.toml")
strict = Policy.load(CONFIGS / "policy_strict.toml")


def rule(t="EMAIL"):
    return Finding(type=t, line=1, start=0, end=5, source="rule")


def ml(score):
    return Finding(type=ML_TYPE, line=2, source="ml", score=score)


@pytest.mark.parametrize(
    "policy,findings,expected",
    [
        (standard, [], "ALLOW"),
        (standard, [rule("EMAIL"), rule("API_KEY")], "ALLOW"),  # masked => resolved
        (standard, [ml(0.60)], "ALLOW"),  # medium: review only
        (standard, [ml(0.90)], "BLOCK"),  # high, cannot be masked
        (strict, [ml(0.50)], "BLOCK"),  # strict blocks medium
        (strict, [rule("EMAIL")], "ALLOW"),
        (standard, [rule("MYSTERY")], "BLOCK"),  # unknown type fails closed
    ],
)
def test_decisions(policy, findings, expected):
    assert policy.decide(findings).action == expected


def test_standard_review_items_listed():
    d = standard.decide([ml(0.6)])
    assert d.allowed and len(d.review) == 1


def test_ml_without_score_is_treated_as_high():
    assert standard.decide([Finding(type=ML_TYPE, line=1, source="ml")]).action == "BLOCK"


def test_unmasked_high_rule_blocks(tmp_path):
    p = tmp_path / "p.toml"
    p.write_text(
        "ml_review_threshold = 0.5\nml_high_risk_threshold = 0.8\nauto_mask = []\n"
        '[severity]\nAPI_KEY = "high"\n[decision]\nblock_on = ["high"]\n'
    )
    assert Policy.load(p).decide([rule("API_KEY")]).action == "BLOCK"


@pytest.mark.parametrize(
    "body",
    [
        "ml_review_threshold = 0.9\nml_high_risk_threshold = 0.5\n",  # reversed
        'mode = "weird"\nml_review_threshold = 0.5\nml_high_risk_threshold = 0.9\n',
        "ml_review_threshold = 0.5\n",  # missing key
        "this is not toml [[[",
    ],
)
def test_invalid_policy_raises(tmp_path, body):
    p = tmp_path / "bad.toml"
    p.write_text(body)
    with pytest.raises(PolicyError):
        Policy.load(p)


def test_missing_policy_raises(tmp_path):
    with pytest.raises(PolicyError):
        Policy.load(tmp_path / "nope.toml")
