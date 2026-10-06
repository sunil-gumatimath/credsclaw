"""Cross-provider key-format verification.

Every sample below is a synthetic token shaped to the format its vendor
documents (verified October 2026). These tests pin the *detection contract*:
real keys match, truncated/placeholder values do not, and no sample is claimed
by two providers at once.
"""

import re

import pytest

from auditor.patterns import PROVIDER_CONFIGS

# (provider, should_match, sample)
FORMAT_CASES = [
    # --- Anthropic: sk-ant-api03 / oat01, ~95-char tail ending AA -------
    ("anthropic", True, "sk-ant-api03-" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9" + "AA"),
    ("anthropic", True, "sk-ant-oat01-" + "x" * 95 + "AA"),
    ("anthropic", True, "sk-ant-admin01-" + "x" * 95),
    ("anthropic", False, "sk-ant-api03-short"),
    # --- OpenAI: project keys carry T3BlbkFJ and run ~155 chars ---------
    ("openai", True, "sk-proj-" + "a" * 26 + "T3BlbkFJ" + "b" * 74),
    ("openai", True, "sk-proj-" + "a" * 100 + "T3BlbkFJ" + "b" * 60),
    ("openai", True, "sk-svcacct-" + "a" * 40 + "T3BlbkFJ" + "b" * 40),
    ("openai", True, "sk-" + "A" * 48),
    ("openai", False, "sk-proj-tooshort"),
    # --- Google: AIza + 35, ya29. OAuth ---------------------------------
    ("google", True, "AIza" + "a" * 35),
    ("google", True, "ya29." + "a" * 60),
    ("google", False, "AIza" + "a" * 20),
    # --- AWS: documented prefixes + 16 uppercase alphanumerics -----------
    ("aws", True, "AKIA" + "0123456789ABCDEF"),
    ("aws", True, "ASIA0123456789ABCDEF"),
    ("aws", True, "AROA0123456789ABCDEF"),
    ("aws", False, "AKIAIOSFODNN7ABCDEF"),  # 15-char tail
    ("aws", False, "AKIASHORT"),
    # --- GitHub: classic prefixes and fine-grained PATs ------------------
    ("github", True, "ghp_" + "a" * 36),
    ("github", True, "gho_" + "b" * 36),
    ("github", True, "ghs_" + "c" * 36),
    ("github", True, "ghr_" + "d" * 36),
    ("github", True, "ghu_" + "e" * 36),
    ("github", True, "github_pat_" + "A" * 22 + "_" + "B" * 59),
    ("github", True, "github_pat_" + "A" * 30 + "_" + "B" * 93),
    ("github", False, "github_pat_short"),
    # --- Slack: classic, app-level xoxa-, xapp-/xwfp-, webhook -----------
    ("slack", True, "xoxb-123456789-987654321-" + "a" * 24),
    ("slack", True, "xoxp-123456789-987654321-" + "b" * 24),
    ("slack", True, "xoxr-123456789-987654321-" + "c" * 24),
    ("slack", True, "xoxa-2-T12345678-A12345678-" + "d" * 32),
    ("slack", True, "xoxa-1-T1-A1-" + "e" * 24),
    ("slack", True, "xapp-1-A024BE7LH6-" + "f" * 24),
    ("slack", True, "xwfp-1-abcdef-" + "g" * 24),
    ("slack", True, "https://hooks.slack.com/services/T00000000/B00000000/" + "H" * 24),
    ("slack", False, "xoxb-123"),
]

AZURE_CASES = [
    (
        True,
        "Endpoint=sb://acct.servicebus.windows.net/;SharedAccessKeyName=Root;"
        "SharedAccessKey=0123456789ABCDEF0123456789ABCDEF0123456789A=",
    ),
    (
        True,
        "DefaultEndpointsProtocol=https;AccountName=acct;"
        "AccountKey=0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF==",
    ),
    (False, "AccountKey=short"),
]

COMPILED = {name: re.compile(cfg[2]) for name, cfg in PROVIDER_CONFIGS.items()}


@pytest.mark.parametrize(("provider", "should_match", "sample"), FORMAT_CASES)
def test_provider_format(provider, should_match, sample):
    assert bool(COMPILED[provider].search(sample)) is should_match, sample[:48]


@pytest.mark.parametrize(("should_match", "sample"), AZURE_CASES)
def test_azure_format(should_match, sample):
    assert bool(COMPILED["azure"].search(sample)) is should_match, sample[:48]


def test_every_provider_has_a_fixture():
    """Each registered provider must be covered by at least one sample."""
    covered = {provider for provider, _, _ in FORMAT_CASES} | {"azure"}
    assert covered == set(PROVIDER_CONFIGS)


@pytest.mark.parametrize(("provider", "should_match", "sample"), FORMAT_CASES)
def test_no_cross_provider_overlap(provider, should_match, sample):
    """A key must not also satisfy another provider's pattern."""
    others = [n for n, rx in COMPILED.items() if n != provider and rx.search(sample)]
    assert not others, f"{provider} sample also matched: {others}"


def test_anthropic_key_not_reported_as_openai():
    """sk-ant-* satisfies the bare sk- length window; OpenAI must exclude it."""
    anthropic_key = "sk-ant-api03-" + "x" * 95 + "AA"
    assert COMPILED["anthropic"].search(anthropic_key)
    assert not COMPILED["openai"].search(anthropic_key)
