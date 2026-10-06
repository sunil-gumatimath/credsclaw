"""Pattern matching tests — all 7 provider regex patterns."""

import re

from auditor import (
    ANTHROPIC_KEY_PATTERN,
    AWS_ACCESS_KEY_PATTERN,
    AZURE_CONNECTION_STRING_PATTERN,
    GITHUB_TOKEN_PATTERN,
    GOOGLE_AI_KEY_PATTERN,
    NON_VALIDATABLE_PROVIDERS,
    OPENAI_KEY_PATTERN,
    PROVIDER_CONFIGS,
    SLACK_TOKEN_PATTERN,
    VALIDATABLE_PROVIDERS,
    VALIDATION_MAP,
)


# ~~~ Registry consistency ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~────
def test_validatable_providers_match_validation_map():
    """VALIDATABLE_PROVIDERS and the validator registries must not drift.

    VALIDATABLE_PROVIDERS is documentation only (the scanner dispatches through
    VALIDATION_MAP and skips NON_VALIDATABLE_PROVIDERS), so nothing would fail
    at runtime if the two disagreed. Pin them together here.
    """
    registered = {display for display, _search, _pattern in PROVIDER_CONFIGS.values()}
    assert VALIDATION_MAP.keys() == registered, "VALIDATION_MAP does not cover every provider"
    assert registered == VALIDATABLE_PROVIDERS | NON_VALIDATABLE_PROVIDERS
    assert not (VALIDATABLE_PROVIDERS & NON_VALIDATABLE_PROVIDERS)


# ~~~ Anthropic ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_valid_anthropic_key():
    key = "sk-ant-api03-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"
    matches = re.findall(ANTHROPIC_KEY_PATTERN, key)
    assert len(matches) == 1


def test_invalid_anthropic_key():
    for key in ["sk-ant-short", "sk-ant", "random-string"]:
        assert len(re.findall(ANTHROPIC_KEY_PATTERN, key)) == 0


# ~~~ OpenAI ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_valid_openai_formats():
    classic = "sk-" + "a" * 48
    classic_with_hyphen = "sk-" + "a" * 24 + "-" + "a" * 23
    proj = "sk-proj-" + "a" * 30 + "T3BlbkFJ" + "b" * 30
    svcacct = "sk-svcacct-" + "a" * 30 + "T3BlbkFJ" + "b" * 30
    admin = "sk-admin-" + "a" * 30 + "T3BlbkFJ" + "b" * 30
    svc = "sk-svc-" + "a" * 30 + "T3BlbkFJ" + "b" * 30
    session = "sk-session-" + "a" * 30 + "T3BlbkFJ" + "b" * 30
    assert len(re.findall(OPENAI_KEY_PATTERN, classic)) == 1
    assert len(re.findall(OPENAI_KEY_PATTERN, classic_with_hyphen)) == 1
    assert len(re.findall(OPENAI_KEY_PATTERN, proj)) == 1
    assert len(re.findall(OPENAI_KEY_PATTERN, svcacct)) == 1
    assert len(re.findall(OPENAI_KEY_PATTERN, admin)) == 1
    assert len(re.findall(OPENAI_KEY_PATTERN, svc)) == 1
    assert len(re.findall(OPENAI_KEY_PATTERN, session)) == 1


def test_invalid_openai_key():
    for key in ["sk-short", "not-a-key"]:
        assert len(re.findall(OPENAI_KEY_PATTERN, key)) == 0


# ~~~ Google ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_valid_google_key():
    assert len(re.findall(GOOGLE_AI_KEY_PATTERN, "AIza" + "a" * 35)) == 1


# ~~~ AWS ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_valid_aws_key():
    assert len(re.findall(AWS_ACCESS_KEY_PATTERN, "AKIA" + "A" * 16)) == 1


def test_invalid_aws_key():
    for key in ["AKIA", "AKIAshort", "NOTAKIA123456789012"]:
        assert len(re.findall(AWS_ACCESS_KEY_PATTERN, key)) == 0


def test_aws_all_prefixes_match():
    for prefix in [
        "AKIA",
        "ASIA",
        "ABIA",
        "ACCA",
        "APKA",
        "AIDA",
        "AROA",
        "AIPA",
        "ANPA",
        "AGPA",
        "ASCA",
    ]:
        assert len(re.findall(AWS_ACCESS_KEY_PATTERN, prefix + "A" * 16)) == 1


def test_search_prefixes_cover_matchable_prefixes():
    aws_query = PROVIDER_CONFIGS["aws"][1]
    for prefix in [
        "AKIA",
        "ASIA",
        "ABIA",
        "ACCA",
        "APKA",
        "AIDA",
        "AROA",
        "AIPA",
        "ANPA",
        "AGPA",
        "ASCA",
    ]:
        assert prefix in aws_query
    assert "xoxp-" in PROVIDER_CONFIGS["slack"][1]


# ~~~ GitHub ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_valid_github_token():
    tokens = [
        "ghp_" + "a" * 40,
        "gho_" + "b" * 36,
        "ghs_" + "c" * 36,
        "ghr_" + "d" * 36,
        "github_pat_" + "e" * 22 + "_" + "f" * 59,
    ]
    for token in tokens:
        assert len(re.findall(GITHUB_TOKEN_PATTERN, token)) == 1
    assert len(re.findall(GITHUB_TOKEN_PATTERN, "ghu_" + "g" * 36)) == 1


def test_github_token_boundaries():
    assert len(re.findall(GITHUB_TOKEN_PATTERN, "ghp_" + "a" * 36)) == 1
    assert len(re.findall(GITHUB_TOKEN_PATTERN, "ghp_" + "a" * 40)) == 1
    assert len(re.findall(GITHUB_TOKEN_PATTERN, "ghp_" + "a" * 41)) == 0
    assert len(re.findall(GITHUB_TOKEN_PATTERN, "ghs_" + "c" * 76)) == 1
    assert len(re.findall(GITHUB_TOKEN_PATTERN, "ghs_" + "c" * 77)) == 0


# ~~~ Slack ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_valid_slack_token():
    token = "xoxb" + "-1234567890123-1234567890123-abcdefghijklmnopqrstuvwx"
    assert len(re.findall(SLACK_TOKEN_PATTERN, token)) == 1


# ~~~ Azure ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_valid_azure_connection_string():
    key = (
        "Endpoint=sb://my-namespace.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey="
        + "A" * 43
        + "="
    )
    assert len(re.findall(AZURE_CONNECTION_STRING_PATTERN, key)) == 1
    storage = "DefaultEndpointsProtocol=https;AccountName=mystorage;AccountKey=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh0123456789+/=="
    assert len(re.findall(AZURE_CONNECTION_STRING_PATTERN, storage)) == 1


def test_azure_rejects_short_key_material():
    short = "Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=Root;SharedAccessKey=A="
    assert len(re.findall(AZURE_CONNECTION_STRING_PATTERN, short)) == 0
