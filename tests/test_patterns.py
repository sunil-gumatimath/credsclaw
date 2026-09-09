"""Pattern matching tests — all 14 provider regex patterns."""

import re

from auditor import (
    ANTHROPIC_KEY_PATTERN,
    AWS_ACCESS_KEY_PATTERN,
    AZURE_CONNECTION_STRING_PATTERN,
    CLOUDFLARE_TOKEN_PATTERN,
    GITHUB_TOKEN_PATTERN,
    GOOGLE_AI_KEY_PATTERN,
    GROQ_API_KEY_PATTERN,
    HUGGINGFACE_KEY_PATTERN,
    MISTRAL_API_KEY_PATTERN,
    OPENAI_KEY_PATTERN,
    OPENROUTER_API_KEY_PATTERN,
    PROVIDER_CONFIGS,
    REPLICATE_API_TOKEN_PATTERN,
    SLACK_TOKEN_PATTERN,
    TOGETHER_API_KEY_PATTERN,
)


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
    assert "cft_" in PROVIDER_CONFIGS["cloudflare"][1]
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


# ~~~ HuggingFace ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_valid_huggingface_key():
    assert len(re.findall(HUGGINGFACE_KEY_PATTERN, "hf_" + "a" * 34)) == 1


# ~~~ Cloudflare ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_valid_cloudflare_token():
    assert len(re.findall(CLOUDFLARE_TOKEN_PATTERN, "cfk_" + "a" * 40 + "01234567")) == 1
    assert len(re.findall(CLOUDFLARE_TOKEN_PATTERN, "cfut_" + "a" * 40 + "abcdef")) == 1
    assert len(re.findall(CLOUDFLARE_TOKEN_PATTERN, "cfat_" + "a" * 40 + "89abcdef")) == 1
    assert len(re.findall(CLOUDFLARE_TOKEN_PATTERN, "cft_" + "a" * 40 + "012345")) == 1
    # Token body may contain underscores and hyphens
    assert len(re.findall(CLOUDFLARE_TOKEN_PATTERN, "cfk_" + "a_b-c" * 10 + "01234567")) == 1


# ~~~ Replicate ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_valid_replicate_token():
    assert len(re.findall(REPLICATE_API_TOKEN_PATTERN, "r8_" + "a" * 37)) == 1
    assert len(re.findall(REPLICATE_API_TOKEN_PATTERN, "r8_" + "a" * 38)) == 1
    assert len(re.findall(REPLICATE_API_TOKEN_PATTERN, "r8_" + "a" * 40)) == 1
    assert len(re.findall(REPLICATE_API_TOKEN_PATTERN, "r8_" + "a" * 36)) == 0
    assert len(re.findall(REPLICATE_API_TOKEN_PATTERN, "r8_" + "a" * 41)) == 0


# ~~~ Groq ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_valid_groq_key():
    assert len(re.findall(GROQ_API_KEY_PATTERN, "gsk_" + "a" * 30)) == 1
    assert len(re.findall(GROQ_API_KEY_PATTERN, "gsk_short")) == 0


# ~~~ OpenRouter ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_valid_openrouter_key():
    assert len(re.findall(OPENROUTER_API_KEY_PATTERN, "sk-or-" + "a" * 40)) == 1
    assert len(re.findall(OPENROUTER_API_KEY_PATTERN, "sk-or-short")) == 0


# ~~~ Together AI ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_valid_together_key():
    assert len(re.findall(TOGETHER_API_KEY_PATTERN, "together_" + "a" * 30)) == 1
    assert len(re.findall(TOGETHER_API_KEY_PATTERN, "together_" + "a-b-c-d" * 8 + "ab")) == 1
    assert len(re.findall(TOGETHER_API_KEY_PATTERN, "together_short")) == 0


# ~~~ Mistral AI ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_valid_mistral_key():
    assert len(re.findall(MISTRAL_API_KEY_PATTERN, "mist_" + "a" * 30)) == 1
    assert len(re.findall(MISTRAL_API_KEY_PATTERN, "mist_" + "a-b-c-d" * 8 + "ab")) == 1
    assert len(re.findall(MISTRAL_API_KEY_PATTERN, "mist_short")) == 0


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
