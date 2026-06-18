"""Pattern matching tests — all 14 provider regex patterns."""

import re

from auditor import (
    ANTHROPIC_KEY_PATTERN,
    OPENAI_KEY_PATTERN,
    GOOGLE_AI_KEY_PATTERN,
    AWS_ACCESS_KEY_PATTERN,
    GITHUB_TOKEN_PATTERN,
    SLACK_TOKEN_PATTERN,
    HUGGINGFACE_KEY_PATTERN,
    CLOUDFLARE_TOKEN_PATTERN,
    AZURE_CONNECTION_STRING_PATTERN,
    REPLICATE_API_TOKEN_PATTERN,
    GROQ_API_KEY_PATTERN,
    OPENROUTER_API_KEY_PATTERN,
    TOGETHER_API_KEY_PATTERN,
    MISTRAL_API_KEY_PATTERN,
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
    proj = "sk-proj-" + "a" * 30 + "T3BlbkFJ" + "b" * 30
    svcacct = "sk-svcacct-" + "a" * 30 + "T3BlbkFJ" + "b" * 30
    admin = "sk-admin-" + "a" * 30 + "T3BlbkFJ" + "b" * 30
    assert len(re.findall(OPENAI_KEY_PATTERN, classic)) == 1
    assert len(re.findall(OPENAI_KEY_PATTERN, proj)) == 1
    assert len(re.findall(OPENAI_KEY_PATTERN, svcacct)) == 1
    assert len(re.findall(OPENAI_KEY_PATTERN, admin)) == 1


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


# ~~~ Replicate ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_valid_replicate_token():
    assert len(re.findall(REPLICATE_API_TOKEN_PATTERN, "r8_" + "a" * 32)) == 1
    assert len(re.findall(REPLICATE_API_TOKEN_PATTERN, "r8_" + "a" * 31)) == 0


# ~~~ Groq ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_valid_groq_key():
    assert len(re.findall(GROQ_API_KEY_PATTERN, "gsk_" + "a" * 30)) == 1
    assert len(re.findall(GROQ_API_KEY_PATTERN, "gsk_short") ) == 0


# ~~~ OpenRouter ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_valid_openrouter_key():
    assert len(re.findall(OPENROUTER_API_KEY_PATTERN, "sk-or-" + "a" * 40)) == 1
    assert len(re.findall(OPENROUTER_API_KEY_PATTERN, "sk-or-short")) == 0


# ~~~ Together AI ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_valid_together_key():
    assert len(re.findall(TOGETHER_API_KEY_PATTERN, "together_" + "a" * 30)) == 1
    assert len(re.findall(TOGETHER_API_KEY_PATTERN, "together_short")) == 0


# ~~~ Mistral AI ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_valid_mistral_key():
    assert len(re.findall(MISTRAL_API_KEY_PATTERN, "mist_" + "a" * 30)) == 1
    assert len(re.findall(MISTRAL_API_KEY_PATTERN, "mist_short")) == 0


# ~~~ Azure ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_valid_azure_connection_string():
    key = "Endpoint=sb://my-namespace.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=ABCDEF12345+/="
    assert len(re.findall(AZURE_CONNECTION_STRING_PATTERN, key)) == 1
