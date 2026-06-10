"""Pattern matching tests — all 13 provider regex patterns."""

import re

from auditor import (
    ANTHROPIC_KEY_PATTERN,
    OPENAI_KEY_PATTERN,
    GOOGLE_AI_KEY_PATTERN,
    AWS_ACCESS_KEY_PATTERN,
    STRIPE_KEY_PATTERN,
    GITHUB_TOKEN_PATTERN,
    SLACK_TOKEN_PATTERN,
    TWILIO_API_KEY_PATTERN,
    SENDGRID_API_KEY_PATTERN,
    HUGGINGFACE_KEY_PATTERN,
    CLOUDFLARE_TOKEN_PATTERN,
    SUPABASE_KEY_PATTERN,
    AZURE_CONNECTION_STRING_PATTERN,
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


# ~~~ Stripe ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_valid_stripe_key():
    live_key = "sk_" + "live_abcdefghijklmnopqrstuvwxyz"
    test_key = "sk_" + "test_1234567890abcdefghijklmn"
    assert len(re.findall(STRIPE_KEY_PATTERN, live_key)) == 1
    assert len(re.findall(STRIPE_KEY_PATTERN, test_key)) == 1


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


# ~~~ Twilio ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_valid_twilio_key():
    assert len(re.findall(TWILIO_API_KEY_PATTERN, "SK" + "a" * 32)) == 1


# ~~~ SendGrid ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_valid_sendgrid_key():
    assert len(re.findall(SENDGRID_API_KEY_PATTERN, "SG." + "a" * 22 + "." + "b" * 43)) == 1


# ~~~ HuggingFace ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_valid_huggingface_key():
    assert len(re.findall(HUGGINGFACE_KEY_PATTERN, "hf_" + "a" * 34)) == 1


# ~~~ Cloudflare ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_valid_cloudflare_token():
    assert len(re.findall(CLOUDFLARE_TOKEN_PATTERN, "cfk_" + "a" * 40 + "01234567")) == 1


# ~~~ Supabase ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_valid_supabase_key():
    assert len(re.findall(SUPABASE_KEY_PATTERN, "sbp_" + "b" * 36)) == 1
    assert len(re.findall(SUPABASE_KEY_PATTERN, "sb_secret_" + "b" * 36)) == 1


# ~~~ Azure ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_valid_azure_connection_string():
    key = "Endpoint=sb://my-namespace.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=ABCDEF12345+/="
    assert len(re.findall(AZURE_CONNECTION_STRING_PATTERN, key)) == 1
