"""Regex patterns for detecting API keys and secrets across 14 providers.

Key formats verified against vendor documentation, October 2026:

* **OpenAI** — ``sk-proj-``/``sk-svcacct-``/``sk-admin-`` keys carry a
  ``T3BlbkFJ`` marker mid-string and run ~155 characters, so the tail is
  bounded generously rather than at the old 80.
* **Anthropic** — ``sk-ant-api03-``/``sk-ant-oat01-`` plus admin/auth forms.
* **GitHub** — classic ``ghp_``/``gho_``/``ghs_``/``ghr_``/``ghu_`` and
  fine-grained ``github_pat_<id>_<secret>``.
* **Slack** — classic ``xoxb``/``xoxp``/``xoxr`` three-field tokens, app-level
  ``xoxa-<app>-<team>-<app>-<secret>`` tokens, and ``xapp-``/``xwfp-`` app
  tokens and ``hooks.slack.com`` webhooks.
* **Cloudflare** — 2026 scannable prefixes ``cfk_``/``cfut_``/``cfat_``
  (40-char body + checksum).
* **Google** — ``AIza`` API keys and ``ya29.`` OAuth access tokens.
* **AWS** — the 11 documented access-key-id prefixes, each + 16 uppercase
  alphanumerics.
* **Azure** — storage / Service Bus connection strings.
* **HuggingFace** — ``hf_`` user access tokens.
* **Replicate** ``r8_``, **Groq** ``gsk_``, **OpenRouter** ``sk-or-``,
  **Together AI** ``together_``, **Mistral** ``mist_``.
"""

import re

# ---------------------------------------------------------------------------
# Provider key patterns (updated June 2026 — audit hardened; Sep 2026 — search-query coverage, noise list, GitHub/Azure bounds)
# ---------------------------------------------------------------------------
ANTHROPIC_KEY_PATTERN = (
    r"\bsk-ant-(?:api\d{2}|oat\d{2}|admin|auth\d{2}|[A-Za-z0-9_-]+)-[A-Za-z0-9_-]{40,}\b"
)
OPENAI_KEY_PATTERN = (
    # The legacy branch excludes sk-ant-* so Anthropic keys are not also
    # reported as OpenAI findings (they satisfy the bare sk- length window).
    r"\b(?:sk-(?:proj|svcacct|admin|svc|session)-[A-Za-z0-9_-]{20,120}T3BlbkFJ"
    r"[A-Za-z0-9_-]{20,120}|sk-(?!ant-)[A-Za-z0-9_-]{48,51})\b"
)
GOOGLE_AI_KEY_PATTERN = (
    r"\b(?:AIza[A-Za-z0-9_-]{35}|AQ\.[A-Za-z0-9_-]{35,}|ya29\.[A-Za-z0-9._\-/]{30,})\b"
)
AWS_ACCESS_KEY_PATTERN = (
    r"\b(?:AKIA|ASIA|ABIA|ACCA|APKA|AIDA|AROA|AIPA|ANPA|AGPA|ASCA)[0-9A-Z]{16}\b"
)
GITHUB_TOKEN_PATTERN = (
    r"\b(?:ghp_[0-9a-zA-Z]{36,40}|gho_[0-9a-zA-Z]{36}|ghs_[0-9a-zA-Z]{36,76}|"
    r"ghr_[0-9a-zA-Z]{36}|ghu_[0-9a-zA-Z]{36}|"
    # Fine-grained PAT: documented as github_pat_ + 22 + "_" + 59, but the
    # trailing secret length is not contractual and has grown over time, so
    # accept 59+ instead of pinning an exact width.
    r"github_pat_[0-9a-zA-Z]{22,30}_[0-9a-zA-Z]{59,100})\b"
)
SLACK_TOKEN_PATTERN = (
    # Classic workspace/user tokens: xoxb-/xoxp-/xoxa-/xoxr-/xoxs-/<etc>
    # in the  field-field-field shape.
    r"\b(?:xox[baprsoecde]-[0-9]{9,13}-[0-9]{9,13}-[0-9a-zA-Z]{24,}|"
    # App-level (xoxa-) tokens have an integer app id in the second field:
    #   xoxa-2-<team>-<app>-<secret>
    r"xoxa-[0-9]{1,3}-[0-9A-Za-z-]{8,}-[0-9A-Za-z-]{8,}-[0-9a-zA-Z]{24,}|"
    # Loosely-shaped fallback so a token that skips the numeric fields is
    # still surfaced for manual review rather than silently dropped.
    r"xox[abeoprsu]-[0-9A-Za-z-]{20,}|"
    r"xapp-[0-9a-zA-Z-]{24,}|xwfp-[0-9a-zA-Z-]{24,}|"
    r"hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+)\b"
)
HUGGINGFACE_KEY_PATTERN = r"\bhf_[A-Za-z0-9]{34,64}\b"
# Cloudflare's scannable token format (2026-04): a 40-character body plus a
# trailing checksum, behind one of four prefixes. Legacy unprefixed tokens
# (37-45 hex chars / 40 alphanumerics) are intentionally not matched: they are
# indistinguishable from ordinary hashes and would flood results with noise.
CLOUDFLARE_TOKEN_PATTERN = r"\b(?:cfk_|cfut_|cfat_|cft_)[A-Za-z0-9_-]{30,50}[A-Fa-f0-9]{6,16}\b"
AZURE_CONNECTION_STRING_PATTERN = (
    r"(?i)(?:Endpoint=sb://[^;]+;SharedAccessKeyName=[^;]+;"
    r"SharedAccessKey=[A-Za-z0-9+/]{32,}={0,2}(?=[^A-Za-z0-9+/=]|$)|"
    r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;"
    r"AccountKey=[A-Za-z0-9+/]{32,}={0,2}(?=[^A-Za-z0-9+/=]|$))"
)
REPLICATE_API_TOKEN_PATTERN = r"\br8_[A-Za-z0-9]{37,40}\b"
GROQ_API_KEY_PATTERN = r"\bgsk_[A-Za-z0-9_-]{30,64}\b"
OPENROUTER_API_KEY_PATTERN = r"\bsk-or-[A-Za-z0-9_-]{30,70}\b"
TOGETHER_API_KEY_PATTERN = r"\btogether_[A-Za-z0-9_-]{30,64}\b"
MISTRAL_API_KEY_PATTERN = r"\bmist_[A-Za-z0-9_-]{30,64}\b"

# ---------------------------------------------------------------------------
# Noise / placeholder detection
# ---------------------------------------------------------------------------
NOISE_SUBSTRINGS = frozenset(
    {
        "example",
        "dummy",
        "sample",
        "placeholder",
        "changeme",
        "your_key",
        "your-api-key",
        "your_api_key",
        "fake",
        "mock",
        "testtest",
        "sk-test",
        "test_key",
        "test-key",
        "testkey",
        "redacted",
        "revoked",
        "censored",
        "masked",
    }
)

# Redaction markers that are only noise when they *dominate* the value.
# These are checked separately: a bare "xxx" or "xxxxx" collides with real
# high-entropy keys by chance (measured: ~1 in 2000 random 20-char AWS-style
# keys contained "xxx"), whereas an all-x placeholder is unambiguous.
REDACTION_MARKER_PATTERNS = (
    re.compile(r"^x+$"),  # xxx, xxxxxxx - entirely redacted
    re.compile(r"^[*•●]+$"),  # ****, ****
    re.compile(r"(?:x{4,}|[*•●]{4,})", re.IGNORECASE),
)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_VALIDATION_TIMEOUT = 10
DEFAULT_MAX_CONCURRENCY = 10
DEFAULT_CHECKPOINT_INTERVAL = 25
DEFAULT_CONFIDENCE_THRESHOLD = 50.0

# ---------------------------------------------------------------------------
# Provider registry  (name_key -> (display_name, search_prefix, pattern))
# ---------------------------------------------------------------------------
PROVIDER_CONFIGS = {
    "anthropic": ("Anthropic", "sk-ant-", ANTHROPIC_KEY_PATTERN),
    "openai": ("OpenAI", "sk-", OPENAI_KEY_PATTERN),
    "google": ("Google", "AIza OR ya29", GOOGLE_AI_KEY_PATTERN),
    "aws": (
        "AWS",
        "AKIA OR ASIA OR ABIA OR ACCA OR APKA OR AIDA OR AROA OR AIPA OR ANPA OR AGPA OR ASCA",
        AWS_ACCESS_KEY_PATTERN,
    ),
    "github": (
        "GitHub",
        "ghp_ OR github_pat_ OR gho_ OR ghs_ OR ghr_ OR ghu_",
        GITHUB_TOKEN_PATTERN,
    ),
    "slack": (
        "Slack",
        "xox- OR xoxb- OR xoxp- OR xoxa- OR xoxr- OR xapp- OR xwfp- OR hooks.slack.com",
        SLACK_TOKEN_PATTERN,
    ),
    "huggingface": ("HuggingFace", "hf_", HUGGINGFACE_KEY_PATTERN),
    "cloudflare": ("Cloudflare", "cfk_ OR cfut_ OR cfat_ OR cft_", CLOUDFLARE_TOKEN_PATTERN),
    "azure": ("Azure", "Endpoint=sb OR DefaultEndpointsProtocol", AZURE_CONNECTION_STRING_PATTERN),
    "replicate": ("Replicate", "r8_", REPLICATE_API_TOKEN_PATTERN),
    "groq": ("Groq", "gsk_", GROQ_API_KEY_PATTERN),
    "openrouter": ("OpenRouter", "sk-or-", OPENROUTER_API_KEY_PATTERN),
    "together": ("Together AI", "together_", TOGETHER_API_KEY_PATTERN),
    "mistral": ("Mistral AI", "mist_", MISTRAL_API_KEY_PATTERN),
}

# Provider names that support live validation
VALIDATABLE_PROVIDERS = frozenset(
    {
        "OpenAI",
        "Anthropic",
        "GitHub",
        "Slack",
        "HuggingFace",
        "Cloudflare",
        "Replicate",
        "Groq",
        "OpenRouter",
        "Together AI",
        "Mistral AI",
    }
)
