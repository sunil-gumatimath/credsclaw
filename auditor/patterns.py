"""Regex patterns for detecting API keys and secrets across 13 providers."""

# ---------------------------------------------------------------------------
# Provider key patterns (updated June 2026)
# ---------------------------------------------------------------------------
ANTHROPIC_KEY_PATTERN = (
    r"\bsk-ant-(?:api0[1-3]|oat01|admin)-[A-Za-z0-9_-]{40,}\b"
)
OPENAI_KEY_PATTERN = (
    r"\b(?:sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,100}T3BlbkFJ"
    r"[A-Za-z0-9_-]{20,100}|sk-[A-Za-z0-9]{48})\b"
)
GOOGLE_AI_KEY_PATTERN = r"\b(?:AIza[A-Za-z0-9_-]{35}|AQ\.[A-Za-z0-9_-]{35,})\b"
AWS_ACCESS_KEY_PATTERN = r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16,}\b"
STRIPE_KEY_PATTERN = (
    r"\b(?:pk_(?:live|test)_[0-9a-zA-Z]{24,}|sk_(?:live|test)_[0-9a-zA-Z]{24,}|"
    r"rk_(?:live|test)_[0-9a-zA-Z]{24,}|whsec_[0-9a-zA-Z]{48,})\b"
)
GITHUB_TOKEN_PATTERN = (
    r"\b(?:ghp_[0-9a-zA-Z]{36,40}|gho_[0-9a-zA-Z]{36}|ghs_[0-9a-zA-Z]{36,200}|"
    r"ghr_[0-9a-zA-Z]{36}|ghu_[0-9a-zA-Z]{36}|"
    r"github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59})\b"
)
SLACK_TOKEN_PATTERN = (
    r"\b(?:xox[baprsoe]-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,}|"
    r"xapp-[0-9a-zA-Z-]{24,}|xwfp-[0-9a-zA-Z-]{24,}|"
    r"hooks\.slack\.com/services/[A-Za-z0-9/]+?)\b"
)
TWILIO_API_KEY_PATTERN = r"\b(?:SK[0-9a-fA-F]{32}|AC[0-9a-fA-F]{32})\b"
SENDGRID_API_KEY_PATTERN = r"\bSG\.[0-9a-zA-Z\.\-_]{22}\.[0-9a-zA-Z\.\-_]{43}\b"
HUGGINGFACE_KEY_PATTERN = r"\bhf_[a-zA-Z0-9]{34}\b"
CLOUDFLARE_TOKEN_PATTERN = r"\b(?:cfk_|cfut_|cfat_)[A-Za-z0-9]{40}[0-9a-f]{8}\b"
SUPABASE_KEY_PATTERN = (
    r"\b(?:sb_publishable_[A-Za-z0-9]{22}_[0-9a-f]{8}|"
    r"sb_secret_[A-Za-z0-9]{22}_[0-9a-f]{8}|"
    r"sbp_[a-zA-Z0-9]{36}|sb_secret_[a-zA-Z0-9]{36})\b"
)
AZURE_CONNECTION_STRING_PATTERN = (
    r"Endpoint=sb://[^;]+;SharedAccessKeyName=[^;]+;"
    r"SharedAccessKey=[A-Za-z0-9+/=]+"
)

# ---------------------------------------------------------------------------
# Noise / placeholder detection
# ---------------------------------------------------------------------------
NOISE_SUBSTRINGS = frozenset({
    "example",
    "dummy",
    "sample",
    "placeholder",
    "changeme",
    "your_key",
    "your-api-key",
    "fake",
    "mock",
    "testtest",
    "xxxxx",
})

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
    "anthropic":   ("Anthropic",   "sk-ant-",      ANTHROPIC_KEY_PATTERN),
    "openai":      ("OpenAI",      "sk-",          OPENAI_KEY_PATTERN),
    "google":      ("Google",      "AIza",         GOOGLE_AI_KEY_PATTERN),
    "aws":         ("AWS",         "AKIA",         AWS_ACCESS_KEY_PATTERN),
    "stripe":      ("Stripe",      "sk_",          STRIPE_KEY_PATTERN),
    "github":      ("GitHub",      "ghp_",         GITHUB_TOKEN_PATTERN),
    "slack":       ("Slack",       "xoxb-",        SLACK_TOKEN_PATTERN),
    "twilio":      ("Twilio",      "SK",           TWILIO_API_KEY_PATTERN),
    "sendgrid":    ("SendGrid",    "SG.",          SENDGRID_API_KEY_PATTERN),
    "huggingface": ("HuggingFace", "hf_",          HUGGINGFACE_KEY_PATTERN),
    "cloudflare":  ("Cloudflare",  "cfk_",         CLOUDFLARE_TOKEN_PATTERN),
    "supabase":    ("Supabase",    "sbp_",         SUPABASE_KEY_PATTERN),
    "azure":       ("Azure",       "Endpoint=sb",  AZURE_CONNECTION_STRING_PATTERN),
}

# Provider names that support live validation
VALIDATABLE_PROVIDERS = frozenset({
    "OpenAI", "Anthropic", "Stripe", "GitHub", "Slack",
    "SendGrid", "HuggingFace", "Cloudflare", "Supabase",
})
