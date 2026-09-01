"""CredsClaw — scan for leaked secrets across GitHub, git, and local files."""

import logging

# ---------------------------------------------------------------------------
# Logging setup (console only; file handler is added by main())
# ---------------------------------------------------------------------------
logger = logging.getLogger("auditor")
logger.setLevel(logging.INFO)

if not logger.handlers:
    _console = logging.StreamHandler()
    _console.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(_console)

# ---------------------------------------------------------------------------
# Re-export key symbols for backward compatibility
# ---------------------------------------------------------------------------
from auditor.cli import (
    build_arg_parser,
    generate_pre_commit_config,
    get_github_token,
    parse_args,
    parse_csv_arg,
)
from auditor.config import (
    CONFIG_ARG_MAP,
    DEFAULT_CONFIG_FILE,
    PLURAL_LIST_KEYS,
    apply_config_to_parser,
    load_config,
)
from auditor.exporter import (
    _severity_to_sarif_level,
    export_html_results,
    export_results,
    export_sarif_results,
    print_summary,
)
from auditor.patterns import (
    ANTHROPIC_KEY_PATTERN,
    AWS_ACCESS_KEY_PATTERN,
    AZURE_CONNECTION_STRING_PATTERN,
    CLOUDFLARE_TOKEN_PATTERN,
    DEFAULT_CHECKPOINT_INTERVAL,
    DEFAULT_CONFIDENCE_THRESHOLD,
    DEFAULT_MAX_CONCURRENCY,
    DEFAULT_VALIDATION_TIMEOUT,
    GITHUB_TOKEN_PATTERN,
    GOOGLE_AI_KEY_PATTERN,
    GROQ_API_KEY_PATTERN,
    HUGGINGFACE_KEY_PATTERN,
    MISTRAL_API_KEY_PATTERN,
    NOISE_SUBSTRINGS,
    OPENAI_KEY_PATTERN,
    OPENROUTER_API_KEY_PATTERN,
    PROVIDER_CONFIGS,
    REPLICATE_API_TOKEN_PATTERN,
    SLACK_TOKEN_PATTERN,
    TOGETHER_API_KEY_PATTERN,
    VALIDATABLE_PROVIDERS,
)
from auditor.rate_limiter import RateLimiter
from auditor.scanner import APIAuditor
from auditor.scoring import (
    calculate_char_diversity,
    calculate_confidence_score,
    fingerprint_key,
    get_severity_level,
    mask_key,
    shannon_entropy,
)
from auditor.tracker import ProgressTracker
from auditor.utils import parse_iso8601, safe_utc_now
from auditor.validator import VALIDATION_MAP, create_validator_session

__all__ = [
    # patterns
    "ANTHROPIC_KEY_PATTERN",
    "OPENAI_KEY_PATTERN",
    "GOOGLE_AI_KEY_PATTERN",
    "AWS_ACCESS_KEY_PATTERN",
    "GITHUB_TOKEN_PATTERN",
    "SLACK_TOKEN_PATTERN",
    "HUGGINGFACE_KEY_PATTERN",
    "CLOUDFLARE_TOKEN_PATTERN",
    "AZURE_CONNECTION_STRING_PATTERN",
    "REPLICATE_API_TOKEN_PATTERN",
    "GROQ_API_KEY_PATTERN",
    "OPENROUTER_API_KEY_PATTERN",
    "TOGETHER_API_KEY_PATTERN",
    "MISTRAL_API_KEY_PATTERN",
    "NOISE_SUBSTRINGS",
    "PROVIDER_CONFIGS",
    "VALIDATABLE_PROVIDERS",
    "DEFAULT_VALIDATION_TIMEOUT",
    "DEFAULT_MAX_CONCURRENCY",
    "DEFAULT_CHECKPOINT_INTERVAL",
    "DEFAULT_CONFIDENCE_THRESHOLD",
    # utils
    "parse_iso8601",
    "safe_utc_now",
    # scoring
    "shannon_entropy",
    "calculate_char_diversity",
    "calculate_confidence_score",
    "get_severity_level",
    "mask_key",
    "fingerprint_key",
    # config
    "DEFAULT_CONFIG_FILE",
    "CONFIG_ARG_MAP",
    "PLURAL_LIST_KEYS",
    "load_config",
    "apply_config_to_parser",
    # cli
    "parse_csv_arg",
    "get_github_token",
    "build_arg_parser",
    "parse_args",
    "generate_pre_commit_config",
    # tracker / rate_limiter / validator / scanner / exporter
    "ProgressTracker",
    "RateLimiter",
    "VALIDATION_MAP",
    "create_validator_session",
    "APIAuditor",
    "export_results",
    "export_html_results",
    "export_sarif_results",
    "_severity_to_sarif_level",
    "print_summary",
]
