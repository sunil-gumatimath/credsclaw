"""CredsClaw — scan for leaked secrets across GitHub, git, and local files."""

import logging
import os

# ---------------------------------------------------------------------------
# Logging setup (console only; file handler is added by main())
# ---------------------------------------------------------------------------
logger = logging.getLogger("auditor")
logger.setLevel(logging.INFO)

if not logger.handlers:
    _console = logging.StreamHandler()
    _console.setFormatter(
        logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    )
    logger.addHandler(_console)

# ---------------------------------------------------------------------------
# Re-export key symbols for backward compatibility
# ---------------------------------------------------------------------------
from auditor.patterns import (
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
    NOISE_SUBSTRINGS,
    PROVIDER_CONFIGS,
    VALIDATABLE_PROVIDERS,
    DEFAULT_VALIDATION_TIMEOUT,
    DEFAULT_MAX_CONCURRENCY,
    DEFAULT_CHECKPOINT_INTERVAL,
    DEFAULT_CONFIDENCE_THRESHOLD,
)

from auditor.utils import parse_iso8601, safe_utc_now

from auditor.scoring import (
    shannon_entropy,
    calculate_char_diversity,
    calculate_confidence_score,
    get_severity_level,
    mask_key,
    fingerprint_key,
)

from auditor.config import (
    DEFAULT_CONFIG_FILE,
    CONFIG_ARG_MAP,
    PLURAL_LIST_KEYS,
    load_config,
    apply_config_to_parser,
)

from auditor.cli import (
    parse_csv_arg,
    get_github_token,
    build_arg_parser,
    parse_args,
    generate_pre_commit_config,
)

from auditor.tracker import ProgressTracker

from auditor.rate_limiter import RateLimiter

from auditor.validator import VALIDATION_MAP

from auditor.scanner import APIAuditor

from auditor.exporter import export_results, export_html_results, print_summary

__all__ = [
    # patterns
    "ANTHROPIC_KEY_PATTERN", "OPENAI_KEY_PATTERN", "GOOGLE_AI_KEY_PATTERN",
    "AWS_ACCESS_KEY_PATTERN", "STRIPE_KEY_PATTERN", "GITHUB_TOKEN_PATTERN",
    "SLACK_TOKEN_PATTERN", "TWILIO_API_KEY_PATTERN", "SENDGRID_API_KEY_PATTERN",
    "HUGGINGFACE_KEY_PATTERN", "CLOUDFLARE_TOKEN_PATTERN", "SUPABASE_KEY_PATTERN",
    "AZURE_CONNECTION_STRING_PATTERN",
    "NOISE_SUBSTRINGS", "PROVIDER_CONFIGS", "VALIDATABLE_PROVIDERS",
    "DEFAULT_VALIDATION_TIMEOUT", "DEFAULT_MAX_CONCURRENCY",
    "DEFAULT_CHECKPOINT_INTERVAL", "DEFAULT_CONFIDENCE_THRESHOLD",
    # utils
    "parse_iso8601", "safe_utc_now",
    # scoring
    "shannon_entropy", "calculate_char_diversity", "calculate_confidence_score",
    "get_severity_level", "mask_key", "fingerprint_key",
    # config
    "DEFAULT_CONFIG_FILE", "CONFIG_ARG_MAP", "PLURAL_LIST_KEYS",
    "load_config", "apply_config_to_parser",
    # cli
    "parse_csv_arg", "get_github_token", "build_arg_parser", "parse_args",
    "generate_pre_commit_config",
    # tracker / rate_limiter / validator / scanner / exporter
    "ProgressTracker", "RateLimiter", "VALIDATION_MAP", "APIAuditor",
    "export_results", "export_html_results", "print_summary",
]
