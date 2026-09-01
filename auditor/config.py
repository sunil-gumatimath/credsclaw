"""YAML config-file loading and merging with argparse."""

import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_FILE = "auditor.yaml"

CONFIG_ARG_MAP: dict[str, str] = {
    "repo": "repo",
    "dir": "dir",
    "mode": "mode",
    "providers": "providers",
    "validate": "validate",
    "output_format": "output_format",
    "output_file": "output_file",
    "extensions": "extensions",
    "max_concurrency": "max_concurrency",
    "confidence_threshold": "confidence_threshold",
    "checkpoint_interval": "checkpoint_interval",
    "checkpoint_file": "checkpoint_file",
    "max_pages": "max_pages",
    "min_stars": "min_stars",
    "language": "language",
    "updated_after": "updated_after",
    "allow_patterns": "allow_patterns",
    "deny_patterns": "deny_patterns",
    "store_raw_keys": "store_raw_keys",
    "encrypt_output": "encrypt_output",
    "encryption_key": "encryption_key",
    "timeout": "timeout",
    "recent_repos_days": "recent_repos_days",
    "sort": "sort",
    "dry_run": "dry_run",
    "resume": "resume",
    "since_checkpoint": "since_checkpoint",
    "no_ssl_verify": "no_ssl_verify",
}

PLURAL_LIST_KEYS: frozenset = frozenset(
    {
        "providers",
        "allow_patterns",
        "deny_patterns",
        "extensions",
    }
)


def load_config(filepath: str) -> dict:
    """Load configuration from a YAML file. Returns {} on failure."""
    path = Path(filepath)
    if not path.exists():
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            config = yaml.safe_load(f)
        if not isinstance(config, dict):
            logger.warning("Config file has no valid top-level mapping: %s", filepath)
            return {}
        logger.info("Loaded config from %s", filepath)
        return config
    except Exception as exc:
        logger.error("Failed to load config %s: %s", filepath, exc)
        return {}


def apply_config_to_parser(config: dict, parser) -> None:
    """Merge YAML config values into argparse as defaults.

    CLI flags take precedence because argparse applies the user's
    explicit values *after* the defaults set here.
    """
    # Warn on unknown keys
    for k in config:
        if k not in CONFIG_ARG_MAP:
            logger.warning("Unknown config key '%s' ignored", k)

    for config_key, arg_dest in CONFIG_ARG_MAP.items():
        if config_key not in config:
            continue
        value = config[config_key]

        # Normalise list-in-YAML keys to comma-separated strings
        # so they match the argparse ``type=str`` storage.
        if config_key in PLURAL_LIST_KEYS and isinstance(value, list):
            value = ",".join(str(v) for v in value)

        # Type coercion for numeric fields
        if config_key in ("max_concurrency", "checkpoint_interval", "max_pages", "min_stars", "recent_repos_days", "timeout"):
            try:
                value = int(value)  # type: ignore[assignment]
            except (ValueError, TypeError):
                logger.error("Invalid integer for %s: %r", config_key, value)
                continue
        if config_key == "confidence_threshold":
            try:
                value = float(value)  # type: ignore[assignment]
            except (ValueError, TypeError):
                logger.error("Invalid float for %s: %r", config_key, value)
                continue

        parser.set_defaults(**{arg_dest: value})
