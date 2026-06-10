"""CLI argument parsing, config merge, and pre-commit hook generation."""

import argparse
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from auditor.config import DEFAULT_CONFIG_FILE, apply_config_to_parser, load_config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pre-commit hook
# ---------------------------------------------------------------------------
PRE_COMMIT_HOOK_TEMPLATE = """\
repos:
  - repo: local
    hooks:
      - id: api-key-auditor
        name: Exposed API Key Auditor
        description: Scans staged files for exposed API keys and secrets
        entry: python -m auditor --mode local --dir . --confidence-threshold 60.0 --dry-run
        language: system
        types: [text]
        pass_filenames: false
"""


def generate_pre_commit_config(path: str = ".pre-commit-config.yaml") -> str:
    """Write a .pre-commit-config.yaml hook file and return its path."""
    out = Path(path)
    out.write_text(PRE_COMMIT_HOOK_TEMPLATE, encoding="utf-8")
    logger.info("Pre-commit hook config written to %s", out.resolve())
    return str(out.resolve())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def parse_csv_arg(value: str) -> List[str]:
    """Split a comma-separated string into a trimmed list."""
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def get_github_token() -> str:
    """Read GITHUB_TOKEN from env or prompt the user."""
    token = os.getenv("GITHUB_TOKEN")
    if token:
        return token
    return input("Enter your GitHub token: ").strip()


# ---------------------------------------------------------------------------
# Argparse
# ---------------------------------------------------------------------------
DEFAULT_CONFIG_FILE_SHORT = DEFAULT_CONFIG_FILE  # re-export for convenience


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the argument parser (exposed separately so config can inject defaults)."""
    parser = argparse.ArgumentParser(
        description="Exposed API Key Auditor - Scan GitHub or local directories for leaked secrets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  Basic GitHub code scan:
    python -m auditor --repo owner/repo --providers openai,github

  Local directory scan:
    python -m auditor --mode local --dir ./project --providers openai,aws

  Git history scan:
    python -m auditor --mode git-history --dir ./repo --providers github,slack

  Use config file:
    python -m auditor --config auditor.yaml

  Generate pre-commit hook:
    python -m auditor --generate-pre-commit-hook

  Generate HTML report:
    python -m auditor --output-format html --output-file report.html
""",
    )

    # Core
    parser.add_argument(
        "--config", type=str, default=DEFAULT_CONFIG_FILE,
        help=f"Config file path (default: {DEFAULT_CONFIG_FILE})",
    )
    parser.add_argument(
        "--repo", type=str, default="",
        help="Specific repository to search (format: owner/repo)",
    )
    parser.add_argument(
        "--extensions", type=str, default="",
        help="File extensions to search (comma-separated, e.g., py,js,env)",
    )
    parser.add_argument(
        "--dir", type=str,
        help="Local directory path to scan (for mode=local or git-history)",
    )
    parser.add_argument(
        "--mode", type=str, choices=["code", "commits", "local", "git-history"],
        default="code", help="Search mode: code, commits, local, or git-history",
    )
    parser.add_argument(
        "--validate", action="store_true",
        help="Validate found API keys against provider APIs",
    )
    parser.add_argument(
        "--output-format", type=str, choices=["json", "csv", "txt", "html"],
        default="json", help="Output format (json, csv, txt, html)",
    )
    parser.add_argument(
        "--output-file", type=str, default="",
        help="Output file path (default: audit_results.{format})",
    )

    # GitHub filters
    parser.add_argument("--max-pages", type=int, help="Maximum pages to fetch from GitHub API")
    parser.add_argument("--min-stars", type=int, help="Minimum stars for repositories")
    parser.add_argument("--language", type=str, help="Filter by programming language")
    parser.add_argument("--updated-after", type=str, help="Filter repos updated after date (YYYY-MM-DD)")
    parser.add_argument("--sort", type=str, choices=["indexed", ""], default="indexed", help="Sort mode")

    # Checkpoint / resume
    parser.add_argument("--resume", action="store_true", help="Continue from previous checkpoint")
    parser.add_argument("--checkpoint-file", type=str, default="output/progress.json", help="Checkpoint file path")
    parser.add_argument("--since-checkpoint", action="store_true", help="Only process items newer than checkpoint timestamp")

    # Performance
    parser.add_argument(
        "--max-concurrency", type=int, default=10,
        help="Max concurrent item processors",
    )
    parser.add_argument(
        "--checkpoint-interval", type=int, default=25,
        help="Save checkpoint every N processed items",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Search only; do not fetch contents or export findings",
    )
    parser.add_argument(
        "--timeout", type=int, default=10,
        help="Validation request timeout in seconds",
    )

    # Providers & confidence
    parser.add_argument(
        "--providers", type=str, default="openai,anthropic",
        help="Providers (comma-separated): openai,anthropic,google,aws,stripe,github,slack,twilio,sendgrid,huggingface,cloudflare,supabase,azure",
    )
    parser.add_argument(
        "--confidence-threshold", type=float, default=50.0,
        help="Minimum confidence score (0-100) to report a key",
    )

    # Filtering
    parser.add_argument("--allow-patterns", type=str, default="", help="Comma-separated regex allow patterns")
    parser.add_argument("--deny-patterns", type=str, default="", help="Comma-separated regex deny patterns")

    # Security
    parser.add_argument("--store-raw-keys", action="store_true", help="Store raw keys in checkpoint and output (unsafe)")
    parser.add_argument("--encrypt-output", action="store_true", help="Encrypt output file using Fernet key")
    parser.add_argument("--encryption-key", type=str, default="", help="Fernet key (or use OUTPUT_ENCRYPTION_KEY env var)")

    # Utility
    parser.add_argument("--generate-pre-commit-hook", action="store_true", help="Generate a .pre-commit-config.yaml file")

    return parser


def parse_args(argv: Optional[List[str]] = None, config: Optional[dict] = None) -> argparse.Namespace:
    """Parse CLI arguments, optionally overlaying values from a YAML config (CLI always wins)."""
    parser = build_arg_parser()

    # Apply config file defaults first (CLI args will override later during parse)
    if config:
        apply_config_to_parser(config, parser)

    args = parser.parse_args(argv)

    # Derive default output filename from format if not provided
    if not args.output_file:
        fmt_to_ext = {"json": "json", "csv": "csv", "txt": "txt", "html": "html"}
        ext = fmt_to_ext.get(args.output_format, "json")
        args.output_file = f"output/audit_results.{ext}"

    return args
