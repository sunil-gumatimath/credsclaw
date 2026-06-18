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
      - id: credsclaw
        name: CredsClaw
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
        description="CredsClaw - Scan GitHub or local directories for leaked secrets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  Basic GitHub code scan:
    python -m auditor --repo owner/repo --providers openai,github

  Discover & scan recent repos:
    python -m auditor --recent-repos-days 7 --providers all

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

    # ── Core ──────────────────────────────────────────────────────────
    core = parser.add_argument_group("Core")
    core.add_argument(
        "--mode", type=str, choices=["code", "commits", "local", "git-history"],
        default="code", help="Search mode: code, commits, local, or git-history",
    )
    core.add_argument(
        "--providers", type=str, default="openai,anthropic",
        help="Providers (comma-separated): openai,anthropic,google,aws,github,slack,huggingface,cloudflare,azure,replicate,groq,openrouter,together,mistral",
    )
    core.add_argument(
        "--repo", type=str, default="",
        help="Specific repository to search (format: owner/repo)",
    )
    core.add_argument(
        "--dir", type=str,
        help="Local directory path to scan (for mode=local or git-history)",
    )
    core.add_argument(
        "--config", type=str, default=DEFAULT_CONFIG_FILE,
        help=f"Config file path (default: {DEFAULT_CONFIG_FILE})",
    )

    # ── GitHub Filters ────────────────────────────────────────────────
    gh = parser.add_argument_group("GitHub Filters")
    gh.add_argument(
        "--recent-repos-days", type=int, default=None,
        help="Discover repos pushed to in last N days (mode: code/commits, disables --repo/--dir)",
    )
    gh.add_argument("--max-pages", type=int, help="Maximum API pages to fetch")
    gh.add_argument("--min-stars", type=int, help="Minimum repository stars")
    gh.add_argument("--language", type=str, help="Filter by programming language")
    gh.add_argument("--updated-after", type=str, help="Only repos updated after date (YYYY-MM-DD)")
    gh.add_argument("--sort", type=str, choices=["indexed", ""], default="indexed", help="Sort mode (default: indexed)")
    gh.add_argument(
        "--extensions", type=str, default="",
        help="File extensions to search (comma-separated, e.g., py,js,env)",
    )

    # ── Performance & Checkpoint ──────────────────────────────────────
    perf = parser.add_argument_group("Performance & Checkpoint")
    perf.add_argument(
        "--max-concurrency", type=int, default=10,
        help="Max concurrent item processors",
    )
    perf.add_argument(
        "--dry-run", action="store_true",
        help="Search only; do not fetch contents or export findings",
    )
    perf.add_argument("--resume", action="store_true", help="Continue from previous checkpoint")
    perf.add_argument("--checkpoint-file", type=str, default="output/progress.json", help="Checkpoint file path")
    perf.add_argument("--since-checkpoint", action="store_true", help="Only process items newer than checkpoint timestamp")
    perf.add_argument(
        "--checkpoint-interval", type=int, default=25,
        help="Save checkpoint every N processed items",
    )
    perf.add_argument(
        "--timeout", type=int, default=10,
        help="Validation request timeout in seconds",
    )
    perf.add_argument(
        "--no-ssl-verify", action="store_true",
        help="Disable SSL certificate verification (use behind corporate proxies)",
    )

    # ── Output ────────────────────────────────────────────────────────
    out = parser.add_argument_group("Output")
    out.add_argument(
        "--output-format", type=str, choices=["json", "csv", "txt", "html"],
        default="json", help="Output format (json, csv, txt, html)",
    )
    out.add_argument(
        "--output-file", type=str, default="",
        help="Output file path (default: audit_results.{format})",
    )
    out.add_argument("--validate", action="store_true", help="Validate found keys against provider APIs")

    # ── Security & Filtering ──────────────────────────────────────────
    sec = parser.add_argument_group("Security & Filtering")
    sec.add_argument("--store-raw-keys", action="store_true", help="Store raw keys in output (unsafe)")
    sec.add_argument("--encrypt-output", action="store_true", help="Encrypt output file using Fernet key")
    sec.add_argument("--encryption-key", type=str, default="", help="Fernet key (or use OUTPUT_ENCRYPTION_KEY env var)")
    sec.add_argument(
        "--confidence-threshold", type=float, default=50.0,
        help="Minimum confidence score (0-100) to report a key",
    )
    sec.add_argument("--allow-patterns", type=str, default="", help="Comma-separated regex allow patterns")
    sec.add_argument("--deny-patterns", type=str, default="", help="Comma-separated regex deny patterns")

    # ── Utility ───────────────────────────────────────────────────────
    util = parser.add_argument_group("Utility")
    util.add_argument("--generate-pre-commit-hook", action="store_true", help="Generate a .pre-commit-config.yaml file")

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

    # Validation
    if args.recent_repos_days is not None:
        if args.repo:
            parser.error("argument --recent-repos-days: not allowed with argument --repo")
        if args.dir:
            parser.error("argument --recent-repos-days: not allowed with argument --dir")
        if args.mode not in ("code", "commits"):
            parser.error("argument --recent-repos-days: only allowed with modes 'code' or 'commits'")

    if args.encryption_key:
        import warnings
        warnings.warn(
            "--encryption-key is deprecated and will be removed in a future release. "
            "Use the OUTPUT_ENCRYPTION_KEY environment variable instead.",
            DeprecationWarning,
            stacklevel=2,
        )

    return args
