"""CLI argument parser and pre-commit hook generation tests."""

import os
from pathlib import Path

from auditor import (
    build_arg_parser,
    parse_args,
    generate_pre_commit_config,
)


# ~~~ Pre-commit hook ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_generate_pre_commit_config(tmp_path):
    """generate_pre_commit_config should write a .pre-commit-config.yaml file."""
    out_path = str(tmp_path / ".pre-commit-config.yaml")
    result_path = generate_pre_commit_config(out_path)
    assert os.path.exists(out_path)
    content = Path(out_path).read_text(encoding="utf-8")
    assert "credsclaw" in content
    assert "python -m auditor" in content
    assert result_path == os.path.abspath(out_path)


# ~~~ Parser structure ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_build_arg_parser_has_new_flags():
    """build_arg_parser should include all the new CLI flags."""
    parser = build_arg_parser()
    actions = {a.dest for a in parser._actions if hasattr(a, "dest")}
    assert "config" in actions
    assert "generate_pre_commit_hook" in actions
    assert "mode" in actions
    assert "output_format" in actions
    assert "output_file" in actions
    assert "validate" in actions
    assert "confidence_threshold" in actions


def test_build_arg_parser_mode_choices():
    """--mode should accept git-history as a valid choice."""
    parser = build_arg_parser()
    for action in parser._actions:
        if hasattr(action, "dest") and action.dest == "mode":
            assert "git-history" in action.choices
            assert "local" in action.choices
            assert "code" in action.choices
            assert "commits" in action.choices
            break


def test_build_arg_parser_output_format_choices():
    """--output-format should accept html as a valid choice."""
    parser = build_arg_parser()
    for action in parser._actions:
        if hasattr(action, "dest") and action.dest == "output_format":
            assert "html" in action.choices
            assert "json" in action.choices
            assert "csv" in action.choices
            assert "txt" in action.choices
            break


# ~~~ Parsing ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_parse_args_output_file_default():
    """parse_args should derive output filename from format when not provided."""
    args = parse_args(["--output-format", "html"])
    assert args.output_file == "output/audit_results.html"

    args = parse_args(["--output-format", "csv"])
    assert args.output_file == "output/audit_results.csv"

    args = parse_args(["--output-format", "json"])
    assert args.output_file == "output/audit_results.json"


def test_parse_args_with_config():
    """parse_args should accept config dict and apply defaults."""
    config = {"mode": "local", "providers": "stripe"}
    args = parse_args([], config=config)
    assert args.mode == "local"
    assert args.providers == "stripe"


def test_parse_args_cli_overrides_config():
    """CLI args should override config defaults."""
    config = {"mode": "local", "confidence_threshold": 80.0}
    args = parse_args(["--mode", "code", "--confidence-threshold", "60.0"], config=config)
    assert args.mode == "code"
    assert args.confidence_threshold == 60.0


def test_parse_args_recent_repos_days_validation():
    """parse_args should error when mutually exclusive or unsupported options are combined with --recent-repos-days."""
    import pytest

    # 1. Not allowed with --repo
    with pytest.raises(SystemExit):
        parse_args(["--recent-repos-days", "7", "--repo", "owner/repo"])

    # 2. Not allowed with --dir
    with pytest.raises(SystemExit):
        parse_args(["--recent-repos-days", "7", "--dir", "."])

    # 3. Only allowed with code or commits mode (local mode should error)
    with pytest.raises(SystemExit):
        parse_args(["--recent-repos-days", "7", "--mode", "local"])

    # 4. Valid combination
    args = parse_args(["--recent-repos-days", "7", "--mode", "code"])
    assert args.recent_repos_days == 7
    assert args.mode == "code"


def test_parse_csv_arg_empty():
    from auditor.cli import parse_csv_arg
    assert parse_csv_arg("") == []

def test_parse_csv_arg_single():
    from auditor.cli import parse_csv_arg
    assert parse_csv_arg("openai") == ["openai"]

def test_parse_csv_arg_multiple():
    from auditor.cli import parse_csv_arg
    assert parse_csv_arg("openai, anthropic, aws") == ["openai", "anthropic", "aws"]

def test_no_ssl_verify_flag_parsed():
    parser = build_arg_parser()
    args = parser.parse_args(["--no-ssl-verify"])
    assert args.no_ssl_verify is True

def test_encryption_key_deprecation_warning():
    import pytest
    with pytest.warns(DeprecationWarning, match="--encryption-key is deprecated"):
        parse_args(["--encryption-key", "some-key"])
