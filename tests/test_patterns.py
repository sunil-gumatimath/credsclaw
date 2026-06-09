import argparse
import asyncio
import logging
import os
import re
import subprocess
from pathlib import Path

from auditor import (
    ANTHROPIC_KEY_PATTERN,
    APIAuditor,
    GOOGLE_AI_KEY_PATTERN,
    OPENAI_KEY_PATTERN,
    ProgressTracker,
    RateLimiter,
    fingerprint_key,
    mask_key,
    calculate_confidence_score,
    get_severity_level,
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
    load_config,
    apply_config_to_parser,
    generate_pre_commit_config,
    export_html_results,
    build_arg_parser,
    parse_args,
)


def _build_args(**overrides):
    base = {
        "max_concurrency": 2,
        "allow_patterns": [],
        "deny_patterns": [],
        "since_checkpoint": False,
        "sort": "indexed",
        "min_stars": None,
        "language": None,
        "updated_after": None,
        "max_pages": 1,
        "dry_run": True,
        "validate": False,
        "store_raw_keys": False,
        "checkpoint_interval": 5,
        "timeout": 5,
        "confidence_threshold": 50.0,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


# ---------------------------------------------------------------------------
# Existing regex & confidence tests
# ---------------------------------------------------------------------------

def test_valid_anthropic_key():
    key = "sk-ant-api03-" + "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNO"
    key = "sk-ant-api03-" + ("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" * 3)
    matches = re.findall(ANTHROPIC_KEY_PATTERN, key)
    assert len(matches) == 1


def test_invalid_anthropic_key():
    invalid_keys = ["sk-ant-short", "sk-ant", "random-string"]
    for key in invalid_keys:
        matches = re.findall(ANTHROPIC_KEY_PATTERN, key)
        assert len(matches) == 0


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
    invalid_keys = ["sk-short", "not-a-key"]
    for key in invalid_keys:
        assert len(re.findall(OPENAI_KEY_PATTERN, key)) == 0


def test_valid_google_key():
    key = "AIza" + "a" * 35
    assert len(re.findall(GOOGLE_AI_KEY_PATTERN, key)) == 1


def test_valid_aws_key():
    key = "AKIA" + "A" * 16
    assert len(re.findall(AWS_ACCESS_KEY_PATTERN, key)) == 1


def test_invalid_aws_key():
    invalid_keys = ["AKIA", "AKIAshort", "NOTAKIA123456789012"]
    for key in invalid_keys:
        assert len(re.findall(AWS_ACCESS_KEY_PATTERN, key)) == 0


def test_valid_stripe_key():
    live_key = "sk_" + "live_abcdefghijklmnopqrstuvwxyz"
    test_key = "sk_" + "test_1234567890abcdefghijklmn"
    assert len(re.findall(STRIPE_KEY_PATTERN, live_key)) == 1
    assert len(re.findall(STRIPE_KEY_PATTERN, test_key)) == 1


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


def test_valid_slack_token():
    token = "xoxb" + "-1234567890123-1234567890123-abcdefghijklmnopqrstuvwx"
    assert len(re.findall(SLACK_TOKEN_PATTERN, token)) == 1


def test_valid_twilio_key():
    key = "SK" + "a" * 32
    assert len(re.findall(TWILIO_API_KEY_PATTERN, key)) == 1


def test_valid_sendgrid_key():
    key = "SG." + "a" * 22 + "." + "b" * 43
    assert len(re.findall(SENDGRID_API_KEY_PATTERN, key)) == 1


def test_mask_and_fingerprint():
    key = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"
    masked = mask_key(key)
    assert masked.startswith("sk-proj-")
    assert masked.endswith("3456")
    fp = fingerprint_key(key)
    assert len(fp) == 64


def test_noise_filter_rejects_placeholder_context(tmp_path):
    args = _build_args()
    tracker = ProgressTracker(checkpoint_file=str(tmp_path / "progress.json"), store_raw_keys=False)
    auditor = APIAuditor("fake-token", RateLimiter(), tracker, args)
    key = "sk-" + "a" * 48
    context = f"OPENAI_API_KEY={key} # example placeholder"
    assert auditor.is_probable_secret(key, context) is False


def test_allow_pattern_overrides_noise(tmp_path):
    args = _build_args(allow_patterns=[r"OPENAI_API_KEY"], deny_patterns=[])
    tracker = ProgressTracker(checkpoint_file=str(tmp_path / "progress.json"), store_raw_keys=False)
    auditor = APIAuditor("fake-token", RateLimiter(), tracker, args)
    key = "sk-" + "a" * 48
    context = f"OPENAI_API_KEY={key} # example placeholder"
    assert auditor.is_probable_secret(key, context) is True


def test_deny_pattern_blocks(tmp_path):
    args = _build_args(deny_patterns=[r"DO_NOT_USE"])
    tracker = ProgressTracker(checkpoint_file=str(tmp_path / "progress.json"), store_raw_keys=False)
    auditor = APIAuditor("fake-token", RateLimiter(), tracker, args)
    key = "sk-" + "A1" * 24
    context = f"DO_NOT_USE={key}"
    assert auditor.is_probable_secret(key, context) is False


def test_confidence_scoring_high_entropy():
    key = "sk-" + "".join(chr(65 + (i * 13) % 52) for i in range(48))
    context = "api_key=secret production token authorization"
    is_noise = False
    score = calculate_confidence_score(key, context, is_noise)
    assert score > 60.0, f"Expected score > 60, got {score}"


def test_confidence_scoring_low_entropy():
    key = "aaaaaaaa"
    context = "test key"
    is_noise = False
    score = calculate_confidence_score(key, context, is_noise)
    assert score < 40.0


def test_confidence_scoring_noise_penalty():
    key = "sk-" + "a" * 48
    context = "example placeholder dummy test"
    is_noise = True
    score = calculate_confidence_score(key, context, is_noise)
    assert score < 50.0


def test_severity_levels():
    assert get_severity_level(90.0) == "CRITICAL"
    assert get_severity_level(70.0) == "HIGH"
    assert get_severity_level(50.0) == "MEDIUM"
    assert get_severity_level(30.0) == "LOW"


def test_confidence_threshold_filtering(tmp_path):
    args = _build_args(confidence_threshold=80.0)
    tracker = ProgressTracker(checkpoint_file=str(tmp_path / "progress.json"), store_raw_keys=False)
    auditor = APIAuditor("fake-token", RateLimiter(), tracker, args)
    key = "sk-" + "".join(chr(65 + (i * 13) % 52) for i in range(48))
    context = "api_key=secret production token authorization"
    args2 = _build_args(confidence_threshold=20.0)
    tracker2 = ProgressTracker(checkpoint_file=str(tmp_path / "progress2.json"), store_raw_keys=False)
    auditor2 = APIAuditor("fake-token", RateLimiter(), tracker2, args2)
    assert auditor2.is_probable_secret(key, context) is True
    score = calculate_confidence_score(key, context, False)
    if score < 80:
        assert auditor.is_probable_secret(key, context) is False


def test_valid_huggingface_key():
    key = "hf_" + "a" * 34
    assert len(re.findall(HUGGINGFACE_KEY_PATTERN, key)) == 1


def test_valid_cloudflare_token():
    key = "cfk_" + "a" * 40 + "01234567"
    assert len(re.findall(CLOUDFLARE_TOKEN_PATTERN, key)) == 1


def test_valid_supabase_key():
    key = "sbp_" + "b" * 36
    secret_key = "sb_secret_" + "b" * 36
    assert len(re.findall(SUPABASE_KEY_PATTERN, key)) == 1
    assert len(re.findall(SUPABASE_KEY_PATTERN, secret_key)) == 1


def test_valid_azure_connection_string():
    key = "Endpoint=sb://my-namespace.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=ABCDEF12345+/="
    assert len(re.findall(AZURE_CONNECTION_STRING_PATTERN, key)) == 1


def test_local_scan_logic():
    args = _build_args()
    tracker = ProgressTracker(checkpoint_file="temp_progress.json", store_raw_keys=False)
    auditor = APIAuditor("fake", RateLimiter(), tracker, args)
    assert hasattr(auditor, "audit_local_directory")


# ---------------------------------------------------------------------------
# Config file loading tests
# ---------------------------------------------------------------------------

def test_load_config_missing_file(tmp_path):
    """load_config should return {} for a non-existent file."""
    missing = str(tmp_path / "nonexistent.yaml")
    result = load_config(missing)
    assert result == {}


def test_load_config_invalid_yaml(tmp_path):
    """load_config should return {} for malformed YAML."""
    bad_file = tmp_path / "bad.yaml"
    bad_file.write_text(": : invalid yaml : :", encoding="utf-8")
    result = load_config(str(bad_file))
    assert result == {}


def test_load_config_valid_yaml(tmp_path):
    """load_config should parse valid YAML correctly."""
    config_data = {
        "mode": "local",
        "providers": ["openai", "github"],
        "confidence_threshold": 70.0,
        "output_format": "html",
    }
    cfg_file = tmp_path / "auditor.yaml"
    import yaml
    cfg_file.write_text(yaml.dump(config_data), encoding="utf-8")
    result = load_config(str(cfg_file))
    assert result["mode"] == "local"
    assert result["providers"] == ["openai", "github"]
    assert result["confidence_threshold"] == 70.0
    assert result["output_format"] == "html"
    assert result.get("repo") is None  # not in config


def test_apply_config_sets_defaults():
    """apply_config_to_parser should set defaults from config dict."""
    config = {"mode": "local", "confidence_threshold": 80.0}
    parser = build_arg_parser()
    apply_config_to_parser(config, parser)
    args = parser.parse_args([], namespace=argparse.Namespace())
    assert args.mode == "local"
    assert args.confidence_threshold == 80.0


def test_apply_config_plural_list_conversion():
    """YAML lists should be converted to comma-separated strings."""
    config = {"providers": ["openai", "github", "aws"], "extensions": ["py", "js"]}
    parser = build_arg_parser()
    apply_config_to_parser(config, parser)
    args = parser.parse_args([], namespace=argparse.Namespace())
    assert args.providers == "openai,github,aws"
    assert args.extensions == "py,js"


def test_apply_config_skips_unknown_keys():
    """Unknown config keys should be ignored without error."""
    config = {"unknown_key": "value", "nonexistent": 42}
    parser = build_arg_parser()
    apply_config_to_parser(config, parser)
    args = parser.parse_args([], namespace=argparse.Namespace())
    # Should not raise; defaults remain unchanged
    assert args.mode == "code"
    assert args.providers == "openai,anthropic"


# ---------------------------------------------------------------------------
# Pre-commit hook generation tests
# ---------------------------------------------------------------------------

def test_generate_pre_commit_config(tmp_path):
    """generate_pre_commit_config should write a .pre-commit-config.yaml file."""
    out_path = str(tmp_path / ".pre-commit-config.yaml")
    result_path = generate_pre_commit_config(out_path)
    assert os.path.exists(out_path)
    content = Path(out_path).read_text(encoding="utf-8")
    assert "api-key-auditor" in content
    assert "auditor.py" in content
    assert result_path == os.path.abspath(out_path)


# ---------------------------------------------------------------------------
# HTML export tests
# ---------------------------------------------------------------------------

def _make_progress_with_keys(store_raw_keys=False):
    """Helper: create a ProgressTracker with sample findings."""
    tracker = ProgressTracker(checkpoint_file="", store_raw_keys=store_raw_keys)
    for i, (provider, sev, conf) in enumerate([
        ("OpenAI", "CRITICAL", 92.5),
        ("GitHub", "HIGH", 74.0),
        ("Stripe", "MEDIUM", 55.3),
    ]):
        key = f"sk-test-key-{i}-" + "a" * 30
        key_hash = fingerprint_key(key)
        tracker.add_key({
            "provider": provider,
            "key_hash": key_hash,
            "key_masked": mask_key(key),
            "repo": f"owner/repo{i}",
            "path": f".env.{i}",
            "url": f"https://github.com/owner/repo{i}/blob/.env.{i}",
            "timestamp": "2026-01-01T00:00:00",
            "confidence": conf,
            "severity": sev,
            "valid": None,
        })
    return tracker


def test_export_html_results_no_keys(tmp_path):
    """export_html_results should not create a file when there are no keys."""
    tracker = ProgressTracker(checkpoint_file="", store_raw_keys=False)
    out_file = str(tmp_path / "report.html")
    export_html_results(tracker, out_file)
    assert not os.path.exists(out_file)


def test_export_html_results_creates_file(tmp_path):
    """export_html_results should create an HTML file with findings."""
    tracker = _make_progress_with_keys()
    out_file = str(tmp_path / "report.html")
    export_html_results(tracker, out_file)
    assert os.path.exists(out_file)
    content = Path(out_file).read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert "API Key Auditor Report" in content


def test_export_html_results_contains_key_data(tmp_path):
    """HTML report should contain provider, severity, and masked key data."""
    tracker = _make_progress_with_keys()
    out_file = str(tmp_path / "report.html")
    export_html_results(tracker, out_file)
    content = Path(out_file).read_text(encoding="utf-8")
    assert "OpenAI" in content
    assert "CRITICAL" in content
    assert "92.5" in content
    assert "GitHub" in content
    assert "HIGH" in content
    assert "Stripe" in content
    assert "MEDIUM" in content


def test_export_html_results_contains_severity_bars(tmp_path):
    """HTML report should have severity bar chart elements."""
    tracker = _make_progress_with_keys()
    out_file = str(tmp_path / "report.html")
    export_html_results(tracker, out_file)
    content = Path(out_file).read_text(encoding="utf-8")
    assert "sev-bar" in content
    assert "CRITICAL" in content
    assert "Severity Breakdown" in content


def test_export_html_results_contains_table(tmp_path):
    """HTML report should contain sortable table with expected columns."""
    tracker = _make_progress_with_keys()
    out_file = str(tmp_path / "report.html")
    export_html_results(tracker, out_file)
    content = Path(out_file).read_text(encoding="utf-8")
    assert "sortTable" in content
    assert "applyFilter" in content
    assert "data-index" in content


# ---------------------------------------------------------------------------
# Git history scanning tests
# ---------------------------------------------------------------------------

def test_audit_git_history_method_exists():
    """APIAuditor should have the audit_git_history method."""
    args = _build_args()
    tracker = ProgressTracker(checkpoint_file="temp_progress.json", store_raw_keys=False)
    auditor = APIAuditor("fake", RateLimiter(), tracker, args)
    assert hasattr(auditor, "audit_git_history")


def test_audit_git_history_not_a_repo(tmp_path, caplog):
    """audit_git_history should log error when directory is not a git repo."""
    caplog.set_level(logging.ERROR)
    args = _build_args()
    tracker = ProgressTracker(checkpoint_file=str(tmp_path / "checkpoint.json"), store_raw_keys=False)
    auditor = APIAuditor("fake", RateLimiter(), tracker, args)
    asyncio.run(auditor.audit_git_history("OpenAI", r"sk-\w+", str(tmp_path)))
    assert any("Not a git repository" in msg for msg in caplog.messages)


def test_audit_git_history_dry_run(tmp_path, caplog):
    """audit_git_history dry-run should not process commits when --dry-run is set."""
    caplog.set_level(logging.INFO)

    # Init a real git repo first so we can test dry-run behaviour
    subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=str(tmp_path), capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=str(tmp_path), capture_output=True)
    env_file = tmp_path / ".env"
    import string
    valid_chars = string.ascii_letters + string.digits
    high_entropy_key = "sk-" + "".join(valid_chars[(i * 17) % len(valid_chars)] for i in range(48))

    env_file.write_text(f"OPENAI_API_KEY={high_entropy_key}", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(tmp_path), capture_output=True)
    subprocess.run(["git", "commit", "-m", "feat: add api key"], cwd=str(tmp_path), capture_output=True)

    args = _build_args(dry_run=True)
    tracker = ProgressTracker(checkpoint_file=str(tmp_path / "checkpoint.json"), store_raw_keys=False)
    auditor = APIAuditor("", RateLimiter(), tracker, args)
    asyncio.run(auditor.audit_git_history("OpenAI", OPENAI_KEY_PATTERN, str(tmp_path)))

    # No keys should be added since dry_run is True
    assert len(tracker.found_keys) == 0


def test_audit_git_history_with_actual_repo(tmp_path):
    """audit_git_history should scan actual commits in a real git repo."""
    import string
    # Init a git repo with a commit containing a fake key
    subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=str(tmp_path), capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=str(tmp_path), capture_output=True)
    env_file = tmp_path / ".env"
    # Generate a high-entropy key using only valid alphanumeric characters
    valid_chars = string.ascii_letters + string.digits
    high_entropy_key = "sk-" + "".join(valid_chars[(i * 17) % len(valid_chars)] for i in range(48))
    env_file.write_text(f"OPENAI_API_KEY={high_entropy_key}", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(tmp_path), capture_output=True)
    subprocess.run(["git", "commit", "-m", "feat: add api key"], cwd=str(tmp_path), capture_output=True)

    args = _build_args(dry_run=False)
    tracker = ProgressTracker(checkpoint_file=str(tmp_path / "checkpoint.json"), store_raw_keys=False)
    auditor = APIAuditor("", RateLimiter(), tracker, args)
    asyncio.run(auditor.audit_git_history("OpenAI", OPENAI_KEY_PATTERN, str(tmp_path)))

    # After scanning, at least one key should have been found
    assert tracker.found_keys, "Expected at least one finding in git history scan"
    assert tracker.found_keys[0]["provider"] == "OpenAI"
    assert "commit" in tracker.found_keys[0]


# ---------------------------------------------------------------------------
# Argument parser tests
# ---------------------------------------------------------------------------

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


def test_parse_args_output_file_default():
    """parse_args should derive output filename from format when not provided."""
    args = parse_args(["--output-format", "html"])
    assert args.output_file == "audit_results.html"

    args = parse_args(["--output-format", "csv"])
    assert args.output_file == "audit_results.csv"

    args = parse_args(["--output-format", "json"])
    assert args.output_file == "audit_results.json"


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
    assert args.mode == "code"  # CLI override
    assert args.confidence_threshold == 60.0  # CLI override
