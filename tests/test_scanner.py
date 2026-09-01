"""Scanner tests — noise/allow/deny filtering, git history scanning."""

import argparse
import asyncio
import logging
import subprocess
from unittest.mock import patch

import pytest

from auditor import (
    OPENAI_KEY_PATTERN,
    APIAuditor,
    ProgressTracker,
    RateLimiter,
    calculate_confidence_score,
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
        "extensions": "",
    }
    base.update(overrides)
    return argparse.Namespace(**base)


# ~~~ Noise / allow / deny filtering ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_noise_filter_rejects_placeholder_context(tmp_path):
    args = _build_args()
    tracker = ProgressTracker(checkpoint_file=str(tmp_path / "progress.json"), store_raw_keys=False)
    auditor = APIAuditor("fake-token", RateLimiter(), tracker, args)
    key = "sk-" + "a" * 48
    context = f"OPENAI_API_KEY={key} # example placeholder"
    is_probable, _ = auditor.is_probable_secret(key, context)
    assert is_probable is False


def test_allow_pattern_overrides_noise(tmp_path):
    args = _build_args(allow_patterns=[r"OPENAI_API_KEY"], deny_patterns=[])
    tracker = ProgressTracker(checkpoint_file=str(tmp_path / "progress.json"), store_raw_keys=False)
    auditor = APIAuditor("fake-token", RateLimiter(), tracker, args)
    key = "sk-" + "a" * 48
    context = f"OPENAI_API_KEY={key} # example placeholder"
    is_probable, _ = auditor.is_probable_secret(key, context)
    assert is_probable is True


def test_deny_pattern_blocks(tmp_path):
    args = _build_args(deny_patterns=[r"DO_NOT_USE"])
    tracker = ProgressTracker(checkpoint_file=str(tmp_path / "progress.json"), store_raw_keys=False)
    auditor = APIAuditor("fake-token", RateLimiter(), tracker, args)
    key = "sk-" + "A1" * 24
    context = f"DO_NOT_USE={key}"
    is_probable, _ = auditor.is_probable_secret(key, context)
    assert is_probable is False


def test_confidence_threshold_filtering(tmp_path):
    args = _build_args(confidence_threshold=80.0)
    tracker = ProgressTracker(checkpoint_file=str(tmp_path / "progress.json"), store_raw_keys=False)
    auditor = APIAuditor("fake-token", RateLimiter(), tracker, args)
    key = "sk-" + "".join(chr(65 + (i * 13) % 52) for i in range(48))
    context = "api_key=secret production token authorization"
    score = calculate_confidence_score(key, context, False)
    is_probable, returned_score = auditor.is_probable_secret(key, context)
    assert returned_score == pytest.approx(score, abs=0.1)
    # If entropy is high enough to score >= 80, the high-threshold auditor accepts it
    if score >= 80.0:
        assert is_probable is True
    else:
        assert is_probable is False

    args2 = _build_args(confidence_threshold=20.0)
    tracker2 = ProgressTracker(
        checkpoint_file=str(tmp_path / "progress2.json"), store_raw_keys=False
    )
    auditor2 = APIAuditor("fake-token", RateLimiter(), tracker2, args2)
    is_probable2, _ = auditor2.is_probable_secret(key, context)
    assert is_probable2 is True


# ~~~ Mode method existence ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
@pytest.mark.asyncio
async def test_local_scan_logic(tmp_path):
    args = _build_args(dry_run=False, dir=str(tmp_path))
    env_file = tmp_path / ".env"
    import string

    valid_chars = string.ascii_letters + string.digits
    high_entropy_key = "sk-" + "".join(valid_chars[(i * 17) % len(valid_chars)] for i in range(48))
    env_file.write_text(f"OPENAI_API_KEY={high_entropy_key}", encoding="utf-8")

    tracker = ProgressTracker(checkpoint_file=str(tmp_path / "progress.json"), store_raw_keys=False)
    auditor = APIAuditor("fake", RateLimiter(), tracker, args)
    await auditor.audit_local_directory("OpenAI", OPENAI_KEY_PATTERN, str(tmp_path))
    assert len(tracker.found_keys) == 1
    assert tracker.found_keys[0]["provider"] == "OpenAI"


# ~~~ Git history ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_audit_git_history_not_a_repo(tmp_path, caplog):
    caplog.set_level(logging.ERROR)
    args = _build_args()
    tracker = ProgressTracker(
        checkpoint_file=str(tmp_path / "checkpoint.json"), store_raw_keys=False
    )
    auditor = APIAuditor("fake", RateLimiter(), tracker, args)
    asyncio.run(auditor.audit_git_history("OpenAI", r"sk-\w+", str(tmp_path)))
    assert any("Not a git repository" in msg for msg in caplog.messages)


def test_audit_git_history_dry_run(tmp_path, caplog):
    caplog.set_level(logging.INFO)

    # Init a real git repo
    subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"], cwd=str(tmp_path), capture_output=True
    )
    subprocess.run(["git", "config", "user.name", "Test"], cwd=str(tmp_path), capture_output=True)
    env_file = tmp_path / ".env"
    import string

    valid_chars = string.ascii_letters + string.digits
    high_entropy_key = "sk-" + "".join(valid_chars[(i * 17) % len(valid_chars)] for i in range(48))
    env_file.write_text(f"OPENAI_API_KEY={high_entropy_key}", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(tmp_path), capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "feat: add api key"], cwd=str(tmp_path), capture_output=True
    )

    args = _build_args(dry_run=True)
    tracker = ProgressTracker(
        checkpoint_file=str(tmp_path / "checkpoint.json"), store_raw_keys=False
    )
    auditor = APIAuditor("", RateLimiter(), tracker, args)
    asyncio.run(auditor.audit_git_history("OpenAI", OPENAI_KEY_PATTERN, str(tmp_path)))

    assert len(tracker.found_keys) == 0


def test_audit_git_history_with_actual_repo(tmp_path):
    import string

    valid_chars = string.ascii_letters + string.digits
    high_entropy_key = "sk-" + "".join(valid_chars[(i * 17) % len(valid_chars)] for i in range(48))

    # Init git repo with a commit containing a fake key
    subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"], cwd=str(tmp_path), capture_output=True
    )
    subprocess.run(["git", "config", "user.name", "Test"], cwd=str(tmp_path), capture_output=True)
    env_file = tmp_path / ".env"
    env_file.write_text(f"OPENAI_API_KEY={high_entropy_key}", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(tmp_path), capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "feat: add api key"], cwd=str(tmp_path), capture_output=True
    )

    args = _build_args(dry_run=False)
    tracker = ProgressTracker(
        checkpoint_file=str(tmp_path / "checkpoint.json"), store_raw_keys=False
    )
    auditor = APIAuditor("", RateLimiter(), tracker, args)
    asyncio.run(auditor.audit_git_history("OpenAI", OPENAI_KEY_PATTERN, str(tmp_path)))

    assert tracker.found_keys, "Expected at least one finding in git history scan"
    assert tracker.found_keys[0]["provider"] == "OpenAI"
    assert "commit" in tracker.found_keys[0]


@pytest.mark.asyncio
async def test_discover_recent_repositories_success(tmp_path):
    args = _build_args(language="python", min_stars=50)
    tracker = ProgressTracker(
        checkpoint_file=str(tmp_path / "checkpoint.json"), store_raw_keys=False
    )
    auditor = APIAuditor("fake-token", RateLimiter(), tracker, args)

    mock_data = {
        "items": [
            {"full_name": "owner1/repo1"},
            {"full_name": "owner2/repo2"},
        ]
    }

    with patch.object(auditor, "request_with_retry", return_value=mock_data) as mock_request:
        repos = await auditor.discover_recent_repositories(7)
        assert repos == ["owner1/repo1", "owner2/repo2"]
        mock_request.assert_called_once()
        called_url = mock_request.call_args[0][0]
        assert "pushed:>" in called_url
        assert "language:python" in called_url
        assert "stars:>=50" in called_url


@pytest.mark.asyncio
async def test_no_ssl_verify_creates_permissive_context():
    args = _build_args(no_ssl_verify=True)
    tracker = ProgressTracker(checkpoint_file="temp.json", store_raw_keys=False)
    auditor = APIAuditor("fake", RateLimiter(), tracker, args)
    async with auditor:
        # Check connector inside session
        assert hasattr(auditor.session.connector, "_ssl")


@pytest.mark.asyncio
async def test_session_no_default_auth_header():
    args = _build_args()
    tracker = ProgressTracker(checkpoint_file="temp.json", store_raw_keys=False)
    auditor = APIAuditor("fake", RateLimiter(), tracker, args)
    async with auditor:
        assert "Authorization" not in auditor.session.headers


@pytest.mark.asyncio
async def test_retry_after_integer_header():
    rl = RateLimiter()
    await rl.wait_if_needed(429, {"Retry-After": "5"})
    # It would have slept 5s, but we're not mocking sleep here so just verifying it doesn't crash
    # If we really wanted to verify, we'd mock asyncio.sleep.


@pytest.mark.asyncio
async def test_provider_found_count_tracks_per_session():
    args = _build_args()
    tracker = ProgressTracker(checkpoint_file="temp.json", store_raw_keys=False)
    auditor = APIAuditor("fake", RateLimiter(), tracker, args)
    auditor._incr_stat("OpenAI", "repo1")
    auditor._incr_stat("OpenAI", "repo2")
    auditor._incr_stat("AWS", "repo3")
    assert auditor._provider_found_count["OpenAI"] == 2
    assert auditor._provider_found_count["AWS"] == 1
