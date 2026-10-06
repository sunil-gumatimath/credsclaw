"""Scanner tests — noise/allow/deny filtering, git history scanning."""

import argparse
import asyncio
import base64
import logging
import re
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from auditor import (
    AWS_ACCESS_KEY_PATTERN,
    GITHUB_TOKEN_PATTERN,
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


def test_noise_filter_rejects_test_fixtures(tmp_path):
    args = _build_args()
    tracker = ProgressTracker(checkpoint_file=str(tmp_path / "progress.json"), store_raw_keys=False)
    auditor = APIAuditor("fake-token", RateLimiter(), tracker, args)
    key = "sk-" + "a" * 48
    assert auditor.is_probable_secret(key, f"key={key} # sk-test fixture")[0] is False
    assert auditor.is_probable_secret(key, f"key={key} # redacted")[0] is False


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


def test_noise_on_neighbouring_line_does_not_drop_key(tmp_path):
    """A noise word on an adjacent line must not hard-reject a genuine key.

    The candidate context is a +/-CONTEXT_WINDOW slice that spans several
    lines; noise detection is scoped to the key's own line so a neighbouring
    doc sample (e.g. ``AKIAIOSFODNN7EXAMPLE``) cannot suppress a real finding.
    """
    import string

    valid_chars = string.ascii_letters + string.digits
    args = _build_args(confidence_threshold=40.0)
    tracker = ProgressTracker(checkpoint_file=str(tmp_path / "progress.json"), store_raw_keys=False)
    auditor = APIAuditor("fake-token", RateLimiter(), tracker, args)
    key = "sk-" + "".join(valid_chars[(i * 17) % len(valid_chars)] for i in range(48))
    context = f'OPENAI_API_KEY = "{key}"\nAWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
    is_probable, score = auditor.is_probable_secret(key, context)
    assert is_probable is True
    assert score >= 40.0


def test_noise_on_same_line_still_rejects(tmp_path):
    """Noise on the key's own line remains a hard reject (regression guard)."""
    args = _build_args()
    tracker = ProgressTracker(checkpoint_file=str(tmp_path / "progress.json"), store_raw_keys=False)
    auditor = APIAuditor("fake-token", RateLimiter(), tracker, args)
    key = "sk-" + "a" * 48
    context = f'OPENAI_API_KEY = "{key}"  # example placeholder\nAWS = AKIAIOSFODNN7EXAMPLE'
    assert auditor.is_probable_secret(key, context)[0] is False


def test_candidate_extraction_survives_adjacent_noise_line(tmp_path):
    """extract_candidates must not lose a key sitting next to a noisy line."""
    import string

    valid_chars = string.ascii_letters + string.digits
    args = _build_args(confidence_threshold=40.0)
    tracker = ProgressTracker(checkpoint_file=str(tmp_path / "progress.json"), store_raw_keys=False)
    auditor = APIAuditor("fake-token", RateLimiter(), tracker, args)
    key = "sk-" + "".join(valid_chars[(i * 17) % len(valid_chars)] for i in range(48))
    content = f'OPENAI_API_KEY = "{key}"\nAWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
    assert len(auditor.extract_candidates(content, OPENAI_KEY_PATTERN)) == 1


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

    # --dry-run must not fetch diffs or write findings, but it still has to
    # walk the history so the item count is reported.
    assert len(tracker.found_keys) == 0
    assert any("items for OpenAI" in msg for msg in caplog.messages)


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
async def test_retry_after_integer_header(monkeypatch):
    """Retry-After: 5 must sleep ~5s rather than the exponential fallback.

    ``asyncio.sleep`` is patched so the assertion is real and the suite does
    not actually block for 5 seconds.
    """
    slept: list[float] = []

    async def fake_sleep(delay):
        slept.append(delay)

    monkeypatch.setattr("auditor.rate_limiter.asyncio.sleep", fake_sleep)
    rl = RateLimiter()
    await rl.wait_if_needed(429, {"Retry-After": "5"})
    assert slept == [5.0]


@pytest.mark.asyncio
async def test_retry_after_invalid_falls_back(monkeypatch):
    """A non-numeric Retry-After header must not raise; it uses the default."""
    slept: list[float] = []

    async def fake_sleep(delay):
        slept.append(delay)

    monkeypatch.setattr("auditor.rate_limiter.asyncio.sleep", fake_sleep)
    rl = RateLimiter()
    await rl.wait_if_needed(429, {"Retry-After": "soon"})
    assert slept == [5]


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


# ~~~ Redaction markers ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_all_x_placeholder_is_rejected(tmp_path):
    """An obviously redacted value stays rejected even though 'xxx' is no
    longer a blanket noise substring."""
    args = _build_args()
    tracker = ProgressTracker(checkpoint_file=str(tmp_path / "progress.json"))
    auditor = APIAuditor("t", RateLimiter(), tracker, args)
    assert auditor.is_probable_secret("sk-" + "x" * 48, "key=sk-" + "x" * 48)[0] is False


def test_real_key_containing_xxx_is_not_rejected(tmp_path):
    """A genuine secret that happens to contain 'xxx' must survive."""
    import string

    valid = string.ascii_letters + string.digits
    args = _build_args(confidence_threshold=40.0)
    tracker = ProgressTracker(checkpoint_file=str(tmp_path / "progress.json"))
    auditor = APIAuditor("t", RateLimiter(), tracker, args)
    key = "AKIA" + "".join(valid[i % len(valid)] for i in range(16))
    key = key[:4] + "xxx" + key[7:]
    is_probable, _ = auditor.is_probable_secret(key, f"AWS_ACCESS_KEY_ID={key}")
    assert is_probable is True


# ~~~ Checkpoint cadence ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~───────────────────
@pytest.mark.asyncio
async def test_checkpoint_saves_on_interval_despite_skipped_items(tmp_path):
    """Counter-based checkpointing must fire even when processed-count modulo
    would step over the interval."""
    args = _build_args(dry_run=False, dir=str(tmp_path), checkpoint_interval=5)
    for i in range(12):
        (tmp_path / f"f{i}.txt").write_text("nothing here", encoding="utf-8")

    tracker = ProgressTracker(checkpoint_file=str(tmp_path / "progress.json"))
    saves = []
    tracker.save_progress = lambda: saves.append(1)  # type: ignore[method-assign]

    auditor = APIAuditor("t", RateLimiter(), tracker, args)
    await auditor.audit_local_directory("OpenAI", r"sk-\w{48}", str(tmp_path))
    # 12 items at interval 5 fires at items 5 and 10, plus the unconditional
    # end-of-scan save in _run_item_loop.
    assert len(saves) == 3, f"expected 3 saves for 12 items at interval 5, got {len(saves)}"


# ~~~ Cross-repo occurrence counting ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~───────
@pytest.mark.asyncio
async def test_local_scan_keeps_one_finding_across_files(tmp_path):
    """The same key in two files is one secret with two locations."""
    import string

    valid = string.ascii_letters + string.digits
    key = "sk-" + "".join(valid[(i * 17) % len(valid)] for i in range(48))
    (tmp_path / "a.env").write_text(f"OPENAI_API_KEY={key}", encoding="utf-8")
    (tmp_path / "b.env").write_text(f"OPENAI_API_KEY={key}", encoding="utf-8")

    args = _build_args(dry_run=False, dir=str(tmp_path), confidence_threshold=40.0)
    tracker = ProgressTracker(checkpoint_file=str(tmp_path / "progress.json"))
    auditor = APIAuditor("t", RateLimiter(), tracker, args)
    await auditor.audit_local_directory("OpenAI", OPENAI_KEY_PATTERN, str(tmp_path))

    assert len(tracker.found_keys) == 1
    assert tracker.found_keys[0]["occurrences"] == 2
    assert {loc["path"] for loc in tracker.found_keys[0]["locations"]} == {"a.env", "b.env"}


# ~~~ Code-mode resume ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~──────────────────────
def _code_hit(path="config.py"):
    return {
        "repository": {
            "full_name": "acme/app",
            "updated_at": "2026-01-01T00:00:00Z",
            "stargazers_count": 5,
        },
        "path": path,
        "html_url": f"https://github.com/acme/app/blob/main/{path}",
    }


def _stub_code_mode(auditor, content):
    """Replace the GitHub I/O in *auditor* with a single-page stub.

    Returns the ``get_file_content`` mock so callers can assert on how many
    times file contents were fetched.
    """
    hits = [_code_hit()]

    async def fake_search(query, page=1):
        return {"items": hits} if page == 1 else None

    async def fake_rate_limit_sync():
        return None

    auditor.search_github_code = fake_search  # type: ignore[method-assign]
    auditor._fetch_initial_rate_limit = fake_rate_limit_sync  # type: ignore[method-assign]
    return patch.object(auditor, "get_file_content", return_value=content)


@pytest.mark.asyncio
async def test_code_mode_marks_items_processed_for_resume(tmp_path):
    """Code search must record processed identifiers so --resume can skip them.

    Regression: ``audit_api_keys`` omitted ``mark_processed`` on its success
    path, so a checkpoint written during a code scan listed zero processed
    items and every resume re-fetched every file.
    """
    import string

    valid = string.ascii_letters + string.digits
    key = "sk-" + "".join(valid[(i * 17) % len(valid)] for i in range(48))
    args = _build_args(dry_run=False, confidence_threshold=40.0)
    tracker = ProgressTracker(checkpoint_file=str(tmp_path / "progress.json"))
    auditor = APIAuditor("t", RateLimiter(), tracker, args)

    with _stub_code_mode(auditor, f"OPENAI_API_KEY={key}"):
        await auditor.audit_api_keys("OpenAI", "sk-", OPENAI_KEY_PATTERN)

    assert len(tracker.found_keys) == 1
    assert "OpenAI/acme/app/config.py" in tracker.processed


@pytest.mark.asyncio
async def test_code_mode_resume_skips_already_processed_files(tmp_path):
    """A resumed scan must not re-download content it already recorded."""
    import string

    valid = string.ascii_letters + string.digits
    key = "sk-" + "".join(valid[(i * 17) % len(valid)] for i in range(48))
    checkpoint = _unique_checkpoint(tmp_path)
    args = _build_args(dry_run=False, confidence_threshold=40.0, checkpoint_file=str(checkpoint))

    first = ProgressTracker(checkpoint_file=str(checkpoint))
    first_auditor = APIAuditor("t", RateLimiter(), first, args)
    with _stub_code_mode(first_auditor, f"OPENAI_API_KEY={key}") as fetch:
        await first_auditor.audit_api_keys("OpenAI", "sk-", OPENAI_KEY_PATTERN)
    assert fetch.call_count == 1

    # Second run resumes from the checkpoint written by the first.
    resumed = ProgressTracker(checkpoint_file=str(checkpoint))
    assert "OpenAI/acme/app/config.py" in resumed.processed

    resumed_auditor = APIAuditor("t", RateLimiter(), resumed, args)
    with _stub_code_mode(resumed_auditor, f"OPENAI_API_KEY={key}") as fetch_again:
        await resumed_auditor.audit_api_keys("OpenAI", "sk-", OPENAI_KEY_PATTERN)

    assert fetch_again.call_count == 0, "resumed scan re-fetched an already-processed file"
    # The finding is still remembered via the checkpoint, just not re-found.
    assert len(resumed.found_keys) == 1


# ~~~ Code-mode content cache ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~──────────────
def _multi_key_env():
    """File content holding one key of each of three provider families."""
    import string

    valid = string.ascii_letters + string.digits
    key = "sk-" + "".join(valid[(i * 17) % len(valid)] for i in range(48))
    return (
        f"OPENAI_API_KEY={key}\n"
        "AWS_ACCESS_KEY_ID=" + "AKIA" + "0123456789ABCDEF\n"
        "GITHUB_TOKEN=ghp_" + "a" * 36 + "\n"
    )


def _code_item(blob_sha="sha-v1"):
    return {
        "repository": {"full_name": "acme/app", "updated_at": "2026-01-01T00:00:00Z"},
        "path": ".env",
        "html_url": "https://github.com/acme/app/blob/main/.env",
        "sha": blob_sha,
    }


def _stub_code_network(auditor, content_by_sha, state):
    """Stub code search + contents API; count real fetches in *state*."""

    async def fake_search(query, page=1):
        return {"items": [_code_item(state["sha"])]} if page == 1 else None

    async def fake_rate_limit_sync():
        return None

    async def fake_retry(url, headers=None):
        state["fetches"] += 1
        sha = state["sha"]
        return {"content": base64.b64encode(content_by_sha[sha].encode()).decode()}

    auditor.search_github_code = fake_search  # type: ignore[method-assign]
    auditor._fetch_initial_rate_limit = fake_rate_limit_sync  # type: ignore[method-assign]
    auditor.request_with_retry = fake_retry  # type: ignore[method-assign]


THREE_PROVIDERS = [
    ("OpenAI", "sk-", OPENAI_KEY_PATTERN),
    ("AWS", "AKIA", AWS_ACCESS_KEY_PATTERN),
    ("GitHub", "ghp_", GITHUB_TOKEN_PATTERN),
]


@pytest.mark.asyncio
async def test_content_cache_fetches_shared_file_once(tmp_path):
    """A file matched by 3 providers must be downloaded once, not 3 times.

    Code search runs once per provider, so without a cache every file holding
    several key types was re-fetched from the contents API (1000 req/hr).
    """
    content = _multi_key_env()
    checkpoint = _unique_checkpoint(tmp_path)
    args = _build_args(dry_run=False, confidence_threshold=40.0, checkpoint_file=str(checkpoint))
    tracker = ProgressTracker(checkpoint_file=str(checkpoint))
    auditor = APIAuditor("t", RateLimiter(), tracker, args)

    state = {"sha": "sha-v1", "fetches": 0}
    _stub_code_network(auditor, {"sha-v1": content}, state)

    for name, term, pattern in THREE_PROVIDERS:
        await auditor.audit_api_keys(name, term, pattern)

    assert state["fetches"] == 1, f"expected 1 content fetch, got {state['fetches']}"
    hits, misses, _entries = auditor.content_cache_stats()
    assert (hits, misses) == (2, 1)
    # All three secrets still found; the cache must not suppress findings.
    assert len(tracker.found_keys) == 3
    assert {f["provider"] for f in tracker.found_keys} == {"OpenAI", "AWS", "GitHub"}


@pytest.mark.asyncio
async def test_content_cache_refetches_when_blob_sha_changes(tmp_path):
    """An edited file (new blob SHA) must be re-fetched, never served stale."""
    old = _multi_key_env()
    import string

    valid = string.ascii_letters + string.digits
    new_key = "sk-" + "".join(valid[(i * 17 + 9) % len(valid)] for i in range(48))
    new = old.replace(old.split("=", 1)[1].splitlines()[0], new_key)

    checkpoint = _unique_checkpoint(tmp_path)
    args = _build_args(dry_run=False, confidence_threshold=40.0, checkpoint_file=str(checkpoint))
    tracker = ProgressTracker(checkpoint_file=str(checkpoint))
    auditor = APIAuditor("t", RateLimiter(), tracker, args)

    state = {"sha": "sha-v1", "fetches": 0}
    _stub_code_network(auditor, {"sha-v1": old, "sha-v2": new}, state)

    providers = list(THREE_PROVIDERS)
    for i, (name, term, pattern) in enumerate(providers):
        if i == 2:
            state["sha"] = "sha-v2"  # file edited between provider passes
        await auditor.audit_api_keys(name, term, pattern)

    assert state["fetches"] == 2, (
        f"expected 2 fetches (one per distinct blob sha), got {state['fetches']}"
    )
    hits, misses, _ = auditor.content_cache_stats()
    assert (hits, misses) == (1, 2)


def test_content_cache_respects_entry_bound(tmp_path):
    """The cache evicts to stay within its entry cap."""
    auditor = APIAuditor(
        "t",
        RateLimiter(),
        ProgressTracker(str(_unique_checkpoint(tmp_path))),
        _build_args(),
    )
    auditor._content_cache_max_entries = 3
    for i in range(10):
        auditor._store_cached_content((f"repo{i}", "p", "s"), "x" * 100)
    _hits, _misses, entries = auditor.content_cache_stats()
    assert entries == 3


def test_content_cache_respects_byte_budget(tmp_path):
    """The cache evicts to stay within its character budget."""
    auditor = APIAuditor(
        "t",
        RateLimiter(),
        ProgressTracker(str(_unique_checkpoint(tmp_path))),
        _build_args(),
    )
    auditor._content_cache_max_entries = 100
    auditor._content_cache_max_chars = 250
    for i in range(10):
        auditor._store_cached_content((f"repo{i}", "p", "s"), "x" * 100)
    _hits, _misses, entries = auditor.content_cache_stats()
    assert auditor._content_cache_chars <= 250
    assert entries == 2


def test_content_cache_skips_oversized_entry(tmp_path):
    """A file too large to cache is still returned, just not memoised."""
    auditor = APIAuditor(
        "t",
        RateLimiter(),
        ProgressTracker(str(_unique_checkpoint(tmp_path))),
        _build_args(),
    )
    auditor._content_cache_max_chars = 1000
    auditor._store_cached_content(("repo", "big", "s"), "y" * 5000)
    _hits, _misses, entries = auditor.content_cache_stats()
    assert entries == 0


@pytest.mark.asyncio
async def test_get_file_content_without_blob_sha_still_caches(tmp_path):
    """A missing ``sha`` in the search result must not defeat the cache."""
    checkpoint = _unique_checkpoint(tmp_path)
    args = _build_args(dry_run=False, confidence_threshold=40.0, checkpoint_file=str(checkpoint))
    tracker = ProgressTracker(checkpoint_file=str(checkpoint))
    auditor = APIAuditor("t", RateLimiter(), tracker, args)

    calls = []

    async def fake_retry(url, headers=None):
        calls.append(url)
        return {"content": base64.b64encode(b"hello world").decode()}

    auditor.request_with_retry = fake_retry  # type: ignore[method-assign]

    first = await auditor.get_file_content("acme/app", "README.md")
    second = await auditor.get_file_content("acme/app", "README.md")
    assert first == second == "hello world"
    assert len(calls) == 1


# ~~~ Combined git-history scan ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~────────────
def _git_repo_with_commits(tmp_path, n_commits, per_commit):
    """Build a real git repo whose commits each carry *per_commit* file text."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=str(tmp_path), capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "t@t.com"], cwd=str(tmp_path), capture_output=True
    )
    subprocess.run(["git", "config", "user.name", "T"], cwd=str(tmp_path), capture_output=True)
    for i in range(n_commits):
        (tmp_path / f"f{i}.env").write_text(per_commit(i), encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=str(tmp_path), capture_output=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", f"c{i}"], cwd=str(tmp_path), capture_output=True
        )
    return tmp_path


def _count_git_spawns(monkeypatch):
    """Patch the scanner's subprocess call; return a mutable {'log':n,'show':n}."""
    import auditor.scanner as sc

    real = sc.asyncio.create_subprocess_exec
    counts = {"log": 0, "show": 0}

    async def counting(prog, *rest, **kw):
        if "log" in rest:
            counts["log"] += 1
        if "show" in rest:
            counts["show"] += 1
        return await real(prog, *rest, **kw)

    monkeypatch.setattr(sc.asyncio, "create_subprocess_exec", counting)
    return counts


GIT_PROVIDERS = [
    ("OpenAI", "", OPENAI_KEY_PATTERN),
    ("AWS", "", AWS_ACCESS_KEY_PATTERN),
    ("GitHub", "", GITHUB_TOKEN_PATTERN),
]


def _git_commit_body(seed):
    import string

    valid = string.ascii_letters + string.digits
    key = "sk-" + "".join(valid[(i * 17 + seed) % len(valid)] for i in range(48))
    return (
        f"OPENAI_API_KEY={key}\n"
        "AWS_ACCESS_KEY_ID=" + "AKIA" + "0123456789ABCDEF\n"
        "GITHUB_TOKEN=ghp_" + "a" * 36 + "\n"
    )


@pytest.mark.asyncio
async def test_git_history_all_runs_git_once_per_commit(tmp_path, monkeypatch):
    """One `git log` and one `git show` per commit, regardless of provider count.

    Regression: git-history re-ran the whole history once per provider, so
    N providers meant N git log calls and (commits x N) git show subprocesses.
    """
    repo = _git_repo_with_commits(tmp_path, 5, _git_commit_body)
    checkpoint = _unique_checkpoint(tmp_path)
    args = _build_args(dry_run=False, confidence_threshold=40.0, checkpoint_file=str(checkpoint))
    tracker = ProgressTracker(checkpoint_file=str(checkpoint))
    auditor = APIAuditor("t", RateLimiter(), tracker, args)

    counts = _count_git_spawns(monkeypatch)
    await auditor.audit_git_history_combined(GIT_PROVIDERS, str(repo))

    assert counts["log"] == 1, f"expected 1 git log, got {counts['log']}"
    assert counts["show"] == 5, f"expected 5 git show (one per commit), got {counts['show']}"


@pytest.mark.asyncio
async def test_git_history_all_matches_per_provider_passes(tmp_path):
    """The combined pass must find exactly what per-provider passes find."""
    # Both passes read the SAME repo with independent checkpoint files, so the
    # commit SHAs they report are directly comparable.
    repo = _git_repo_with_commits(tmp_path, 4, _git_commit_body)

    combined_cp = _unique_checkpoint(tmp_path, "combined.json")
    combined_args = _build_args(
        dry_run=False, confidence_threshold=40.0, checkpoint_file=str(combined_cp)
    )
    combined = ProgressTracker(checkpoint_file=str(combined_cp))
    combined_auditor = APIAuditor("t", RateLimiter(), combined, combined_args)
    await combined_auditor.audit_git_history_combined(GIT_PROVIDERS, str(repo))

    sep_cp = _unique_checkpoint(tmp_path, "separate.json")
    sep_args = _build_args(dry_run=False, confidence_threshold=40.0, checkpoint_file=str(sep_cp))
    separate = ProgressTracker(checkpoint_file=str(sep_cp))
    sep_auditor = APIAuditor("t", RateLimiter(), separate, sep_args)
    for name, _prefix, pattern in GIT_PROVIDERS:
        await sep_auditor.audit_git_history(name, pattern, str(repo))

    def summary(tracker):
        return sorted(
            (f["provider"], f.get("commit"), f["occurrences"], f["confidence"])
            for f in tracker.found_keys
        )

    assert combined.found_keys, "combined pass found nothing; fixture is broken"
    assert summary(combined) == summary(separate)
    assert len(combined.processed) == len(separate.processed)


@pytest.mark.asyncio
async def test_git_history_all_resume_skips_git_show(tmp_path, monkeypatch):
    """A resumed git-history scan must not re-read commits it already covered."""
    repo = _git_repo_with_commits(tmp_path, 3, _git_commit_body)
    checkpoint = _unique_checkpoint(tmp_path)
    args = _build_args(dry_run=False, confidence_threshold=40.0, checkpoint_file=str(checkpoint))

    first = ProgressTracker(checkpoint_file=str(checkpoint))
    first_auditor = APIAuditor("t", RateLimiter(), first, args)
    await first_auditor.audit_git_history_combined(GIT_PROVIDERS, str(repo))
    assert first.found_keys

    resumed = ProgressTracker(checkpoint_file=str(checkpoint))
    resumed_auditor = APIAuditor("t", RateLimiter(), resumed, args)
    counts = _count_git_spawns(monkeypatch)
    await resumed_auditor.audit_git_history_combined(GIT_PROVIDERS, str(repo))

    assert counts["show"] == 0, f"resumed scan ran {counts['show']} git show subprocesses"
    # Findings survive via the checkpoint even though nothing was re-read.
    assert len(resumed.found_keys) == len(first.found_keys)


# ~~~ Line / column numbering ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~──────────────
def _legacy_positions(content, pattern):
    """The pre-optimisation arithmetic, kept as the reference for tests."""
    out = []
    for m in re.compile(pattern).finditer(content):
        last = content.rfind("\n", 0, m.start())
        out.append(
            (
                m.group(0),
                content[: m.start()].count("\n") + 1,
                m.start() - last if last != -1 else m.start() + 1,
            )
        )
    return out


def _positions(auditor, content, pattern=OPENAI_KEY_PATTERN):
    return [
        (key, line, col)
        for key, _ctx, _conf, _sev, line, col in auditor.extract_candidates(content, pattern)
    ]


LINE_CASES = {
    "no newlines": lambda k: f"KEY={k}",
    "match at line 1 col 1": lambda k: f"{k}\nrest",
    "match mid line": lambda k: f"a=1\nb=2\nKEY={k}\n",
    "after blank lines": lambda k: f"\n\n\nKEY={k}",
    "consecutive newlines": lambda k: f"x\n\n\n\nKEY={k}\n",
    "trailing newline": lambda k: f"line\nKEY={k}\n",
    "end of file, no newline": lambda k: f"line\nKEY={k}",
    "two keys one line": lambda k: f"a={k} b={okey(7)}",
    "adjacent lines": lambda k: f"K1={k}\nK2={okey(8)}",
    "windows CRLF": lambda k: f"line1\r\nKEY={k}\r\nline3",
    "many lines then key": lambda k: "\n".join(["x = 1"] * 2000) + f"\nKEY={k}",
    "key then many lines": lambda k: f"KEY={k}\n" + "\n".join(["x = 1"] * 2000),
    "empty file with key at 0": lambda k: k,
    "leading newline": lambda k: f"\nKEY={k}",
}


@pytest.mark.parametrize("label", sorted(LINE_CASES))
def test_line_numbers_match_legacy_arithmetic(tmp_path, label):
    """Reported line/column must be byte-identical to the pre-optimisation result.

    The index is a performance change only; a finder that reports a different
    line number would silently mis-point every SARIF result and HTML report.
    """
    import re as _re  # noqa: F401  (used inside _legacy_positions)

    auditor = APIAuditor(
        "t",
        RateLimiter(),
        ProgressTracker(str(_unique_checkpoint(tmp_path))),
        _build_args(confidence_threshold=40.0),
    )
    content = LINE_CASES[label](okey(0))
    assert _positions(auditor, content) == _legacy_positions(content, OPENAI_KEY_PATTERN)


def test_newline_index_is_reused_across_patterns(tmp_path):
    """The per-file index must be built once, not once per provider pattern."""
    from auditor.patterns import AWS_ACCESS_KEY_PATTERN

    auditor = APIAuditor(
        "t",
        RateLimiter(),
        ProgressTracker(str(_unique_checkpoint(tmp_path))),
        _build_args(confidence_threshold=40.0),
    )
    content = (
        "a\nb\nOPENAI_API_KEY=" + okey(0) + "\nAWS_ACCESS_KEY_ID=" + "AKIA" + "0123456789ABCDEF"
    )
    # Newline positions are the offsets OF the "\n" characters themselves.
    expected_offsets = [i for i, ch in enumerate(content) if ch == "\n"]

    auditor.extract_candidates(content, OPENAI_KEY_PATTERN)
    cached_content, offsets = auditor._newline_cache
    assert cached_content is content
    assert offsets == expected_offsets

    # A second pattern over the same content must hit the cache, not rebuild.
    auditor.extract_candidates(content, AWS_ACCESS_KEY_PATTERN)
    assert auditor._newline_cache[0] is content

    # Different content invalidates it.
    auditor.extract_candidates("x\ny", OPENAI_KEY_PATTERN)
    assert auditor._newline_cache[0] == "x\ny"
    assert auditor._newline_cache[1] == [1]


def test_line_numbers_on_a_real_large_file(tmp_path):
    """Spot-check against truth on a multi-thousand-line file."""
    auditor = APIAuditor(
        "t",
        RateLimiter(),
        ProgressTracker(str(_unique_checkpoint(tmp_path))),
        _build_args(confidence_threshold=40.0),
    )
    lines = [f"line {i} = {i}" for i in range(5000)]
    lines[4321] = f"OPENAI_API_KEY={okey(3)}"
    content = "\n".join(lines)

    assert _positions(auditor, content) == [(okey(3), 4322, 16)]


# ~~~ Combined local tree scan ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~──────────────
def okey(seed=0):
    """A synthetic but high-entropy OpenAI-format key."""
    import string

    valid = string.ascii_letters + string.digits
    return "sk-" + "".join(valid[(i * 17 + seed) % len(valid)] for i in range(48))


def _unique_checkpoint(tmp_path, name="progress.json"):
    """A checkpoint path outside the scanned tree, unique to one test.

    The audit writes its checkpoint into the tree, and ``.json`` is not in the
    skip list, so a checkpoint left inside the scanned directory is picked up as
    a scannable file on a later pass. Sharing one path across tests also lets a
    previous test's resume state leak into the next one.
    """
    ckpt_dir = Path(tempfile.mkdtemp())
    return ckpt_dir / name


@pytest.mark.asyncio
async def test_local_tree_reads_each_file_once(tmp_path):
    """One pass over the tree, regardless of how many providers are selected.

    Regression: local mode used to walk and re-read every file once per
    provider, so N providers cost N passes.
    """
    from pathlib import Path

    import auditor.patterns as patterns

    for i in range(4):
        (tmp_path / f"f{i}.py").write_text("x = 1\n", encoding="utf-8")

    checkpoint = _unique_checkpoint(tmp_path)
    args = _build_args(dry_run=False, checkpoint_file=str(checkpoint))
    tracker = ProgressTracker(checkpoint_file=str(checkpoint))
    auditor = APIAuditor("t", RateLimiter(), tracker, args)

    real_read_text = Path.read_text
    reads: dict = {}

    def counting(self, *a, **k):
        reads[self] = reads.get(self, 0) + 1
        return real_read_text(self, *a, **k)

    with patch.object(Path, "read_text", counting):
        await auditor.audit_local_tree(list(patterns.PROVIDER_CONFIGS.values()), str(tmp_path))

    assert reads, "expected the scan to read files"
    assert set(reads.values()) == {1}, f"files re-read per provider: {sorted(reads.values())}"


@pytest.mark.asyncio
async def test_local_tree_matches_per_provider_passes(tmp_path):
    """The combined pass must find exactly what N single-provider passes find."""
    import string

    from auditor.patterns import PROVIDER_CONFIGS

    valid = string.ascii_letters + string.digits
    openai_key = "sk-" + "".join(valid[(i * 17) % len(valid)] for i in range(48))

    (tmp_path / "openai.env").write_text(f"OPENAI_API_KEY={openai_key}", encoding="utf-8")
    (tmp_path / "anthropic.env").write_text(
        "ANTHROPIC_API_KEY=sk-ant-api03-" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9" + "AA",
        encoding="utf-8",
    )
    # Assembled from fragments on purpose: a contiguous literal here is a
    # syntactically valid key, and the project's own self-scan flags it (the CI
    # gate is scoped to auditor/ for exactly this reason).
    (tmp_path / "aws.env").write_text(
        "AWS_ACCESS_KEY_ID=" + "AKIA" + "0123456789ABCDEF", encoding="utf-8"
    )
    (tmp_path / "gh.env").write_text("GITHUB_TOKEN=ghp_" + "a" * 36, encoding="utf-8")
    (tmp_path / "slack.env").write_text(
        "SLACK=xoxb-123456789-987654321-" + "b" * 24, encoding="utf-8"
    )
    (tmp_path / "noise.py").write_text(f"# example placeholder {openai_key}\n", encoding="utf-8")

    checkpoint = _unique_checkpoint(tmp_path)
    args = _build_args(dry_run=False, confidence_threshold=40.0, checkpoint_file=str(checkpoint))

    combined = ProgressTracker(checkpoint_file=str(checkpoint))
    combined_auditor = APIAuditor("t", RateLimiter(), combined, args)
    await combined_auditor.audit_local_tree(list(PROVIDER_CONFIGS.values()), str(tmp_path))

    separate_cp = _unique_checkpoint(tmp_path, "progress2.json")
    separate_args = _build_args(
        dry_run=False, confidence_threshold=40.0, checkpoint_file=str(separate_cp)
    )
    separate = ProgressTracker(checkpoint_file=str(separate_cp))
    separate_auditor = APIAuditor("t", RateLimiter(), separate, separate_args)
    for entry in PROVIDER_CONFIGS.values():
        await separate_auditor.audit_local_directory(entry[0], entry[2], str(tmp_path))

    def summary(tracker):
        return sorted((f["provider"], f.get("path"), f["occurrences"]) for f in tracker.found_keys)

    assert combined.found_keys, "combined pass found nothing; fixture is broken"
    assert summary(combined) == summary(separate)
    # Every provider records a processed identifier for every file, so the
    # checkpoint is as resumable as the per-provider path was.
    assert len(combined.processed) == len(separate.processed)


@pytest.mark.asyncio
async def test_local_tree_skips_already_processed_files(tmp_path):
    """A resumed combined scan must not re-read files it already covered."""
    import string

    from auditor.patterns import OPENAI_KEY_PATTERN

    valid = string.ascii_letters + string.digits
    key = "sk-" + "".join(valid[(i * 17) % len(valid)] for i in range(48))
    (tmp_path / "a.env").write_text(f"OPENAI_API_KEY={key}", encoding="utf-8")
    (tmp_path / "b.env").write_text(f"OPENAI_API_KEY={key}", encoding="utf-8")

    checkpoint = _unique_checkpoint(tmp_path)
    args = _build_args(dry_run=False, confidence_threshold=40.0, checkpoint_file=str(checkpoint))

    first = ProgressTracker(checkpoint_file=str(checkpoint))
    first_auditor = APIAuditor("t", RateLimiter(), first, args)
    await first_auditor.audit_local_tree([("OpenAI", "sk-", OPENAI_KEY_PATTERN)], str(tmp_path))
    assert len(first.processed) == 2

    resumed = ProgressTracker(checkpoint_file=str(checkpoint))
    resumed_auditor = APIAuditor("t", RateLimiter(), resumed, args)
    await resumed_auditor.audit_local_tree([("OpenAI", "sk-", OPENAI_KEY_PATTERN)], str(tmp_path))

    # Still one merged finding, now with both locations preserved.
    assert len(resumed.found_keys) == 1
    assert resumed.found_keys[0]["occurrences"] == 2
