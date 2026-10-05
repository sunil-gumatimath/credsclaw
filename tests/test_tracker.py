"""Tracker tests — checkpoint/resume state, dedupe, and occurrence tracking."""

import json

from auditor.tracker import ProgressTracker


def _finding(hash_: str, repo: str, path: str, line: int = 1) -> dict:
    return {
        "key_hash": hash_,
        "provider": "OpenAI",
        "repo": repo,
        "path": path,
        "line": line,
        "timestamp": "2026-10-01T00:00:00+00:00",
    }


def test_save_and_load_progress(tmp_path):
    checkpoint = tmp_path / "progress.json"
    tracker1 = ProgressTracker(str(checkpoint))
    tracker1.add_key({"key_hash": "hash1", "provider": "test", "key": "secret", "timestamp": "now"})
    tracker1.mark_processed("item1")
    tracker1.save_progress()

    tracker2 = ProgressTracker(str(checkpoint))
    assert tracker2.is_processed("item1")
    assert tracker2.is_duplicate_hash("hash1")
    assert len(tracker2.found_keys) == 1
    assert tracker2.found_keys[0]["provider"] == "test"
    # Raw key should be stripped by default
    assert "key" not in tracker2.found_keys[0]


def test_atomic_write_survives_crash(tmp_path, monkeypatch):
    checkpoint = tmp_path / "progress.json"
    tracker = ProgressTracker(str(checkpoint))
    tracker.add_key({"key_hash": "hash1", "provider": "test", "timestamp": "now"})
    tracker.save_progress()

    # Mock os.replace to simulate a crash during atomic swap
    def mock_replace(src, dst):
        raise Exception("Simulated crash")

    monkeypatch.setattr("os.replace", mock_replace)

    tracker.add_key({"key_hash": "hash2", "provider": "test", "timestamp": "now"})
    tracker.save_progress()

    # Original file should still be intact
    tracker3 = ProgressTracker(str(checkpoint))
    assert tracker3.is_duplicate_hash("hash1")
    assert not tracker3.is_duplicate_hash("hash2")


def test_load_corrupted_checkpoint(tmp_path):
    checkpoint = tmp_path / "progress.json"
    checkpoint.write_text("{bad json...")
    # Should not crash, just start fresh
    tracker = ProgressTracker(str(checkpoint))
    assert len(tracker.found_keys) == 0


def test_is_duplicate_hash(tmp_path):
    tracker = ProgressTracker(str(tmp_path / "progress.json"))
    tracker.add_key({"key_hash": "abc", "provider": "p1", "timestamp": "now"})
    assert tracker.is_duplicate_hash("abc")
    assert not tracker.is_duplicate_hash("def")


def test_missing_checkpoint_with_resume_flag_starts_fresh(tmp_path, caplog):
    """--resume against an absent checkpoint is silent-but-harmless here.

    The user-facing warning lives in __main__ (which owns the flag); the
    tracker itself must simply not crash on a missing file.
    """
    tracker = ProgressTracker(str(tmp_path / "does-not-exist.json"))
    assert tracker.found_keys == []
    assert tracker.processed == set()


# ~~~ Occurrence tracking ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~────────────────────
def test_same_secret_in_multiple_repos_is_one_finding_with_all_locations(tmp_path):
    tracker = ProgressTracker(str(tmp_path / "progress.json"))
    tracker.add_key(_finding("same", "org/a", "config.py"))
    tracker.add_key(_finding("same", "org/b", "settings.py"))
    tracker.add_key(_finding("same", "org/c", "app.py", line=42))

    # One secret, not three.
    assert len(tracker.found_keys) == 1
    entry = tracker.found_keys[0]
    assert entry["occurrences"] == 3
    assert tracker.occurrences("same") == 3
    repos = {loc["repo"] for loc in entry["locations"]}
    assert repos == {"org/a", "org/b", "org/c"}


def test_repeat_location_in_same_file_does_not_double_count(tmp_path):
    tracker = ProgressTracker(str(tmp_path / "progress.json"))
    tracker.add_key(_finding("dup", "org/a", "config.py", line=7))
    tracker.add_key(_finding("dup", "org/a", "config.py", line=7))
    assert tracker.found_keys[0]["occurrences"] == 1
    assert len(tracker.found_keys[0]["locations"]) == 1


def test_same_line_repeated_at_different_lines_counts_separately(tmp_path):
    tracker = ProgressTracker(str(tmp_path / "progress.json"))
    tracker.add_key(_finding("dup", "org/a", "config.py", line=7))
    tracker.add_key(_finding("dup", "org/a", "config.py", line=99))
    assert tracker.found_keys[0]["occurrences"] == 2


def test_distinct_secrets_stay_separate_findings(tmp_path):
    tracker = ProgressTracker(str(tmp_path / "progress.json"))
    tracker.add_key(_finding("h1", "org/a", "x.py"))
    tracker.add_key(_finding("h2", "org/a", "x.py"))
    assert len(tracker.found_keys) == 2
    assert tracker.found_keys[0]["occurrences"] == 1


def test_occurrences_survive_checkpoint_roundtrip(tmp_path):
    checkpoint = tmp_path / "progress.json"
    tracker = ProgressTracker(str(checkpoint))
    tracker.add_key(_finding("same", "org/a", "config.py"))
    tracker.add_key(_finding("same", "org/b", "settings.py"))
    tracker.save_progress()

    reloaded = ProgressTracker(str(checkpoint))
    assert len(reloaded.found_keys) == 1
    assert reloaded.found_keys[0]["occurrences"] == 2
    assert reloaded.occurrences("same") == 2


def test_legacy_checkpoint_without_locations_is_rehydrated(tmp_path):
    """A checkpoint written before occurrence tracking still reports a count."""
    checkpoint = tmp_path / "progress.json"
    checkpoint.write_text(
        json.dumps(
            {
                "processed": [],
                "found_keys": [
                    {
                        "key_hash": "legacy",
                        "provider": "OpenAI",
                        "repo": "local",
                        "path": "keys.txt",
                        "line": 3,
                        "timestamp": "2026-09-01T00:00:00+00:00",
                    }
                ],
                "timestamp": "2026-09-01T00:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )
    tracker = ProgressTracker(str(checkpoint))
    assert tracker.found_keys[0]["occurrences"] == 1
    assert tracker.found_keys[0]["locations"] == [{"repo": "local", "path": "keys.txt", "line": 3}]


def test_new_location_after_resume_is_appended(tmp_path):
    checkpoint = tmp_path / "progress.json"
    first = ProgressTracker(str(checkpoint))
    first.add_key(_finding("same", "org/a", "config.py"))
    first.save_progress()

    second = ProgressTracker(str(checkpoint))
    second.add_key(_finding("same", "org/b", "settings.py"))
    assert len(second.found_keys) == 1
    assert second.found_keys[0]["occurrences"] == 2
    assert {loc["repo"] for loc in second.found_keys[0]["locations"]} == {"org/a", "org/b"}
