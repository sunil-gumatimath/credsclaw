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


# ~~~ Processed-identifier sidecar ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~─────────
def test_processed_goes_to_sidecar_not_main_checkpoint(tmp_path):
    """`processed` is bulk data, so it lives in its own file."""
    checkpoint = tmp_path / "progress.json"
    tracker = ProgressTracker(str(checkpoint))
    tracker.add_key({"key_hash": "h1", "provider": "test", "timestamp": "now"})
    tracker.mark_processed("item1")
    tracker.save_progress()

    payload = json.loads(checkpoint.read_text(encoding="utf-8"))
    assert "processed" not in payload, "processed should be split out of the main checkpoint"
    assert "found_keys" in payload

    sidecar = tmp_path / "progress.json.processed"
    assert sidecar.exists()
    assert sidecar.read_text(encoding="utf-8").splitlines() == ["item1"]


def test_sidecar_accumulates_across_saves(tmp_path):
    """Each save must append, so nothing is lost between checkpoints."""
    checkpoint = tmp_path / "progress.json"
    tracker = ProgressTracker(str(checkpoint))
    for i in range(5):
        tracker.mark_processed(f"item{i}")
    tracker.save_progress()

    for i in range(5, 12):
        tracker.mark_processed(f"item{i}")
        tracker.save_progress()

    disk = (tmp_path / "progress.json.processed").read_text(encoding="utf-8").splitlines()
    assert sorted(disk) == sorted(tracker.processed)
    assert len(disk) == len(set(disk)), "sidecar must not accumulate duplicates"
    assert len(disk) == 12


def test_resume_restores_every_processed_identifier(tmp_path):
    """A tracker reloaded from disk must know every identifier, not a subset."""
    checkpoint = tmp_path / "progress.json"
    tracker = ProgressTracker(str(checkpoint))
    tracker.add_key({"key_hash": "h1", "provider": "test", "timestamp": "now"})
    for i in range(200):
        tracker.mark_processed(f"OpenAI/repo{i}/file.py")
    tracker.save_progress()
    for i in range(200, 500):
        tracker.mark_processed(f"OpenAI/repo{i}/file.py")
        tracker.save_progress()

    resumed = ProgressTracker(str(checkpoint))
    assert resumed.processed == tracker.processed
    assert len(resumed.processed) == 500
    assert len(resumed.found_keys) == 1


def test_legacy_inline_processed_still_loads(tmp_path):
    """Checkpoints written before the split keep working."""
    checkpoint = tmp_path / "progress.json"
    checkpoint.write_text(
        json.dumps(
            {
                "processed": ["old1", "old2"],
                "found_keys": [{"key_hash": "h1", "provider": "test", "timestamp": "now"}],
                "seen_keys": [{"key_hash": "h1"}],
                "timestamp": "2026-01-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    tracker = ProgressTracker(str(checkpoint))
    assert tracker.is_processed("old1")
    assert tracker.is_processed("old2")

    # Saving migrates the inline set into the sidecar.
    tracker.save_progress()
    assert "processed" not in json.loads(checkpoint.read_text(encoding="utf-8"))
    assert sorted((tmp_path / "progress.json.processed").read_text().splitlines()) == [
        "old1",
        "old2",
    ]


def test_truncated_final_sidecar_line_is_discarded(tmp_path):
    """A crash mid-append must not leave a truncated identifier marked processed."""
    checkpoint = tmp_path / "progress.json"
    tracker = ProgressTracker(str(checkpoint))
    tracker.add_key({"key_hash": "h1", "provider": "test", "timestamp": "now"})
    tracker.mark_processed("good1")
    tracker.mark_processed("good2")
    tracker.save_progress()

    # Simulate a kill partway through appending the next identifier.
    sidecar = tmp_path / "progress.json.processed"
    with open(sidecar, "a", encoding="utf-8") as f:
        f.write("OpenAI/repo/file.p")

    resumed = ProgressTracker(str(checkpoint))
    assert resumed.is_processed("good1")
    assert resumed.is_processed("good2")
    assert not resumed.is_processed("OpenAI/repo/file.p")
    # Only the two intact identifiers survive.
    assert resumed.processed == {"good1", "good2"}


def test_clear_processed_removes_sidecar(tmp_path):
    """Clearing processed state must not leave a stale sidecar behind."""
    checkpoint = tmp_path / "progress.json"
    tracker = ProgressTracker(str(checkpoint))
    tracker.mark_processed("item1")
    tracker.save_progress()
    sidecar = tmp_path / "progress.json.processed"
    assert sidecar.exists()

    tracker.clear_processed()
    assert tracker.processed == set()
    assert not sidecar.exists()

    # A later save must not resurrect the cleared identifier.
    tracker.mark_processed("item2")
    tracker.save_progress()
    assert sidecar.read_text(encoding="utf-8").splitlines() == ["item2"]

    resumed = ProgressTracker(str(checkpoint))
    assert resumed.processed == {"item2"}


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
