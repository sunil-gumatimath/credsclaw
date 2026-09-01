from auditor.tracker import ProgressTracker


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
