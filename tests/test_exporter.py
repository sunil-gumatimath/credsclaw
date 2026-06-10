"""HTML report export tests."""

import os
from pathlib import Path

from auditor import (
    export_html_results,
    fingerprint_key,
    mask_key,
    ProgressTracker,
)


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
    assert "CredsClaw Report" in content


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
    assert "Stripe" in content


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
