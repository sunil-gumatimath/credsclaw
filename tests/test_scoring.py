"""Confidence scoring, severity levels, masking, and fingerprinting tests."""

from auditor import (
    calculate_confidence_score,
    fingerprint_key,
    get_severity_level,
    mask_key,
)


def test_mask_and_fingerprint():
    key = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890123456789012345678903456"
    masked = mask_key(key)
    assert masked.startswith("sk-p")
    assert masked.endswith("56")
    assert "..." in masked
    fp = fingerprint_key(key)
    assert len(fp) == 64


def test_confidence_scoring_high_entropy():
    key = "sk-" + "".join(chr(65 + (i * 13) % 52) for i in range(48))
    context = "api_key=secret production token authorization"
    score = calculate_confidence_score(key, context, is_noise=False)
    assert score > 60.0, f"Expected score > 60, got {score}"


def test_confidence_scoring_low_entropy():
    key = "aaaaaaaa"
    context = "test key"
    score = calculate_confidence_score(key, context, is_noise=False)
    assert score < 40.0


def test_confidence_scoring_noise_penalty():
    key = "sk-" + "a" * 48
    context = "example placeholder dummy test"
    score = calculate_confidence_score(key, context, is_noise=True)
    assert score < 50.0


def test_severity_levels():
    assert get_severity_level(90.0) == "CRITICAL"
    assert get_severity_level(70.0) == "HIGH"
    assert get_severity_level(50.0) == "MEDIUM"
    assert get_severity_level(30.0) == "LOW"


def test_shannon_entropy_empty_string():
    from auditor.scoring import shannon_entropy

    assert shannon_entropy("") == 0.0


def test_mask_key_short():
    assert mask_key("short") == "***"
    assert mask_key("ab") == "***"


def test_severity_boundary_values():
    assert get_severity_level(80.0) == "CRITICAL"
    assert get_severity_level(60.0) == "HIGH"
    assert get_severity_level(40.0) == "MEDIUM"


def test_confidence_score_empty_input_is_low():
    """Empty key with no context should score very low (well below threshold)."""
    score = calculate_confidence_score("", "", False)
    assert score < 30.0, f"Expected score < 30 for empty input, got {score}"
