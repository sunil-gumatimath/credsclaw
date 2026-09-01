from auditor.utils import parse_iso8601, safe_utc_now


def test_parse_iso8601_valid():
    dt = parse_iso8601("2026-06-17T12:00:00Z")
    assert dt is not None
    assert dt.year == 2026

    dt = parse_iso8601("2026-06-17T12:00:00+00:00")
    assert dt is not None

    dt = parse_iso8601("2026-06-17 12:00:00")
    assert dt is not None


def test_parse_iso8601_invalid():
    assert parse_iso8601("invalid") is None
    assert parse_iso8601("") is None
    assert parse_iso8601(None) is None


def test_safe_utc_now():
    now = safe_utc_now()
    assert isinstance(now, str)
    assert "T" in now
