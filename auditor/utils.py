"""Shared utility functions used across the auditor package."""

import re
from datetime import datetime, timezone
from typing import Optional


def parse_iso8601(value: str) -> Optional[datetime]:
    """Parse an ISO-8601 date string, handling Z suffix and fractional seconds."""
    if not value or not value.strip():
        return None
    value = value.strip()
    try:
        # Handle Z suffix
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        # Truncate fractional seconds to 6 digits (Windows fromisoformat limit)
        # e.g. 2024-01-01T00:00:00.1234567+00:00 -> 2024-01-01T00:00:00.123456+00:00
        m = re.match(r"^(.*\.\d{6})\d+(.*)$", value)
        if m:
            value = m.group(1) + m.group(2)
        dt = datetime.fromisoformat(value)
        # Ensure timezone-aware (assume UTC if naive, e.g. --updated-after 2024-01-01)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, OverflowError):
        return None


def safe_utc_now() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()
