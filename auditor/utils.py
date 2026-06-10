"""Shared utility functions used across the auditor package."""

from datetime import datetime, timezone
from typing import Optional


def parse_iso8601(value: str) -> Optional[datetime]:
    """Parse an ISO-8601 date string, handling Z suffix."""
    if not value:
        return None
    try:
        if value.endswith("Z"):
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def safe_utc_now() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()
