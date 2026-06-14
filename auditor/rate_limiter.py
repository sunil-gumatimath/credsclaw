"""GitHub API rate-limit handling with exponential backoff and a global
per-process token bucket to prevent concurrent-task stampedes."""

import asyncio
import logging
import time
from typing import Dict

logger = logging.getLogger(__name__)

# GitHub search API: 30 req/min for authenticated, 10 for unauthenticated.
# Start conservative; ratchet up from actual response headers.
_SEARCH_QUOTA = 25


class RateLimiter:
    """Track GitHub API rate limits and apply backoff on 403/429.

    Uses a per-process token bucket (asyncio.Lock + shared counter) so
    N concurrent tasks don't all see X-RateLimit-Remaining > 0 on their
    first request and exhaust the quota in one barrage.
    """

    def __init__(self, max_retries: int = 5):
        self.max_retries = max_retries
        self._lock = asyncio.Lock()
        self._remaining = _SEARCH_QUOTA
        self._reset_time: float = 0.0

    # ------------------------------------------------------------------
    # Public helpers called by scanner.py
    # ------------------------------------------------------------------

    async def acquire(self) -> None:
        """Block until a search-API token is available.

        Call *before* every GitHub search GET so the token bucket prevents
        concurrent tasks from collectively overshooting the quota.
        """
        while True:
            async with self._lock:
                if self._remaining > 0:
                    self._remaining -= 1
                    return
                now = time.time()
                if self._reset_time > now:
                    wait = self._reset_time - now + 1.0
                else:
                    wait = 3.0
            logger.warning(
                "Rate-limit token bucket empty. Waiting %.0fs ...", wait
            )
            await asyncio.sleep(wait)

    async def update_from_headers(self, headers: Dict[str, str]) -> None:
        """Update the token bucket from GitHub response headers."""
        async with self._lock:
            raw_remaining = headers.get("X-RateLimit-Remaining")
            raw_reset = headers.get("X-RateLimit-Reset")
            if raw_remaining is not None:
                self._remaining = int(raw_remaining)
            if raw_reset is not None:
                self._reset_time = float(raw_reset)

    async def wait_if_needed(self, status: int, response_headers: Dict[str, str]) -> None:
        """Legacy hook -- called after each response.  Also updates bucket."""
        await self.update_from_headers(response_headers)

        retry_after = response_headers.get("Retry-After")
        if retry_after and status in {403, 429}:
            wait_time = max(1, int(retry_after))
            logger.warning("Rate-limited (Retry-After). Waiting %s seconds...", wait_time)
            await asyncio.sleep(wait_time)
            return

        remaining = int(response_headers.get("X-RateLimit-Remaining", "1"))
        reset_timestamp = int(response_headers.get("X-RateLimit-Reset", "0"))
        if remaining == 0 and reset_timestamp:
            wait_time = max(1, int(reset_timestamp - time.time() + 3))
            logger.warning("Rate limit reached. Waiting %s seconds...", wait_time)
            await asyncio.sleep(wait_time)

    async def exponential_backoff(self, attempt: int) -> None:
        wait_time = min(2**attempt, 300)
        logger.warning(
            "Backing off for %s seconds (attempt %s/%s)",
            wait_time, attempt + 1, self.max_retries,
        )
        await asyncio.sleep(wait_time)
