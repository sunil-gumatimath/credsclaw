"""GitHub API rate-limit handling with exponential backoff."""

import asyncio
import logging
import time
from typing import Dict

logger = logging.getLogger(__name__)


class RateLimiter:
    """Track GitHub API rate limits and apply backoff on 403/429."""

    def __init__(self, max_retries: int = 5):
        self.max_retries = max_retries

    async def wait_if_needed(self, status: int, response_headers: Dict[str, str]) -> None:
        remaining = int(response_headers.get("X-RateLimit-Remaining", "1"))
        reset_timestamp = int(response_headers.get("X-RateLimit-Reset", "0"))
        retry_after = response_headers.get("Retry-After")

        if retry_after and status in {403, 429}:
            wait_time = max(1, int(retry_after))
            logger.warning("Rate-limited (Retry-After). Waiting %s seconds...", wait_time)
            await asyncio.sleep(wait_time)
            return

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
