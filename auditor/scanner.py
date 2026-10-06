"""Core APIAuditor class — scans GitHub, local directories, and git history."""

import asyncio
import base64
import logging
import re
import ssl
from bisect import bisect_right
from collections import OrderedDict
from collections.abc import Callable
from pathlib import Path
from typing import Any

import aiohttp

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

from datetime import UTC

from auditor.cli import parse_csv_arg
from auditor.patterns import NOISE_SUBSTRINGS, REDACTION_MARKER_PATTERNS
from auditor.rate_limiter import SEARCH_QUOTA, RateLimiter
from auditor.scoring import (
    calculate_confidence_score,
    fingerprint_key,
    get_severity_level,
    mask_key,
)
from auditor.tracker import ProgressTracker
from auditor.utils import parse_iso8601, safe_utc_now
from auditor.validator import (
    NON_VALIDATABLE_PROVIDERS,
    VALIDATION_MAP,
    create_validator_session,
)

logger = logging.getLogger(__name__)

# Audit hardening constants
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # Skip files larger than 5 MB (avoid OOM)
CONTEXT_WINDOW = 80  # Characters of context around a match (was 40; S-MED-02)
VALIDATION_CONCURRENCY = 5  # Max parallel validation requests (V-MED-04)
# Memoised GitHub file contents. The contents API allows 1000 req/hr
# authenticated, and code search runs once per provider, so an uncached design
# re-downloads every file once per provider that matches it.
CONTENT_CACHE_MAX_CHARS = 32 * 1024 * 1024  # ~32M chars
CONTENT_CACHE_MAX_ENTRIES = 4096
_PATTERN_CACHE: dict[str, re.Pattern[str]] = {}


def _is_redaction_marker(key: str) -> bool:
    """True when *key* is an unmistakable redaction placeholder.

    Kept separate from :data:`auditor.patterns.NOISE_SUBSTRINGS` because a bare
    ``xxx`` / ``xxxxx`` substring collides with genuine random secrets, while an
    all-``x`` or all-asterisk value never does.
    """
    return any(p.search(key) for p in REDACTION_MARKER_PATTERNS)


class APIAuditor:
    """Scans GitHub code/commits, local directories, or git history for exposed API keys."""

    def __init__(
        self,
        token: str,
        rate_limiter: RateLimiter,
        progress: ProgressTracker,
        args: Any,
    ):
        self.token = token
        self.rate_limiter = rate_limiter
        self.progress = progress
        self.args = args
        self.session: aiohttp.ClientSession | None = None
        self.lock = asyncio.Lock()
        self.semaphore = asyncio.Semaphore(max(1, args.max_concurrency))
        self.compiled_allow = []
        if getattr(args, "allow_patterns", None):
            for p in args.allow_patterns:
                try:
                    self.compiled_allow.append(re.compile(p, re.IGNORECASE))
                except re.error as exc:
                    logger.warning("Invalid allow pattern '%s' skipped: %s", p, exc)
        self.compiled_deny = []
        if getattr(args, "deny_patterns", None):
            for p in args.deny_patterns:
                try:
                    self.compiled_deny.append(re.compile(p, re.IGNORECASE))
                except re.error as exc:
                    logger.warning("Invalid deny pattern '%s' skipped: %s", p, exc)
        self._content_cache: OrderedDict[tuple[str, str, str], str] = OrderedDict()
        self._content_cache_chars = 0
        self._content_cache_hits = 0
        self._content_cache_misses = 0
        self._content_cache_max_chars = CONTENT_CACHE_MAX_CHARS
        self._content_cache_max_entries = CONTENT_CACHE_MAX_ENTRIES
        # Most recently indexed (content, newline offsets) pair. See
        # _newline_offsets: one entry is enough because every provider pass
        # over a file runs back-to-back.
        self._newline_cache: tuple[str, list[int]] | None = None
        self.stats_by_provider: dict[str, dict[str, int]] = {}
        self.stats_by_repo: dict[str, int] = {}
        self._provider_found_count: dict[str, int] = {}
        self._processed_since_save = 0
        self._checkpoint_saving = False
        self.since_dt = None
        if args.since_checkpoint and progress.checkpoint_timestamp:
            self.since_dt = parse_iso8601(progress.checkpoint_timestamp)
            if self.since_dt is None:
                logger.warning(
                    "Could not parse checkpoint timestamp '%s'; "
                    "will process all items (no incremental filtering)",
                    progress.checkpoint_timestamp,
                )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def __aenter__(self):
        connector_kwargs: dict[str, Any] = {}
        if getattr(self.args, "no_ssl_verify", False):
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            connector_kwargs["ssl"] = ssl_ctx
            logger.warning("SSL certificate verification is disabled")
        connector = aiohttp.TCPConnector(**connector_kwargs)
        self.session = aiohttp.ClientSession(
            connector=connector,
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------
    def _incr_stat(self, provider: str, repo: str) -> None:
        provider_stats = self.stats_by_provider.setdefault(
            provider, {"found": 0, "validated_true": 0, "validated_false": 0}
        )
        provider_stats["found"] += 1
        self.stats_by_repo[repo] = self.stats_by_repo.get(repo, 0) + 1
        self._provider_found_count[provider] = self._provider_found_count.get(provider, 0) + 1

    def save_progress_locked(self) -> None:
        """Save the checkpoint while holding ``self.lock``.

        Scan modes fan out one task per file and each can reach the
        checkpoint-interval threshold, so without serialising them two tasks
        can write the tracker at once and the slower write can land last while
        carrying less state — silently dropping findings the checkpoint claims
        to have covered. ``os.replace`` keeps the file valid, so this loses
        progress on a crash rather than corrupting it.

        The save is synchronous and runs to completion without yielding, and
        every mutation of the tracker's sets and lists already happens under
        ``self.lock`` in the callers. So the only race left is between two
        checkpoints, and serialising them needs nothing more than this guard.
        """
        if self._checkpoint_saving:
            # Re-entrant save (a caller already holds self.lock). The outer
            # call will persist the state this one would have written.
            return
        self._checkpoint_saving = True
        try:
            self.progress.save_progress()
        finally:
            self._checkpoint_saving = False

    def _checkpoint_if_due(self) -> None:
        """Save the checkpoint every ``checkpoint_interval`` items processed.

        Uses its own counter rather than ``len(processed) % interval == 0``:
        items are skipped in several paths (already-processed, unreadable,
        filtered), so a modulo test can step straight over a multiple and then
        never fire again for the rest of the scan.
        """
        self._processed_since_save += 1
        if self._processed_since_save >= self.args.checkpoint_interval:
            self._processed_since_save = 0
            self.save_progress_locked()

    def _record_validation(self, provider: str, valid: bool | None) -> None:
        provider_stats = self.stats_by_provider.setdefault(
            provider, {"found": 0, "validated_true": 0, "validated_false": 0}
        )
        if valid is True:
            provider_stats["validated_true"] += 1
        elif valid is False:
            provider_stats["validated_false"] += 1

    # ------------------------------------------------------------------
    # GitHub API
    # ------------------------------------------------------------------

    async def _fetch_initial_rate_limit(self) -> None:
        """Sync the token bucket with GitHub's actual remaining search quota."""
        if self.session is None:
            # Best-effort optimisation: never fatal, the bucket just keeps its
            # conservative SEARCH_QUOTA default.
            logger.debug("ClientSession not initialized; skipping rate-limit sync")
            return
        try:
            headers = {"Authorization": f"token {self.token}"}
            async with self.session.get(
                "https://api.github.com/rate_limit", headers=headers
            ) as resp:
                data = await resp.json()
            resources = data.get("resources", {})
            # Code search has its own, stricter quota (10/min authenticated)
            # separate from general search (30/min). Prefer code_search so we
            # don't seed the bucket with 30 and blow the 10/min budget on the
            # first concurrent volley.
            search = resources.get("code_search") or resources.get("search", {})
            remaining = search.get("remaining", SEARCH_QUOTA)
            reset_at = search.get("reset", 0)
            await self.rate_limiter.update_from_headers(
                {
                    "X-RateLimit-Remaining": str(remaining),
                    "X-RateLimit-Reset": str(reset_at),
                }
            )
            logger.debug(
                "Rate-limit bucket synced: %s search requests remaining",
                remaining,
            )
        except Exception as exc:
            logger.debug("Could not fetch initial rate limit: %s", exc)

    async def request_with_retry(
        self, url: str, headers: dict[str, str] | None = None
    ) -> dict[str, Any] | None:
        if self.session is None:
            raise RuntimeError("ClientSession not initialized; use 'async with APIAuditor(...)'")
        for attempt in range(self.rate_limiter.max_retries):
            try:
                request_headers = {"Authorization": f"token {self.token}"}
                if headers:
                    request_headers.update(headers)
                async with self.session.get(url, headers=request_headers) as response:
                    resp_headers = dict(response.headers)

                    if response.status in {403, 429}:
                        # Prefer GitHub's Retry-After over blind exponential backoff.
                        retry_after = response.headers.get("Retry-After")
                        if retry_after:
                            try:
                                wait_time = max(1, int(retry_after))
                            except (ValueError, TypeError):
                                wait_time = min(2**attempt, 300)
                        else:
                            wait_time = min(2**attempt, 300)
                        logger.warning(
                            "Rate limit/auth issue for %s (status %s), waiting %ss",
                            url,
                            response.status,
                            wait_time,
                        )
                        await asyncio.sleep(wait_time)
                        if "/search/" in url:
                            await self.rate_limiter.update_from_headers(resp_headers)
                        continue

                    if "/search/" in url:
                        await self.rate_limiter.wait_if_needed(response.status, resp_headers)

                    if response.status == 404:
                        return None

                    response.raise_for_status()
                    return await response.json()  # type: ignore[no-any-return]
            except aiohttp.ClientError as exc:
                logger.error("Request error for %s: %s", url, exc)
                if attempt < self.rate_limiter.max_retries - 1:
                    await self.rate_limiter.exponential_backoff(attempt)
                    continue
                return None
        return None

    async def discover_recent_repositories(self, days: int) -> list[str]:
        """Query GitHub search API for public repositories updated/pushed to within the last N days."""
        from datetime import datetime, timedelta

        # Sync the token bucket with actual GitHub remaining quota
        await self._fetch_initial_rate_limit()

        cutoff_date = (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%d")

        # Build query
        q = f"pushed:>{cutoff_date}"
        if self.args.language:
            q += f" language:{self.args.language}"
        if self.args.min_stars:
            q += f" stars:>={self.args.min_stars}"

        logger.info("Discovering public repositories with query: %s", q)
        repos: list[str] = []

        page = 1
        max_repos = 100  # Default safe upper bound
        while len(repos) < max_repos:
            await self.rate_limiter.acquire()
            url = f"https://api.github.com/search/repositories?q={q}&sort=updated&order=desc&per_page=100&page={page}"
            data = await self.request_with_retry(url)
            if not data or "items" not in data:
                break

            items = data["items"]
            if not items:
                break

            for item in items:
                full_name = item.get("full_name")
                if full_name:
                    repos.append(full_name)

            if len(items) < 100:
                break
            page += 1
            if self.args.max_pages and page > self.args.max_pages:
                break

        logger.info("Discovered %s recent repositories to scan", len(repos))
        return repos[:max_repos]

    async def search_github_code(self, query: str, page: int = 1) -> dict[str, Any] | None:
        from urllib.parse import quote_plus

        await self.rate_limiter.acquire()

        encoded_q = quote_plus(query)
        sort_param = f"&sort={self.args.sort}&order=desc" if self.args.sort else ""
        url = (
            f"https://api.github.com/search/code?q={encoded_q}&per_page=100&page={page}{sort_param}"
        )
        return await self.request_with_retry(url)

    async def search_github_commits(self, query: str, page: int = 1) -> dict[str, Any] | None:
        from urllib.parse import quote_plus

        await self.rate_limiter.acquire()

        encoded_q = quote_plus(query)
        sort_param = f"&sort={self.args.sort}&order=desc" if self.args.sort else ""
        url = f"https://api.github.com/search/commits?q={encoded_q}&per_page=100&page={page}{sort_param}"
        return await self.request_with_retry(
            url, headers={"Accept": "application/vnd.github.cloak-preview+json"}
        )

    async def get_file_content(
        self, repo_full_name: str, path: str, blob_sha: str = ""
    ) -> str | None:
        """Fetch a file's content, memoised per blob.

        Every provider runs its own code search, so one file holding several
        key types is requested once per matching provider. Each request costs a
        round trip against the contents API (1000 req/hr authenticated), so
        the decoded text is cached keyed on ``(repo, path, blob_sha)``.

        ``blob_sha`` is the blob SHA from the search result. Including it means
        an edited file is re-fetched rather than served stale, while an
        unchanged file is reused across provider passes.
        """
        cache_key = (repo_full_name, path, blob_sha)
        if cache_key in self._content_cache:
            self._content_cache_hits += 1
            # Refresh recency so a hot file survives bulk eviction.
            self._content_cache.move_to_end(cache_key)
            return self._content_cache[cache_key]
        self._content_cache_misses += 1

        url = f"https://api.github.com/repos/{repo_full_name}/contents/{path}"
        data = await self.request_with_retry(url)
        if not data or "content" not in data:
            return None
        try:
            content = base64.b64decode(data["content"]).decode("utf-8", errors="ignore")
        except Exception as exc:
            logger.error(
                "Failed to decode content from %s/%s: %s",
                repo_full_name,
                path,
                exc,
            )
            return None

        self._store_cached_content(cache_key, content)
        return content

    def _store_cached_content(self, key: tuple[str, str, str], content: str) -> None:
        """Insert into the content cache, evicting until it fits the budget.

        Bounded by total characters rather than entry count: file sizes vary by
        orders of magnitude, so an entry cap alone would still let a large scan
        grow without limit.
        """
        size = len(content)
        if size > self._content_cache_max_chars:
            # Too big to cache at all; the caller still gets the content.
            return
        while self._content_cache and (
            self._content_cache_chars + size > self._content_cache_max_chars
            or len(self._content_cache) >= self._content_cache_max_entries
        ):
            _evicted_key, evicted = self._content_cache.popitem(last=False)
            self._content_cache_chars -= len(evicted)
        self._content_cache[key] = content
        self._content_cache_chars += size

    def content_cache_stats(self) -> tuple[int, int, int]:
        """Return ``(hits, misses, entries)`` for logging and tests."""
        return self._content_cache_hits, self._content_cache_misses, len(self._content_cache)

    # ------------------------------------------------------------------
    # Candidate extraction and filtering
    # ------------------------------------------------------------------
    def _matches_allow(self, text: str) -> bool:
        if not self.compiled_allow:
            return True
        return any(p.search(text) for p in self.compiled_allow)

    def _matches_deny(self, text: str) -> bool:
        if not self.compiled_deny:
            return False
        return any(p.search(text) for p in self.compiled_deny)

    @staticmethod
    def _key_line(key: str, context: str) -> str:
        """Return the line of *context* that contains the matched key.

        Noise detection is scoped to the key's own line. The raw candidate
        context is a +/-CONTEXT_WINDOW character slice, which routinely spans
        several lines; without this narrowing an unrelated line carrying a
        noise word (e.g. an ``AKIA...EXAMPLE`` doc sample on the next line)
        silently hard-rejected an otherwise genuine key on the line above.
        """
        for line in context.splitlines():
            if key in line:
                return line
        # Fall back to the whole window when the key is not visible verbatim
        # (truncated window, or a match spanning a line break).
        return context

    def is_probable_secret(self, key: str, context: str) -> tuple[bool, float]:
        """Return (is_likely_secret, confidence_score).

        Filters through deny/allow patterns, noise detection, and entropy analysis.
        Noise substrings (example, dummy, …) cause a hard reject unless explicitly
        overridden by an allow pattern.  The caller uses the pre-calculated score to
        avoid double computation.
        """
        # Noise is judged on the key's own line only; scoring still uses the full
        # context window so nearby keyword hits (api_key, secret, …) still count.
        noise_scope = f"{key} {self._key_line(key, context)}"
        lowered = noise_scope.lower()

        if self._matches_deny(f"{key} {context}"):
            return False, 0.0

        is_noise = any(noise in lowered for noise in NOISE_SUBSTRINGS) or _is_redaction_marker(key)

        # Allow pattern overrides the noise hard-reject.
        if self.compiled_allow and self._matches_allow(f"{key} {context}"):
            confidence = calculate_confidence_score(key, context, is_noise)
            return True, confidence

        if is_noise:
            return False, 0.0

        confidence = calculate_confidence_score(key, context, is_noise=False)
        return confidence >= self.args.confidence_threshold, confidence

    def extract_candidates(
        self, content: str, pattern: str
    ) -> list[tuple[str, str, float, str, int, int]]:
        candidates: list[tuple[str, str, float, str, int, int]] = []
        # Cache compiled patterns to avoid re.compile on every file (P-LOW-01).
        compiled = _PATTERN_CACHE.get(pattern)
        if compiled is None:
            try:
                compiled = re.compile(pattern)
            except re.error as exc:
                logger.warning("Invalid regex pattern skipped: %s (%s)", pattern, exc)
                return candidates
            _PATTERN_CACHE[pattern] = compiled

        # Newline offsets for the whole file, built once and shared by every
        # provider pass over it. Rescanning `content[:match.start()]` per match
        # was O(n*m) and cost ~167ms on a 4MB file.
        newlines = self._newline_offsets(content)

        for match in compiled.finditer(content):
            key = match.group(0)
            start = max(0, match.start() - CONTEXT_WINDOW)
            end = min(len(content), match.end() + CONTEXT_WINDOW)
            context = content[start:end]
            is_probable, confidence = self.is_probable_secret(key, context)
            if is_probable:
                severity = get_severity_level(confidence)
                # bisect_right gives the count of newlines before match.start(),
                # i.e. the zero-based line index; +1 makes it 1-based.
                line_idx = bisect_right(newlines, match.start())
                prev_nl = newlines[line_idx - 1] if line_idx else -1
                col_no = match.start() - prev_nl if line_idx else match.start() + 1
                candidates.append((key, context, confidence, severity, line_idx + 1, col_no))
        return candidates

    def _newline_offsets(self, content: str) -> list[int]:
        """Sorted newline offsets for *content*, memoised per content object.

        The combined local/git-history scans call ``extract_candidates`` once
        per provider with the same ``content``, so this is built once per file
        rather than once per (file x provider x match).

        Keyed on ``id(content)`` while holding a reference to the string itself:
        that keeps the object alive, so its id cannot be recycled by a later
        allocation and mistaken for a cache hit.
        """
        cached = self._newline_cache
        if cached is not None and cached[0] is content:
            return cached[1]
        # str.find in a loop beats enumerate+compare (~9ms vs ~245ms on an 8MB
        # file) because the scan happens in C, not in Python bytecode.
        offsets: list[int] = []
        pos = content.find("\n")
        while pos != -1:
            offsets.append(pos)
            pos = content.find("\n", pos + 1)
        # Keep only the most recent file; holding more would pin memory.
        self._newline_cache = (content, offsets)
        return offsets

    # ------------------------------------------------------------------
    # Local scanning
    # ------------------------------------------------------------------
    async def audit_local_directory(self, provider: str, pattern: str, directory: str) -> None:
        """Recursive local directory scan for a single provider.

        Thin wrapper over :meth:`audit_local_tree` so both entry points share
        one implementation and cannot drift. Prefer ``audit_local_tree`` when
        several providers are selected: it walks the tree once instead of once
        per provider.
        """
        await self.audit_local_tree([(provider, "", pattern)], directory)

    async def audit_local_tree(
        self,
        providers: list[tuple[str, str, str]],
        directory: str,
    ) -> None:
        """Scan a local tree once, applying every provider pattern per file.

        The per-provider path re-walked the tree and re-read every file once
        *per provider*, so N providers cost N passes. This walks once and tests
        each file against all patterns, making local scans linear in file count
        rather than in (files x providers).

        *providers* is a list of ``(display_name, search_prefix, pattern)``
        tuples, i.e. the values of :data:`auditor.patterns.PROVIDER_CONFIGS`.
        Only the search prefix is ignored here; local scans match on pattern.

        Only file discovery and reading are shared. Each provider keeps its own
        findings, stats, checkpoints, and validation pass, so a provider still
        resumes independently and ``--providers`` semantics are unchanged.
        """
        if not providers:
            return

        dir_path = Path(directory)
        if not dir_path.is_dir():
            logger.error("Directory not found: %s", directory)
            return

        logger.info(
            "Auditing %s API keys in local directory: %s",
            ", ".join(entry[0] for entry in providers),
            directory,
        )

        all_files = self._discover_local_files(dir_path)
        if not all_files:
            logger.info("No scannable files found in %s", directory)
            return

        if self.args.dry_run:
            # Discovery only: no reads, no matching, no findings, no checkpoint.
            logger.info(
                "[Dry run] %s items for %s",
                len(all_files),
                ", ".join(entry[0] for entry in providers),
            )
            return

        # Pair each provider with its compiled pattern up front. An uncompilable
        # pattern drops the provider entirely, so the two lists stay aligned by
        # index for the rest of the function.
        compiled: list[tuple[str, re.Pattern[str]]] = []
        for provider_name, _search_prefix, pattern in providers:
            try:
                pattern_obj = _PATTERN_CACHE.get(pattern)
                if pattern_obj is None:
                    pattern_obj = re.compile(pattern)
                    _PATTERN_CACHE[pattern] = pattern_obj
            except re.error as exc:
                logger.warning("Invalid regex pattern skipped: %s (%s)", pattern, exc)
                continue
            compiled.append((provider_name, pattern_obj))
        if not compiled:
            return

        # Keys are bucketed by provider index so validation stays grouped the
        # way batch_validate_keys expects.
        keys_to_validate: dict[int, list[tuple[dict[str, Any], str]]] = {}

        async def process_file(file_path: Path) -> None:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception as exc:
                logger.debug("Failed to read %s: %s", file_path, exc)
                async with self.lock:
                    for provider_name, _pattern_obj in compiled:
                        self.progress.mark_processed(f"{provider_name}/{file_path}")
                return

            for idx, (provider_name, pattern_obj) in enumerate(compiled):
                identifier = f"{provider_name}/{file_path}"
                async with self.lock:
                    if self.progress.is_processed(identifier):
                        continue

                local_candidates = self.extract_candidates(content, pattern_obj.pattern)

                async with self.lock:
                    bucket = keys_to_validate.setdefault(idx, [])
                    for key, _context, confidence, severity, line_no, col_no in local_candidates:
                        key_hash = fingerprint_key(key)
                        key_data: dict[str, Any] = {
                            "provider": provider_name,
                            "key_hash": key_hash,
                            "key_masked": mask_key(key),
                            "repo": "local",
                            "path": str(file_path.relative_to(dir_path)),
                            "url": f"file://{file_path}",
                            "line": line_no,
                            "column": col_no,
                            "timestamp": safe_utc_now(),
                            "confidence": round(confidence, 2),
                            "severity": severity,
                            "valid": None,
                        }
                        if self.args.store_raw_keys:
                            key_data["key"] = key
                        self.progress.add_key(key_data)
                        self._incr_stat(provider_name, "local")
                        bucket.append((key_data, key))
                    self.progress.mark_processed(identifier)
                    self._checkpoint_if_due()

        tasks = [asyncio.create_task(self._wrap_local_file(f, process_file)) for f in all_files]
        iterator = asyncio.as_completed(tasks)
        if tqdm:
            iterator = tqdm(
                iterator, total=len(tasks), desc=f"Scanning {len(providers)} providers (local)"
            )
        for coro in iterator:
            try:
                await coro
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("Local file task failed: %s", exc)

        if self.args.validate:
            for idx, (provider_name, _pattern_obj) in enumerate(compiled):
                bucket = keys_to_validate.get(idx, [])
                if bucket:
                    logger.info("Validating %s %s keys...", len(bucket), provider_name)
                    await self.batch_validate_keys(bucket, provider_name)

        self.save_progress_locked()

    async def _wrap_local_file(self, file_path: Path, process_func) -> None:
        """Bounded-concurrency wrapper mirroring ``_run_item_loop``'s guard."""
        async with self.semaphore:
            try:
                await process_func(file_path)
            except Exception as exc:
                logger.debug("Local file processing failed for %s: %s", file_path, exc)

    def _discover_local_files(self, dir_path: Path) -> list[Path]:
        """Walk *dir_path* once, applying the size/extension/symlink filters."""
        skip_extensions = {
            ".pyc",
            ".pyo",
            ".pyd",
            ".so",
            ".dll",
            ".exe",
            ".bin",
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".ico",
            ".bmp",
            ".svg",
            ".zip",
            ".tar",
            ".gz",
            ".bz2",
            ".7z",
            ".rar",
            ".pdf",
            ".doc",
            ".docx",
            ".xls",
            ".xlsx",
            ".mp3",
            ".mp4",
            ".avi",
            ".mov",
            ".woff",
            ".woff2",
            ".ttf",
            ".eot",
            ".class",
            ".o",
            ".obj",
        }

        allowed_extensions = None
        if self.args.extensions:
            allowed_extensions = {
                f".{ext.lstrip('.')}" for ext in parse_csv_arg(self.args.extensions)
            }

        all_files: list[Path] = []
        for file_path in dir_path.rglob("*"):
            if not file_path.is_file():
                continue
            # Skip symlinks to avoid loops / out-of-scope reads.
            if file_path.is_symlink():
                continue
            # Skip hidden directories (e.g., .git, .venv), but NOT .github or hidden files like .env
            parts = file_path.relative_to(dir_path).parts
            if any(part.startswith(".") and part != ".github" for part in parts[:-1]):
                continue
            if file_path.suffix.lower() in skip_extensions:
                continue
            file_ext = file_path.suffix.lower() or f".{file_path.name.lstrip('.')}"
            if allowed_extensions and file_ext not in allowed_extensions:
                continue
            # Skip very large files to avoid OOM.
            try:
                if file_path.stat().st_size > MAX_FILE_SIZE_BYTES:
                    logger.debug(
                        "Skipping large file %s (%s bytes)", file_path, file_path.stat().st_size
                    )
                    continue
            except OSError:
                continue
            all_files.append(file_path)
        return all_files

    async def batch_validate_keys(
        self, keys_data: list[tuple[dict[str, Any], str]], provider: str
    ) -> None:
        if provider in NON_VALIDATABLE_PROVIDERS:
            # Google/AWS/Azure have no lightweight validation endpoint; skip the
            # session and the request entirely rather than always getting None.
            logger.debug("No live validation available for %s — skipping", provider)
            return
        validator = VALIDATION_MAP.get(provider)
        if not validator:
            return
        no_ssl_verify = getattr(self.args, "no_ssl_verify", False)
        timeout = getattr(self.args, "timeout", 10)
        # Bound validation concurrency to avoid provider rate-limits / FD exhaustion (V-MED-04).
        val_semaphore = asyncio.Semaphore(VALIDATION_CONCURRENCY)

        # Reuse a single session for all validations in this batch
        async with create_validator_session(no_ssl_verify, timeout) as session:

            async def _validated(key: str) -> bool | None:
                async with val_semaphore:
                    return await validator(key, timeout, no_ssl_verify, session)  # type: ignore[no-untyped-call]

            # Dedupe by fingerprint so a key seen in N repos is validated once, then
            # fan the single result back out to every merged finding.
            unique: dict[str, str] = {}
            per_key: list[tuple[dict[str, Any], str]] = []
            for key_data, raw_key in keys_data:
                key_hash = str(key_data.get("key_hash", ""))
                if key_hash not in unique:
                    unique[key_hash] = raw_key
                per_key.append((key_data, key_hash))

            tasks = [_validated(raw) for raw in unique.values()]
            hash_results = await asyncio.gather(*tasks)
            by_hash = dict(zip(unique.keys(), hash_results, strict=False))

            for key_data, key_hash in per_key:
                valid = by_hash.get(key_hash)
                async with self.lock:
                    key_data["valid"] = valid
                    self._record_validation(provider, valid)

    # ------------------------------------------------------------------
    # Repo / date filtering
    # ------------------------------------------------------------------
    def _is_recent_enough(self, repo_updated_at: str = "", commit_date: str = "") -> bool:
        """Return True if the item is newer than the checkpoint timestamp."""
        if not self.since_dt:
            return True
        check_dt = parse_iso8601(commit_date) or parse_iso8601(repo_updated_at)
        if not check_dt:
            return True
        return check_dt > self.since_dt

    def filter_repo(self, item: dict[str, Any]) -> bool:
        """Return True if the repository item passes all user-specified filters."""
        repo = item.get("repository", {})

        if self.args.min_stars and repo.get("stargazers_count", 0) < self.args.min_stars:
            return False
        if self.args.language:
            repo_lang = (repo.get("language") or "").lower()
            if repo_lang != self.args.language.lower():
                return False
        if self.args.updated_after:
            updated_at = parse_iso8601(repo.get("updated_at", ""))
            cutoff = parse_iso8601(self.args.updated_after)
            if updated_at and cutoff and updated_at <= cutoff:
                return False
        return True

    # ------------------------------------------------------------------
    # Shared item-processing loop
    # ------------------------------------------------------------------
    async def _run_item_loop(
        self,
        items: list[Any],
        provider: str,
        pattern: str,
        process_func: "Callable[[Any, list[tuple[dict[str, Any], str]]], Any]",
        description: str,
    ) -> None:
        """Run a generic item processing loop with concurrency, progress,
        checkpoint, and optional validation.

        ``process_func`` is an async callable ``(item, keys_to_validate) -> None``
        that extracts candidates from *item* and appends to ``keys_to_validate``.
        """
        if self.args.dry_run:
            logger.info("[Dry run] %s items for %s", len(items), provider)
            return

        keys_to_validate: list[tuple[dict[str, Any], str]] = []

        async def _wrapped(item: Any) -> None:
            async with self.semaphore:
                try:
                    await process_func(item, keys_to_validate)
                except Exception as exc:
                    logger.debug("Item processing failed for %s: %s", provider, exc)

        tasks = [asyncio.create_task(_wrapped(item)) for item in items]
        iterator = asyncio.as_completed(tasks)
        if tqdm:
            iterator = tqdm(iterator, total=len(tasks), desc=description)
        for coro in iterator:
            try:
                await coro
            except Exception as exc:  # pragma: no cover - defensive (wrapped above)
                logger.debug("Task failed for %s: %s", provider, exc)

        if self.args.validate and keys_to_validate:
            logger.info("Validating %s %s keys...", len(keys_to_validate), provider)
            await self.batch_validate_keys(keys_to_validate, provider)

        self.save_progress_locked()
        logger.info(
            "Completed %s: %s keys found (session), %s total unique keys overall",
            description,
            self._provider_found_count.get(provider, 0),
            len(self.progress.found_keys),
        )

    def log_content_cache(self) -> None:
        """Report cache effectiveness once the scan is done."""
        hits, misses, entries = self.content_cache_stats()
        if misses == 0:
            return
        total = hits + misses
        logger.info(
            "File content cache: %s/%s requests served from cache (%.0f%%), %s entries",
            hits,
            total,
            100.0 * hits / total,
            entries,
        )

    # ------------------------------------------------------------------
    # Scan modes
    # ------------------------------------------------------------------
    async def audit_api_keys(self, provider: str, query: str, pattern: str) -> None:
        """GitHub code search mode."""
        logger.info("Auditing %s API keys...", provider)

        # Sync rate-limit bucket with GitHub's actual remaining quota
        await self._fetch_initial_rate_limit()

        all_items: list[dict[str, Any]] = []

        page = 1
        while True:
            results = await self.search_github_code(query, page)
            if not results or "items" not in results:
                break
            items = results["items"]
            if not items:
                break

            filtered = [item for item in items if self.filter_repo(item)]
            all_items.extend(filtered)
            logger.info("Fetched page %s, got %s filtered code hits", page, len(filtered))

            if len(items) < 100:
                break
            page += 1
            if self.args.max_pages and page > self.args.max_pages:
                logger.info("Reached max pages limit: %s", self.args.max_pages)
                break

        async def process_item(
            item: dict[str, Any],
            keys_to_validate: list[tuple[dict[str, Any], str]],
        ) -> None:
            repo = item["repository"]["full_name"]
            path = item["path"]
            # Blob SHA keys the content cache, so an edited file is re-fetched
            # rather than served stale from an earlier provider's pass.
            blob_sha = item.get("sha") or ""
            identifier = f"{provider}/{repo}/{path}"

            if not self._is_recent_enough(repo_updated_at=item["repository"].get("updated_at", "")):
                return

            async with self.lock:
                if self.progress.is_processed(identifier):
                    return

            content = await self.get_file_content(repo, path, blob_sha)
            if not content:
                async with self.lock:
                    self.progress.mark_processed(identifier)
                return

            local_candidates = self.extract_candidates(content, pattern)

            async with self.lock:
                for key, _context, confidence, severity, line_no, col_no in local_candidates:
                    key_hash = fingerprint_key(key)
                    key_data: dict[str, Any] = {
                        "provider": provider,
                        "key_hash": key_hash,
                        "key_masked": mask_key(key),
                        "repo": repo,
                        "path": path,
                        "url": item.get("html_url") or f"https://github.com/{repo}/blob/{path}",
                        "line": line_no,
                        "column": col_no,
                        "timestamp": safe_utc_now(),
                        "confidence": round(confidence, 2),
                        "severity": severity,
                        "valid": None,
                    }
                    if self.args.store_raw_keys:
                        key_data["key"] = key
                    # add_key merges repeat sightings of the same secret into
                    # one finding with a growing locations list, so no
                    # pre-filter here: a second sighting still counts as a hit.
                    self.progress.add_key(key_data)
                    self._incr_stat(provider, repo)
                    keys_to_validate.append((key_data, key))
                # Must match the other three scan modes. Without this the
                # identifier is never recorded on the success path, so
                # --resume re-fetches every file the checkpoint covers.
                self.progress.mark_processed(identifier)
                self._checkpoint_if_due()

        await self._run_item_loop(
            all_items,
            provider,
            pattern,
            process_item,
            description=f"Auditing {provider}",
        )

    async def audit_commit_messages(self, provider: str, query: str, pattern: str) -> None:
        """GitHub commit-message search mode."""
        logger.info("Auditing %s API keys in commit messages...", provider)

        # Sync rate-limit bucket with GitHub's actual remaining quota
        await self._fetch_initial_rate_limit()

        all_items: list[dict[str, Any]] = []

        page = 1
        while True:
            results = await self.search_github_commits(query, page)
            if not results or "items" not in results:
                break
            items = results["items"]
            if not items:
                break

            filtered = [item for item in items if self.filter_repo(item)]
            all_items.extend(filtered)
            logger.info("Fetched page %s, got %s filtered commits", page, len(filtered))

            if len(items) < 100:
                break
            page += 1
            if self.args.max_pages and page > self.args.max_pages:
                logger.info("Reached max pages limit: %s", self.args.max_pages)
                break

        async def process_commit(
            item: dict[str, Any],
            keys_to_validate: list[tuple[dict[str, Any], str]],
        ) -> None:
            repo = item["repository"]["full_name"]
            commit_sha = item["sha"]
            commit_msg = item.get("commit", {}).get("message", "")
            commit_date = item.get("commit", {}).get("author", {}).get("date", "") or item.get(
                "commit", {}
            ).get("committer", {}).get("date", "")
            identifier = f"{provider}/{repo}/commit/{commit_sha}"

            if not self._is_recent_enough(
                repo_updated_at=item["repository"].get("updated_at", ""),
                commit_date=commit_date,
            ):
                return

            async with self.lock:
                if self.progress.is_processed(identifier):
                    return

            local_candidates = self.extract_candidates(commit_msg, pattern)

            async with self.lock:
                for key, _context, confidence, severity, line_no, col_no in local_candidates:
                    key_hash = fingerprint_key(key)
                    key_data: dict[str, Any] = {
                        "provider": provider,
                        "key_hash": key_hash,
                        "key_masked": mask_key(key),
                        "repo": repo,
                        "commit": commit_sha,
                        "url": item.get("html_url")
                        or f"https://github.com/{repo}/commit/{commit_sha}",
                        "message": commit_msg[:120],
                        "line": line_no,
                        "column": col_no,
                        "timestamp": safe_utc_now(),
                        "confidence": round(confidence, 2),
                        "severity": severity,
                        "valid": None,
                    }
                    if self.args.store_raw_keys:
                        key_data["key"] = key
                    self.progress.add_key(key_data)
                    self._incr_stat(provider, repo)
                    keys_to_validate.append((key_data, key))
                self.progress.mark_processed(identifier)
                self._checkpoint_if_due()

        await self._run_item_loop(
            all_items,
            provider,
            pattern,
            process_commit,
            description=f"Auditing {provider} commits",
        )

    async def audit_git_history(self, provider: str, pattern: str, directory: str) -> None:
        """Scan local git commit history across all branches.

        Thin wrapper over :meth:`audit_git_history_combined` so both entry
        points share one implementation and cannot drift.
        """
        await self.audit_git_history_combined([(provider, "", pattern)], directory)

    async def audit_git_history_combined(
        self,
        providers: list[tuple[str, str, str]],
        directory: str,
    ) -> None:
        """Scan git history once, applying every provider pattern per commit.

        The per-provider path re-ran ``git log --all`` and re-ran ``git show``
        for every commit once *per provider*, so N providers cost N git log
        invocations and (commits x N) git show subprocesses. This reads the
        commit list and each diff once and applies all patterns to it.

        *providers* is a list of ``(display_name, search_prefix, pattern)``
        tuples, i.e. the values of :data:`auditor.patterns.PROVIDER_CONFIGS`.
        Only the search prefix is ignored here; local scans match on pattern.

        Findings, stats, checkpoints, and validation stay per provider, so
        ``--providers`` semantics and ``--resume`` are unchanged.
        """
        if not providers:
            return

        logger.info(
            "Auditing %s API keys in git history: %s",
            ", ".join(entry[0] for entry in providers),
            directory,
        )
        dir_path = Path(directory).resolve()
        git_dir = dir_path / ".git"
        if not git_dir.is_dir():
            logger.error("Not a git repository: %s", directory)
            return

        # One shared `git log` for all providers. Key extraction, findings, and
        # checkpoints stay per provider.
        commits = await self._git_log(dir_path)
        if commits is None:
            return
        if not commits:
            logger.info("No commits found in %s", directory)
            return

        if self.args.dry_run:
            logger.info(
                "[Dry run] %s items for %s",
                len(commits),
                ", ".join(entry[0] for entry in providers),
            )
            return

        compiled = self._compile_providers(providers)
        if not compiled:
            return

        # Keys are bucketed by provider index so validation stays grouped the
        # way batch_validate_keys expects.
        keys_to_validate: dict[int, list[tuple[dict[str, Any], str]]] = {}
        processed_any = False

        for commit in commits:
            sha = commit["sha"]
            if not re.fullmatch(r"[0-9a-fA-F]{7,40}", sha):
                logger.warning("Invalid commit SHA: %s", sha)
                continue

            # Only fetch the diff if some provider still needs this commit.
            targets = [
                (idx, provider_name)
                for idx, (provider_name, _rx) in enumerate(compiled)
                if not self.progress.is_processed(f"{provider_name}/git-history/{sha}")
            ]
            if not targets:
                continue

            diff_text = await self._git_show(dir_path, sha)
            if diff_text is None:
                # Unreadable commit: mark it done for every provider that wanted
                # it, so a resume does not retry a broken commit.
                async with self.lock:
                    for _idx, provider_name in targets:
                        self.progress.mark_processed(f"{provider_name}/git-history/{sha}")
                continue

            for idx, provider_name in targets:
                local_candidates = self.extract_candidates(diff_text, compiled[idx][1].pattern)

                async with self.lock:
                    bucket = keys_to_validate.setdefault(idx, [])
                    for key, _context, confidence, severity, line_no, col_no in local_candidates:
                        key_hash = fingerprint_key(key)
                        key_data: dict[str, Any] = {
                            "provider": provider_name,
                            "key_hash": key_hash,
                            "key_masked": mask_key(key),
                            "repo": "local (git history)",
                            "path": f"commit/{sha}",
                            "url": f"file://{dir_path}",
                            "commit": sha,
                            "author": commit["author"],
                            "date": commit["date"][:10],
                            "message": commit["subject"][:120],
                            "line": line_no,
                            "column": col_no,
                            "timestamp": safe_utc_now(),
                            "confidence": round(confidence, 2),
                            "severity": severity,
                            "valid": None,
                        }
                        if self.args.store_raw_keys:
                            key_data["key"] = key
                        self.progress.add_key(key_data)
                        self._incr_stat(provider_name, "local (git)")
                        bucket.append((key_data, key))
                    self.progress.mark_processed(f"{provider_name}/git-history/{sha}")
                    self._checkpoint_if_due()
            processed_any = True

        if self.args.validate:
            for idx, (provider_name, _rx) in enumerate(compiled):
                bucket = keys_to_validate.get(idx, [])
                if bucket:
                    logger.info("Validating %s %s keys...", len(bucket), provider_name)
                    await self.batch_validate_keys(bucket, provider_name)

        if processed_any:
            logger.info(
                "Completed Git history: %s commit(s) across %s provider(s)",
                len(commits),
                len(compiled),
            )
        self.save_progress_locked()

    @staticmethod
    def _compile_providers(
        providers: list[tuple[str, str, str]],
    ) -> list[tuple[str, re.Pattern[str]]]:
        """Pair each provider with its compiled pattern, skipping bad regexes.

        Shared by the combined local and git-history scans so an uncompilable
        pattern drops the provider (rather than misaligning indices) in both.
        """
        compiled: list[tuple[str, re.Pattern[str]]] = []
        for provider_name, _search_prefix, pattern in providers:
            try:
                pattern_obj = _PATTERN_CACHE.get(pattern)
                if pattern_obj is None:
                    pattern_obj = re.compile(pattern)
                    _PATTERN_CACHE[pattern] = pattern_obj
            except re.error as exc:
                logger.warning("Invalid regex pattern skipped: %s (%s)", pattern, exc)
                continue
            compiled.append((provider_name, pattern_obj))
        return compiled

    async def _git_log(self, dir_path: Path) -> list[dict[str, str]] | None:
        """Return every commit on every branch, or None if git could not run."""
        try:
            process = await asyncio.create_subprocess_exec(
                "git",
                "-c",
                "core.fsmonitor=",
                "-c",
                "diff.external=",
                "log",
                "--all",
                "--format=%H%x00%an%x00%ae%x00%aI%x00%s",
                "--reverse",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(dir_path),
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    process.communicate(), timeout=120
                )
            except TimeoutError:
                process.kill()
                await process.communicate()
                logger.error("git log timed out (large repository?)")
                return None

            if process.returncode != 0:
                logger.error(
                    "git log failed: %s", stderr_bytes.decode("utf-8", errors="replace").strip()
                )
                return None
            raw_log = stdout_bytes.decode("utf-8", errors="replace").strip()
        except FileNotFoundError:
            logger.error("git executable not found on PATH")
            return None

        commits: list[dict[str, str]] = []
        for line in raw_log.splitlines():
            parts = line.split("\x00", 4)
            if len(parts) == 5:
                commits.append(
                    {
                        "sha": parts[0],
                        "author": parts[1],
                        "author_email": parts[2],
                        "date": parts[3],
                        "subject": parts[4],
                    }
                )
        return commits

    async def _git_show(self, dir_path: Path, sha: str) -> str | None:
        """Return one commit's diff, or None if it could not be read."""
        try:
            process = await asyncio.create_subprocess_exec(
                "git",
                "-c",
                "core.fsmonitor=",
                "-c",
                "diff.external=",
                "show",
                "--no-ext-diff",
                "--format=",
                sha,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(dir_path),
            )
            try:
                stdout_bytes, _ = await asyncio.wait_for(process.communicate(), timeout=30)
            except TimeoutError:
                process.kill()
                await process.communicate()
                logger.warning("git show timed out for %s", sha)
                return None
            return stdout_bytes.decode("utf-8", errors="replace")
        except FileNotFoundError:
            return None
