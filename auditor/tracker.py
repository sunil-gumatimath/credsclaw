"""Checkpoint / resume progress tracking."""

import contextlib
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

from auditor.scoring import fingerprint_key, mask_key
from auditor.utils import safe_utc_now

logger = logging.getLogger(__name__)


class ProgressTracker:
    """Tracks processed items, found keys, and checkpoint/resume state."""

    def __init__(
        self,
        checkpoint_file: str = "output/progress.json",
        store_raw_keys: bool = False,
    ) -> None:
        self.checkpoint_file = checkpoint_file
        self.store_raw_keys = store_raw_keys
        self.processed: set[str] = set()
        self.found_keys: list[dict[str, Any]] = []
        self.seen_hashes: set[str] = set()
        self.checkpoint_timestamp: str | None = None
        # Locations per key hash, so a secret reused across repos/files is
        # reported once with every occurrence retained (see add_key).
        self.locations_by_hash: dict[str, list[dict[str, Any]]] = {}
        self.load_progress()

    @staticmethod
    def _location_of(key_data: dict[str, Any]) -> dict[str, Any]:
        """Extract the identifying fields that make a finding's location."""
        loc: dict[str, Any] = {
            "repo": key_data.get("repo", ""),
            "path": key_data.get("path", ""),
        }
        if key_data.get("commit"):
            loc["commit"] = key_data["commit"]
        if key_data.get("line") is not None:
            loc["line"] = key_data["line"]
        return loc

    def load_progress(self) -> None:
        path = Path(self.checkpoint_file)
        if not path.exists():
            return
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            self.processed = set(data.get("processed", []))
            self.found_keys = data.get("found_keys", [])
            self.checkpoint_timestamp = data.get("timestamp")

            # Populate seen_hashes from seen_keys (new format) or found_keys (legacy).
            for item in data.get("seen_keys", []):
                key_hash = item.get("key_hash")
                if key_hash:
                    self.seen_hashes.add(key_hash)

            # Backfill hashes from found_keys for backward compat with older checkpoints.
            for item in self.found_keys:
                if not self.store_raw_keys:
                    item.pop("key", None)
                if item.get("key_hash"):
                    self.seen_hashes.add(item["key_hash"])
                elif item.get("key"):
                    item["key_hash"] = fingerprint_key(item["key"])
                    item["key_masked"] = mask_key(item["key"])
                    self.seen_hashes.add(item["key_hash"])
                # Rehydrate per-location tracking from checkpoints written
                # before occurrences existed.
                key_hash = item.get("key_hash")
                if key_hash:
                    locations = item.get("locations")
                    if not locations:
                        locations = [self._location_of(item)]
                        item["locations"] = locations
                    item.setdefault("occurrences", len(locations))
                    self.locations_by_hash.setdefault(key_hash, list(locations))

            logger.info(
                "Resumed: %s items processed, %s keys found",
                len(self.processed),
                len(self.found_keys),
            )
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            logger.error("Failed to load progress (format error): %s", exc)
        except OSError as exc:
            logger.warning("Failed to read progress file %s: %s", path, exc)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Unexpected error loading progress: %s", exc, exc_info=True)

    def save_progress(self) -> None:
        try:
            structured_seen = [{"key_hash": key_hash} for key_hash in sorted(self.seen_hashes)]
            serializable_keys = []
            for item in self.found_keys:
                entry = dict(item)
                if not self.store_raw_keys:
                    entry.pop("key", None)
                serializable_keys.append(entry)

            payload = {
                "processed": sorted(self.processed),
                "found_keys": serializable_keys,
                "seen_keys": structured_seen,
                "timestamp": safe_utc_now(),
            }

            path = Path(self.checkpoint_file)
            path.parent.mkdir(parents=True, exist_ok=True)

            tmp_fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
            try:
                with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2)
                os.replace(tmp_path, str(path))
                # Restrict checkpoint to owner-only (contains key hashes/masks).
                with contextlib.suppress(OSError):
                    os.chmod(path, 0o600)
            except Exception:
                # Clean up temporary file on failure.
                with contextlib.suppress(OSError):
                    os.unlink(tmp_path)
                raise
        except Exception as exc:
            logger.error("Failed to save progress: %s", exc)

    def is_processed(self, identifier: str) -> bool:
        return identifier in self.processed

    def mark_processed(self, identifier: str) -> None:
        self.processed.add(identifier)

    def is_duplicate_hash(self, key_hash: str) -> bool:
        return key_hash in self.seen_hashes

    def add_key(self, key_data: dict[str, Any]) -> None:
        """Register a finding, merging repeat sightings of the same secret.

        A secret that appears in five repositories is one secret, not five, so
        it is stored once. Each distinct location is appended to
        ``locations`` and ``occurrences`` is incremented, so the report can
        still say "this key leaked in 5 places" instead of silently reporting
        only the first.
        """
        key_hash = key_data["key_hash"]
        location = self._location_of(key_data)
        if key_hash not in self.seen_hashes:
            self.seen_hashes.add(key_hash)
            self.locations_by_hash[key_hash] = [location]
            key_data["locations"] = [location]
            key_data["occurrences"] = 1
            self.found_keys.append(key_data)
            return

        # Already known: record the extra location instead of dropping it.
        known = self.locations_by_hash.setdefault(key_hash, [])
        if location not in known:
            known.append(location)
        for entry in self.found_keys:
            if entry.get("key_hash") == key_hash:
                entry["locations"] = known
                entry["occurrences"] = len(known)
                break

    def occurrences(self, key_hash: str) -> int:
        """Number of distinct locations recorded for a key hash."""
        return len(self.locations_by_hash.get(key_hash, []))
