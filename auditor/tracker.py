"""Checkpoint / resume progress tracking."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from auditor.scoring import fingerprint_key, mask_key
from auditor.utils import safe_utc_now

logger = logging.getLogger(__name__)


class ProgressTracker:
    """Tracks processed items, found keys, and checkpoint/resume state."""

    def __init__(
        self,
        checkpoint_file: str = "output/progress.json",
        store_raw_keys: bool = False,
    ):
        self.checkpoint_file = checkpoint_file
        self.store_raw_keys = store_raw_keys
        self.processed: Set[str] = set()
        self.found_keys: List[Dict[str, Any]] = []
        self.seen_hashes: Set[str] = set()
        self.checkpoint_timestamp: Optional[str] = None
        self.load_progress()

    def load_progress(self) -> None:
        path = Path(self.checkpoint_file)
        if not path.exists():
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
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
                if item.get("key_hash"):
                    self.seen_hashes.add(item["key_hash"])
                elif item.get("key"):
                    item["key_hash"] = fingerprint_key(item["key"])
                    item["key_masked"] = mask_key(item["key"])
                    self.seen_hashes.add(item["key_hash"])
                    if not self.store_raw_keys:
                        item.pop("key", None)

            logger.info(
                "Resumed: %s items processed, %s keys found",
                len(self.processed),
                len(self.found_keys),
            )
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            logger.error("Failed to load progress (format error): %s", exc)
        except Exception as exc:
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
            import tempfile
            import os
            tmp_fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), suffix='.tmp')
            try:
                with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2)
                os.replace(tmp_path, str(path))
            except Exception:
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

    def add_key(self, key_data: Dict[str, Any]) -> None:
        key_hash = key_data["key_hash"]
        if key_hash not in self.seen_hashes:
            self.seen_hashes.add(key_hash)
            self.found_keys.append(key_data)
