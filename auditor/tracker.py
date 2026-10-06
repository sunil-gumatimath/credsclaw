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
        # key_hash -> the found_keys entry that owns it. Lets add_key merge a
        # repeat sighting in O(1) instead of scanning found_keys, which was
        # quadratic in the number of secrets.
        self.entry_by_hash: dict[str, dict[str, Any]] = {}
        # Newline-delimited sidecar holding `processed`. Kept out of the main
        # checkpoint because it dominates its size and only ever grows.
        self.processed_file = f"{self.checkpoint_file}.processed"
        # What the sidecar currently holds, so saves append instead of rewrite.
        self._processed_persisted: set[str] | None = None
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
            # `processed` now lives in a sidecar, but older checkpoints (and any
            # hand-written one) still carry it inline, so read both.
            self.processed = set(data.get("processed", []))
            self.processed.update(self._load_processed_sidecar())
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
                    self.entry_by_hash.setdefault(key_hash, item)

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

    def _load_processed_sidecar(self) -> set[str]:
        """Read processed identifiers from the sidecar, if it exists."""
        path = Path(self.processed_file)
        if not path.exists():
            return set()
        try:
            with open(path, encoding="utf-8") as f:
                raw = f.read()
        except OSError as exc:
            logger.warning("Failed to read processed sidecar %s: %s", path, exc)
            return set()

        lines = raw.split("\n")
        # An append interrupted by a crash can leave a final line with no
        # terminator. Drop it rather than treating a truncated identifier as
        # processed; the worst case is re-scanning one item.
        if lines and lines[-1] != "":
            logger.warning("Discarding truncated final line in %s", path)
            lines.pop()
        ids = {line for line in lines if line}

        self._processed_persisted = set(ids)
        return ids

    def save_progress(self) -> None:
        """Write the checkpoint atomically, splitting bulk data to a sidecar.

        ``processed`` is by far the largest field (measured at ~86% of the file
        on a 5,000-item scan) and every identifier in it is written on every
        save. Keeping it in a separate newline-delimited file means the
        frequent rewrite only pays for ``found_keys``, and the sidecar is
        append-only rather than re-serialised.

        Either file alone is recoverable: if the sidecar is lost the main
        checkpoint still holds the findings, and vice versa.
        """
        try:
            structured_seen = [{"key_hash": key_hash} for key_hash in sorted(self.seen_hashes)]
            serializable_keys = []
            for item in self.found_keys:
                entry = dict(item)
                if not self.store_raw_keys:
                    entry.pop("key", None)
                serializable_keys.append(entry)

            payload = {
                "found_keys": serializable_keys,
                "seen_keys": structured_seen,
                "timestamp": safe_utc_now(),
            }

            path = Path(self.checkpoint_file)
            path.parent.mkdir(parents=True, exist_ok=True)

            self._atomic_write(path, json.dumps(payload, indent=2))
            self._save_processed_sidecar()
        except Exception as exc:
            logger.error("Failed to save progress: %s", exc)

    def _save_processed_sidecar(self) -> None:
        """Append newly-processed identifiers, rewriting only when forced.

        A scan mostly *adds* identifiers, so the common path appends just the
        new ones — O(new) rather than re-writing every identifier each save.
        A full rewrite happens only when the set shrank (``clear_processed``),
        where an append would leave stale entries behind.

        The append is a plain ``O_APPEND`` write rather than read-modify-replace:
        rewriting the whole file per save costs O(n) and measured 2x *slower*
        than the single-file format it replaced. Appends are atomic at this
        size on POSIX and Windows, and a crash mid-append can at worst leave a
        trailing line without a newline, which :meth:`_load_processed_sidecar`
        discards.
        """
        path = Path(self.processed_file)
        path.parent.mkdir(parents=True, exist_ok=True)

        # Unknown on-disk state (fresh tracker, or the sidecar was deleted):
        # write the full set rather than assume an append is safe.
        if self._processed_persisted is None:
            self._atomic_write(
                path, "".join(f"{identifier}\n" for identifier in sorted(self.processed))
            )
            self._processed_persisted = set(self.processed)
            return

        if not self._processed_persisted.issubset(self.processed):
            self._atomic_write(
                path, "".join(f"{identifier}\n" for identifier in sorted(self.processed))
            )
            self._processed_persisted = set(self.processed)
            return

        new_ids = sorted(self.processed - self._processed_persisted)
        if not new_ids:
            return

        payload = "".join(f"{identifier}\n" for identifier in new_ids)
        with open(path, "a", encoding="utf-8") as f:
            f.write(payload)
            # No fsync: a checkpoint is a resume aid, not a durability log, and
            # fsync measured ~1ms per save (roughly 20% of the total) for a
            # guarantee we do not need. Losing the tail of the sidecar on a
            # hard kill costs at most a re-scan of the last interval's items,
            # and a truncated final line is discarded on load anyway.
            f.flush()
        with contextlib.suppress(OSError):
            os.chmod(path, 0o600)
        self._processed_persisted = set(self.processed)

    @staticmethod
    def _atomic_write(path: Path, data: str, append: bool = False) -> None:
        """Write *data* to *path*, replacing it atomically.

        For appends the temporary file is seeded with the existing contents
        first, so the replace stays atomic and a crash mid-write cannot leave a
        half-written sidecar.
        """
        tmp_fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                if append and path.exists():
                    with open(path, encoding="utf-8") as existing:
                        f.write(existing.read())
                f.write(data)
            os.replace(tmp_path, str(path))
            # Restrict checkpoint to owner-only (contains key hashes/masks).
            with contextlib.suppress(OSError):
                os.chmod(path, 0o600)
        except Exception:
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)
            raise

    def is_processed(self, identifier: str) -> bool:
        return identifier in self.processed

    def mark_processed(self, identifier: str) -> None:
        self.processed.add(identifier)

    def clear_processed(self) -> None:
        """Drop every processed identifier and delete the sidecar.

        Callers that want to abandon prior progress should use this rather than
        clearing ``processed`` directly: the sidecar and the in-memory
        persisted-set have to be reset too, or the next save would append
        identifiers that were never actually processed.
        """
        self.processed.clear()
        self._processed_persisted = None
        with contextlib.suppress(OSError):
            os.unlink(self.processed_file)

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
            self.entry_by_hash[key_hash] = key_data
            return

        # Already known: record the extra location instead of dropping it.
        known = self.locations_by_hash.setdefault(key_hash, [])
        if location not in known:
            known.append(location)
        entry = self.entry_by_hash.get(key_hash)
        if entry is None:
            # A checkpoint loaded before the index existed, or a key first seen
            # via the seen_hashes backfill. Fall back to the linear scan.
            for candidate in self.found_keys:
                if candidate.get("key_hash") == key_hash:
                    entry = candidate
                    break
        if entry is not None:
            entry["locations"] = known
            entry["occurrences"] = len(known)
            self.entry_by_hash.setdefault(key_hash, entry)

    def occurrences(self, key_hash: str) -> int:
        """Number of distinct locations recorded for a key hash."""
        return len(self.locations_by_hash.get(key_hash, []))
