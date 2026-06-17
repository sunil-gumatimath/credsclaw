"""Confidence scoring, entropy calculation, key masking / fingerprinting."""

import hashlib
import math
import re
from typing import Dict

from auditor.patterns import NOISE_SUBSTRINGS


def shannon_entropy(value: str) -> float:
    """Calculate Shannon entropy of a string (higher = more random)."""
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    length = len(value)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def calculate_char_diversity(value: str) -> float:
    """Ratio of unique characters to total length."""
    if not value:
        return 0.0
    return len(set(value)) / len(value)


def calculate_confidence_score(key: str, context: str, is_noise: bool) -> float:
    """Calculate confidence score (0-100) for a potential secret.

    Higher score = more likely to be a real API key.
    """
    # Entropy contribution (0-30 points)
    entropy = shannon_entropy(key)
    entropy_score = min(entropy / 4.5, 1.0) * 30.0

    # Context pattern contribution (0-25 points)
    secret_indicators = [
        r"api[_-]?key",
        r"secret[_-]?key",
        r"private[_-]?key",
        r"access[_-]?key",
        r"auth[_-]?token",
        r"bearer[_-]?token",
        r"password",
        r"passwd",
        r"pwd",
        r"token",
        r"credential",
        r"secret",
        r"apikey",
    ]
    context_lower = context.lower()
    context_matches = sum(
        1 for pattern in secret_indicators if re.search(pattern, context_lower)
    )
    context_score = min(context_matches / 2.0, 1.0) * 25.0

    # Noise filter penalty (0-20 points — zero if noisy, 20 if clean)
    noise_score = 0.0 if is_noise else 20.0

    # Length contribution (0-15 points)
    length = len(key)
    if length >= 32:
        length_score = 15.0
    elif length >= 24:
        length_score = 12.0
    elif length >= 16:
        length_score = 8.0
    elif length >= 8:
        length_score = 4.0
    else:
        length_score = 1.0

    # Character diversity (0-10 points)
    diversity_score = calculate_char_diversity(key) * 10.0

    score = entropy_score + context_score + noise_score + length_score + diversity_score
    return min(max(score, 0.0), 100.0)


def get_severity_level(score: float) -> str:
    """Map a confidence score to a severity label."""
    if score >= 80.0:
        return "CRITICAL"
    if score >= 60.0:
        return "HIGH"
    if score >= 40.0:
        return "MEDIUM"
    return "LOW"


def mask_key(value: str) -> str:
    """Return a masked preview (first 8 … last 4)."""
    if len(value) <= 12:
        return "***"
    return f"{value[:8]}...{value[-4:]}"


def fingerprint_key(value: str) -> str:
    """Return the SHA-256 hex digest of the key (for deduplication)."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
