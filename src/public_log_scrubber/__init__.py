"""Small, dependency-free helpers for scrubbing shareable logs."""

from .core import (
    DEFAULT_REPLACEMENT,
    DEFAULT_SENSITIVE_KEYS,
    KNOWN_RULE_IDS,
    ScrubPolicy,
    ScrubResult,
    is_sensitive_key,
    scrub_json,
    scrub_lines,
    scrub_text,
)

__all__ = [
    "DEFAULT_REPLACEMENT",
    "DEFAULT_SENSITIVE_KEYS",
    "KNOWN_RULE_IDS",
    "ScrubPolicy",
    "ScrubResult",
    "is_sensitive_key",
    "scrub_json",
    "scrub_lines",
    "scrub_text",
]

__version__ = "0.2.0"
