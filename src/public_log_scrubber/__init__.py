"""Small, dependency-free helpers for scrubbing shareable logs."""

from .core import (
    DEFAULT_REPLACEMENT,
    DEFAULT_SENSITIVE_KEYS,
    ScrubResult,
    is_sensitive_key,
    scrub_json,
    scrub_text,
)

__all__ = [
    "DEFAULT_REPLACEMENT",
    "DEFAULT_SENSITIVE_KEYS",
    "ScrubResult",
    "is_sensitive_key",
    "scrub_json",
    "scrub_text",
]

__version__ = "0.1.0"
