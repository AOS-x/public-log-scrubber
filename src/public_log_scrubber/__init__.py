"""Small, dependency-free helpers for scrubbing shareable logs."""

from .core import (
    DEFAULT_REPLACEMENT,
    DEFAULT_SENSITIVE_KEYS,
    KNOWN_RULE_IDS,
    DetectionSpan,
    RuleInfo,
    Scrubber,
    ScrubPolicy,
    ScrubResult,
    TextDetector,
    is_sensitive_key,
    list_rules,
    scrub_json,
    scrub_lines,
    scrub_text,
)
from .integrations import ScrubbingFormatter
from .policy import load_policy

__all__ = [
    "DEFAULT_REPLACEMENT",
    "DEFAULT_SENSITIVE_KEYS",
    "KNOWN_RULE_IDS",
    "DetectionSpan",
    "RuleInfo",
    "ScrubPolicy",
    "ScrubResult",
    "Scrubber",
    "ScrubbingFormatter",
    "TextDetector",
    "is_sensitive_key",
    "list_rules",
    "load_policy",
    "scrub_json",
    "scrub_lines",
    "scrub_text",
]

__version__ = "0.3.0"
