"""Dependency-free policy-file loading for the public API and CLI."""

from __future__ import annotations

import json
import os
from pathlib import Path

from .core import DEFAULT_REPLACEMENT, ScrubPolicy


def load_policy(path: str | os.PathLike[str]) -> ScrubPolicy:
    """Load and validate a JSON :class:`ScrubPolicy` file."""

    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid policy JSON: {exc.msg}") from exc

    if not isinstance(raw, dict):
        raise TypeError("policy must be a JSON object")

    allowed = {
        "replacement",
        "extra_sensitive_keys",
        "disabled_rules",
        "scan_json_strings",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ValueError(f"unknown policy field: {unknown[0]}")

    extra_keys = raw.get("extra_sensitive_keys", [])
    disabled_rules = raw.get("disabled_rules", [])
    if not isinstance(extra_keys, list):
        raise TypeError("extra_sensitive_keys must be a JSON array")
    if not isinstance(disabled_rules, list):
        raise TypeError("disabled_rules must be a JSON array")

    return ScrubPolicy(
        replacement=raw.get("replacement", DEFAULT_REPLACEMENT),
        extra_sensitive_keys=tuple(extra_keys),
        disabled_rules=tuple(disabled_rules),
        scan_json_strings=raw.get("scan_json_strings", True),
    )
