"""Core redaction functions.

The module deliberately has no network access and no third-party dependencies.
It is intended to be a useful last pass before logs are pasted into an issue,
chat, support ticket, or public gist.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

DEFAULT_REPLACEMENT = "[REDACTED]"

# These are normalized so callers may write access_token, access-token, or
# accessToken in their own JSON keys.
DEFAULT_SENSITIVE_KEYS = frozenset(
    {
        "apikey",
        "authorization",
        "clientsecret",
        "cookie",
        "password",
        "passwd",
        "privatekey",
        "refreshtoken",
        "secret",
        "session",
        "sessionid",
        "setcookie",
        "token",
        "accesstoken",
    }
)

_KEY_SEPARATOR_RE = re.compile(r"[^a-z0-9]+")

# Text patterns intentionally focus on high-signal credential shapes. This is
# not a general-purpose secret scanner and should not be treated as one.
_GITHUB_TOKEN_RE = re.compile(
    r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b"
)
_GITHUB_FINE_GRAINED_TOKEN_RE = re.compile(
    r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"
)
_AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_BEARER_RE = re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]{8,}")
_BASIC_RE = re.compile(r"(?i)(\bBasic\s+)[A-Za-z0-9+/]{8,}={0,2}")
_URL_PARAMETER_RE = re.compile(
    r"(?i)([?&](?:api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"password|secret|token)=)([^&#\s]+)"
)

_ASSIGNMENT_VALUE = (
    r'(?:"[^"]*"|\'[^\']*\'|(?:Bearer|Basic)\s+\S+|[^\s,;}\]&#]+)'
)
_DEFAULT_ASSIGNMENT_RE = re.compile(
    r"(?P<key>(?<![?&])\b(?:api[_ -]?key|access[_ -]?token|refresh[_ -]?token|"
    r"authorization|cookie|password|passwd|private[_ -]?key|secret|"
    r"session(?:[_ -]?id)?|set[_ -]?cookie|token)\b\s*[:=]\s*)"
    rf"(?P<value>{_ASSIGNMENT_VALUE})",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ScrubResult:
    """The scrubbed value and the number of replacements made."""

    value: Any
    replacements: int


def _normalize_key(key: Any) -> str:
    return _KEY_SEPARATOR_RE.sub("", str(key).lower())


def _sensitive_key_set(extra_keys: Iterable[str] = ()) -> frozenset[str]:
    return frozenset(DEFAULT_SENSITIVE_KEYS).union(
        _normalize_key(key) for key in extra_keys if str(key).strip()
    )


def is_sensitive_key(
    key: Any, sensitive_keys: Iterable[str] = DEFAULT_SENSITIVE_KEYS
) -> bool:
    """Return whether a JSON object key looks credential-like."""

    normalized = _normalize_key(key)
    configured = set(sensitive_keys)
    if normalized in configured:
        return True

    # Catch practical variants such as user_token without treating every
    # field ending in the generic word "key" as sensitive.
    return any(
        normalized.endswith(suffix) and len(normalized) > len(suffix) + 2
        for suffix in ("token", "password", "passwd", "secret")
    )


def _scrub_json_value(
    value: Any, sensitive_keys: frozenset[str], replacement: str
) -> tuple[Any, int]:
    if isinstance(value, Mapping):
        scrubbed: dict[Any, Any] = {}
        replacements = 0
        for key, child in value.items():
            if is_sensitive_key(key, sensitive_keys):
                scrubbed[key] = replacement
                replacements += 1
                continue
            scrubbed_child, child_replacements = _scrub_json_value(
                child, sensitive_keys, replacement
            )
            scrubbed[key] = scrubbed_child
            replacements += child_replacements
        return scrubbed, replacements

    if isinstance(value, list):
        scrubbed_list = []
        replacements = 0
        for child in value:
            scrubbed_child, child_replacements = _scrub_json_value(
                child, sensitive_keys, replacement
            )
            scrubbed_list.append(scrubbed_child)
            replacements += child_replacements
        return scrubbed_list, replacements

    return value, 0


def scrub_json(
    value: Any,
    *,
    extra_keys: Iterable[str] = (),
    replacement: str = DEFAULT_REPLACEMENT,
) -> ScrubResult:
    """Scrub credential-like values from a JSON-compatible Python value.

    The input is not mutated. Values under sensitive keys are replaced as a
    whole, including nested objects and arrays.
    """

    scrubbed, replacements = _scrub_json_value(
        value, _sensitive_key_set(extra_keys), replacement
    )
    return ScrubResult(scrubbed, replacements)


def _extra_assignment_pattern(extra_keys: Iterable[str]) -> re.Pattern[str] | None:
    names = [str(key).strip() for key in extra_keys if str(key).strip()]
    if not names:
        return None
    alternatives = "|".join(re.escape(name) for name in sorted(set(names)))
    return re.compile(
        rf"(?P<key>\b(?:{alternatives})\b\s*[:=]\s*)"
        rf"(?P<value>{_ASSIGNMENT_VALUE})",
        re.IGNORECASE,
    )


def _replace_assignment(match: re.Match[str], replacement: str) -> str:
    return f"{match.group('key')}{replacement}"


def scrub_text(
    text: str,
    *,
    extra_keys: Iterable[str] = (),
    replacement: str = DEFAULT_REPLACEMENT,
) -> ScrubResult:
    """Scrub high-signal credentials from plain text.

    Text redaction is intentionally conservative. It catches common token
    formats and key/value assignments, but it cannot guarantee that arbitrary
    secrets or personal data have been removed.
    """

    scrubbed = text
    replacements = 0

    scrubbed, count = _URL_PARAMETER_RE.subn(
        rf"\1{replacement}",
        scrubbed,
    )
    replacements += count

    scrubbed, count = _DEFAULT_ASSIGNMENT_RE.subn(
        lambda match: _replace_assignment(match, replacement),
        scrubbed,
    )
    replacements += count

    extra_pattern = _extra_assignment_pattern(extra_keys)
    if extra_pattern is not None:
        scrubbed, count = extra_pattern.subn(
            lambda match: _replace_assignment(match, replacement),
            scrubbed,
        )
        replacements += count

    for pattern, token_replacement in (
        (_GITHUB_FINE_GRAINED_TOKEN_RE, replacement),
        (_GITHUB_TOKEN_RE, replacement),
        (_AWS_ACCESS_KEY_RE, replacement),
        (_BEARER_RE, rf"\1{replacement}"),
        (_BASIC_RE, rf"\1{replacement}"),
    ):
        scrubbed, count = pattern.subn(token_replacement, scrubbed)
        replacements += count

    return ScrubResult(scrubbed, replacements)
