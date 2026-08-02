"""Core redaction functions.

The module deliberately has no network access and no third-party dependencies.
It is intended to be a useful last pass before logs are pasted into an issue,
chat, support ticket, or public gist.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
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

RULE_JSON_SENSITIVE_KEY = "json-sensitive-key"
RULE_CUSTOM_KEY = "custom-key"
RULE_URL_PARAMETER = "url-sensitive-parameter"
RULE_ASSIGNMENT = "assignment-sensitive-key"
RULE_GITHUB_TOKEN = "github-token"
RULE_GITHUB_FINE_GRAINED_TOKEN = "github-fine-grained-token"
RULE_AWS_ACCESS_KEY = "aws-access-key"
RULE_BEARER_TOKEN = "bearer-token"
RULE_BASIC_CREDENTIALS = "basic-credentials"
RULE_JWT = "jwt"
RULE_OPENAI_KEY = "openai-key"
RULE_SLACK_TOKEN = "slack-token"
RULE_GITLAB_TOKEN = "gitlab-token"
RULE_STRIPE_KEY = "stripe-key"
RULE_DATABASE_URL_PASSWORD = "database-url-password"

KNOWN_RULE_IDS = frozenset(
    {
        RULE_JSON_SENSITIVE_KEY,
        RULE_CUSTOM_KEY,
        RULE_URL_PARAMETER,
        RULE_ASSIGNMENT,
        RULE_GITHUB_TOKEN,
        RULE_GITHUB_FINE_GRAINED_TOKEN,
        RULE_AWS_ACCESS_KEY,
        RULE_BEARER_TOKEN,
        RULE_BASIC_CREDENTIALS,
        RULE_JWT,
        RULE_OPENAI_KEY,
        RULE_SLACK_TOKEN,
        RULE_GITLAB_TOKEN,
        RULE_STRIPE_KEY,
        RULE_DATABASE_URL_PASSWORD,
    }
)

_KEY_SEPARATOR_RE = re.compile(r"[^a-z0-9]+")

# URL parameter names are kept explicit so a generic parameter such as
# ``id`` is never treated as a credential merely because it is configurable.
_DEFAULT_URL_PARAMETER_NAMES = (
    "api_key",
    "apikey",
    "access_token",
    "accesstoken",
    "authorization",
    "client_secret",
    "clientsecret",
    "cookie",
    "password",
    "passwd",
    "private_key",
    "privatekey",
    "refresh_token",
    "refreshtoken",
    "secret",
    "session",
    "session_id",
    "sessionid",
    "set_cookie",
    "setcookie",
    "token",
)

_DEFAULT_ASSIGNMENT_KEY_PATTERN = (
    r"(?:api[_ -]?key|access[_ -]?token|refresh[_ -]?token|"
    r"authorization|client[_ -]?secret|cookie|password|passwd|"
    r"private[_ -]?key|secret|session(?:[_ -]?id)?|set[_ -]?cookie|token)"
)

_ASSIGNMENT_VALUE = (
    r'(?:(?:"[^"]*")|(?:\'[^\']*\')|(?:Bearer|Basic)\s+\S+|'
    r"[^\s,;}\]&#]+)"
)

# Text patterns intentionally focus on high-signal credential shapes. This is
# not a general-purpose secret scanner and should not be treated as one.
_GITHUB_TOKEN_RE = re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b")
_GITHUB_FINE_GRAINED_TOKEN_RE = re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")
_AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_BEARER_RE = re.compile(r"(?i)(?P<prefix>\bBearer\s+)[A-Za-z0-9._~+/=-]{8,}")
_BASIC_RE = re.compile(r"(?i)(?P<prefix>\bBasic\s+)[A-Za-z0-9+/]{8,}={0,2}")
_JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}\."
    r"[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}(?![A-Za-z0-9_-])"
)
_OPENAI_KEY_RE = re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")
_SLACK_TOKEN_RE = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")
_GITLAB_TOKEN_RE = re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")
_STRIPE_KEY_RE = re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")
_DATABASE_URL_RE = re.compile(
    r"(?i)(?P<prefix>\b(?:postgres(?:ql)?|mysql|mariadb|"
    r"mongodb(?:\+srv)?|redis|amqp)://[^/\s:@]+:)"
    r"(?P<value>[^@\s/]+)(?=@)"
)

_TOKEN_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (RULE_GITHUB_FINE_GRAINED_TOKEN, _GITHUB_FINE_GRAINED_TOKEN_RE),
    (RULE_GITHUB_TOKEN, _GITHUB_TOKEN_RE),
    (RULE_AWS_ACCESS_KEY, _AWS_ACCESS_KEY_RE),
    (RULE_JWT, _JWT_RE),
    (RULE_OPENAI_KEY, _OPENAI_KEY_RE),
    (RULE_SLACK_TOKEN, _SLACK_TOKEN_RE),
    (RULE_GITLAB_TOKEN, _GITLAB_TOKEN_RE),
    (RULE_STRIPE_KEY, _STRIPE_KEY_RE),
    (RULE_DATABASE_URL_PASSWORD, _DATABASE_URL_RE),
    (RULE_BEARER_TOKEN, _BEARER_RE),
    (RULE_BASIC_CREDENTIALS, _BASIC_RE),
)


@dataclass(frozen=True)
class ScrubPolicy:
    """Immutable policy controlling a scrubbing operation.

    ``extra_sensitive_keys`` uses the same normalization rules as the legacy
    ``extra_keys`` function argument. Rule IDs in ``disabled_rules`` are
    stable and are exposed through :data:`KNOWN_RULE_IDS`.
    """

    replacement: str = DEFAULT_REPLACEMENT
    extra_sensitive_keys: tuple[str, ...] = ()
    disabled_rules: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.replacement, str) or not self.replacement:
            raise ValueError("replacement must be a non-empty string")

        if isinstance(self.extra_sensitive_keys, str):
            raise TypeError("extra_sensitive_keys must be an iterable of strings")
        try:
            extra_keys = tuple(self.extra_sensitive_keys)
        except TypeError as exc:
            raise TypeError(
                "extra_sensitive_keys must be an iterable of strings"
            ) from exc
        if any(not isinstance(key, str) or not key.strip() for key in extra_keys):
            raise ValueError("extra_sensitive_keys must contain non-empty strings")
        object.__setattr__(self, "extra_sensitive_keys", extra_keys)

        if isinstance(self.disabled_rules, str):
            raise TypeError("disabled_rules must be an iterable of rule IDs")
        try:
            disabled_rules = tuple(self.disabled_rules)
        except TypeError as exc:
            raise TypeError("disabled_rules must be an iterable of rule IDs") from exc
        if any(not isinstance(rule, str) for rule in disabled_rules):
            raise ValueError("disabled_rules must contain strings")
        unknown = sorted(set(disabled_rules) - KNOWN_RULE_IDS)
        if unknown:
            raise ValueError(f"unknown detector rule ID: {unknown[0]}")
        object.__setattr__(self, "disabled_rules", tuple(sorted(set(disabled_rules))))


@dataclass(frozen=True)
class ScrubResult:
    """The scrubbed value, replacement count, and safe rule counts."""

    value: Any
    replacements: int
    rule_counts: Mapping[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        counts = {str(rule): int(count) for rule, count in self.rule_counts.items()}
        object.__setattr__(self, "rule_counts", MappingProxyType(counts))


def _normalize_key(key: Any) -> str:
    return _KEY_SEPARATOR_RE.sub("", str(key).lower())


def _legacy_extra_keys(extra_keys: Iterable[str]) -> tuple[str, ...]:
    if isinstance(extra_keys, str):
        extra_keys = (extra_keys,)
    return tuple(str(key).strip() for key in extra_keys if str(key).strip())


def _resolve_policy(
    policy: ScrubPolicy | None,
    extra_keys: Iterable[str],
    replacement: str,
) -> ScrubPolicy:
    legacy_keys = _legacy_extra_keys(extra_keys)
    if policy is not None and not legacy_keys and replacement == DEFAULT_REPLACEMENT:
        return policy
    if policy is None:
        return ScrubPolicy(
            replacement=replacement,
            extra_sensitive_keys=legacy_keys,
        )

    if not isinstance(policy, ScrubPolicy):
        raise TypeError("policy must be a ScrubPolicy instance")

    # The legacy default is indistinguishable from an omitted argument, which
    # lets a policy file control the replacement while preserving old callers.
    effective_replacement = (
        policy.replacement if replacement == DEFAULT_REPLACEMENT else replacement
    )
    return ScrubPolicy(
        replacement=effective_replacement,
        extra_sensitive_keys=policy.extra_sensitive_keys + legacy_keys,
        disabled_rules=policy.disabled_rules,
    )


def _sensitive_key_set(policy: ScrubPolicy) -> frozenset[str]:
    configured = {_normalize_key(key) for key in DEFAULT_SENSITIVE_KEYS}
    if RULE_CUSTOM_KEY not in policy.disabled_rules:
        configured.update(_normalize_key(key) for key in policy.extra_sensitive_keys)
    return frozenset(configured)


def _custom_key_set(policy: ScrubPolicy) -> frozenset[str]:
    if RULE_CUSTOM_KEY in policy.disabled_rules:
        return frozenset()
    return frozenset(_normalize_key(key) for key in policy.extra_sensitive_keys)


def _is_sensitive_key(normalized: str, configured: frozenset[str]) -> bool:
    if normalized in configured:
        return True

    # Catch practical variants such as user_token without treating every
    # field ending in the generic word "key" as sensitive.
    return any(
        normalized.endswith(suffix) and len(normalized) > len(suffix) + 2
        for suffix in ("token", "password", "passwd", "secret")
    )


def is_sensitive_key(
    key: Any, sensitive_keys: Iterable[str] = DEFAULT_SENSITIVE_KEYS
) -> bool:
    """Return whether a JSON object key looks credential-like."""

    configured = frozenset(_normalize_key(item) for item in sensitive_keys)
    return _is_sensitive_key(_normalize_key(key), configured)


def _increment(counts: dict[str, int], rule_id: str, amount: int = 1) -> None:
    counts[rule_id] = counts.get(rule_id, 0) + amount


def _result(value: Any, counts: Mapping[str, int]) -> ScrubResult:
    safe_counts = {rule: count for rule, count in counts.items() if count}
    return ScrubResult(value, sum(safe_counts.values()), safe_counts)


def _scrub_json_value(
    value: Any,
    sensitive_keys: frozenset[str],
    custom_keys: frozenset[str],
    policy: ScrubPolicy,
    counts: dict[str, int],
) -> Any:
    if isinstance(value, Mapping):
        scrubbed: dict[Any, Any] = {}
        for key, child in value.items():
            normalized = _normalize_key(key)
            if _is_sensitive_key(normalized, sensitive_keys):
                rule_id = (
                    RULE_CUSTOM_KEY
                    if normalized in custom_keys
                    and normalized not in DEFAULT_SENSITIVE_KEYS
                    else RULE_JSON_SENSITIVE_KEY
                )
                if rule_id not in policy.disabled_rules:
                    scrubbed[key] = policy.replacement
                    _increment(counts, rule_id)
                    continue
            scrubbed[key] = _scrub_json_value(
                child, sensitive_keys, custom_keys, policy, counts
            )
        return scrubbed

    if isinstance(value, list):
        return [
            _scrub_json_value(child, sensitive_keys, custom_keys, policy, counts)
            for child in value
        ]

    return value


def scrub_json(
    value: Any,
    *,
    extra_keys: Iterable[str] = (),
    replacement: str = DEFAULT_REPLACEMENT,
    policy: ScrubPolicy | None = None,
) -> ScrubResult:
    """Scrub credential-like values from a JSON-compatible Python value.

    The input is not mutated. Values under sensitive keys are replaced as a
    whole, including nested objects and arrays.
    """

    effective_policy = _resolve_policy(policy, extra_keys, replacement)
    counts: dict[str, int] = {}
    scrubbed = _scrub_json_value(
        value,
        _sensitive_key_set(effective_policy),
        _custom_key_set(effective_policy),
        effective_policy,
        counts,
    )
    return _result(scrubbed, counts)


def _assignment_pattern(extra_keys: Iterable[str]) -> re.Pattern[str]:
    names = [str(key).strip() for key in extra_keys if str(key).strip()]
    alternatives = [_DEFAULT_ASSIGNMENT_KEY_PATTERN]
    alternatives.extend(
        re.escape(name) for name in sorted(set(names), key=len, reverse=True)
    )
    return re.compile(
        r"(?<![A-Za-z0-9_?&])(?P<key_name>(?:"
        + "|".join(alternatives)
        + r"))(?P<separator>\s*[:=]\s*)"
        rf"(?P<value>{_ASSIGNMENT_VALUE})",
        re.IGNORECASE,
    )


def _url_parameter_pattern(extra_keys: Iterable[str]) -> re.Pattern[str]:
    names = list(_DEFAULT_URL_PARAMETER_NAMES)
    names.extend(str(key).strip() for key in extra_keys if str(key).strip())
    alternatives = "|".join(
        re.escape(name) for name in sorted(set(names), key=len, reverse=True)
    )
    return re.compile(
        rf"(?i)(?P<prefix>[?&](?:{alternatives})=)"
        r"(?P<value>[^&#\s]+)"
    )


def _replace_assignment(match: re.Match[str], replacement: str) -> str:
    return f"{match.group('key_name')}{match.group('separator')}{replacement}"


def _replace_prefixed(match: re.Match[str], replacement: str) -> str:
    return f"{match.group('prefix')}{replacement}"


def _substitute(
    text: str,
    pattern: re.Pattern[str],
    replacement: Any,
    rule_id: str,
    policy: ScrubPolicy,
    counts: dict[str, int],
) -> str:
    if rule_id in policy.disabled_rules:
        return text
    text, count = pattern.subn(replacement, text)
    if count:
        _increment(counts, rule_id, count)
    return text


def _scrub_text_with_policy(text: str, policy: ScrubPolicy) -> ScrubResult:
    scrubbed = text
    counts: dict[str, int] = {}
    custom_keys = (
        () if RULE_CUSTOM_KEY in policy.disabled_rules else policy.extra_sensitive_keys
    )

    scrubbed = _substitute(
        scrubbed,
        _url_parameter_pattern(custom_keys),
        lambda match: _replace_prefixed(match, policy.replacement),
        RULE_URL_PARAMETER,
        policy,
        counts,
    )

    assignment_pattern = _assignment_pattern(custom_keys)

    def replace_assignment(match: re.Match[str]) -> str:
        normalized = _normalize_key(match.group("key_name"))
        rule_id = (
            RULE_CUSTOM_KEY
            if normalized in _custom_key_set(policy)
            and normalized not in DEFAULT_SENSITIVE_KEYS
            else RULE_ASSIGNMENT
        )
        if rule_id in policy.disabled_rules:
            return match.group(0)
        _increment(counts, rule_id)
        return _replace_assignment(match, policy.replacement)

    if (
        RULE_ASSIGNMENT not in policy.disabled_rules
        or RULE_CUSTOM_KEY not in policy.disabled_rules
    ):
        scrubbed = assignment_pattern.sub(replace_assignment, scrubbed)

    for rule_id, pattern in _TOKEN_RULES:
        if rule_id in (
            RULE_BEARER_TOKEN,
            RULE_BASIC_CREDENTIALS,
            RULE_DATABASE_URL_PASSWORD,
        ):
            replacement_function = lambda match: _replace_prefixed(
                match, policy.replacement
            )
        else:
            replacement_function = lambda _match: policy.replacement
        scrubbed = _substitute(
            scrubbed,
            pattern,
            replacement_function,
            rule_id,
            policy,
            counts,
        )

    return _result(scrubbed, counts)


def scrub_text(
    text: str,
    *,
    extra_keys: Iterable[str] = (),
    replacement: str = DEFAULT_REPLACEMENT,
    policy: ScrubPolicy | None = None,
) -> ScrubResult:
    """Scrub high-signal credentials from plain text.

    Text redaction is intentionally conservative. It catches common token
    formats and key/value assignments, but it cannot guarantee that arbitrary
    secrets or personal data have been removed.
    """

    effective_policy = _resolve_policy(policy, extra_keys, replacement)
    return _scrub_text_with_policy(text, effective_policy)


def _split_line_ending(line: str) -> tuple[str, str]:
    if line.endswith("\r\n"):
        return line[:-2], "\r\n"
    if line.endswith(("\n", "\r")):
        return line[:-1], line[-1:]
    return line, ""


def scrub_lines(
    lines: Iterable[str],
    *,
    format: str,
    policy: ScrubPolicy | None = None,
    extra_keys: Iterable[str] = (),
    replacement: str = DEFAULT_REPLACEMENT,
) -> Iterator[ScrubResult]:
    """Lazily scrub text or JSON Lines input.

    JSONL line endings are preserved exactly. Blank JSONL lines are passed
    through unchanged. A malformed JSONL record raises ``ValueError`` after
    all preceding records have been yielded.
    """

    if format not in ("text", "jsonl"):
        raise ValueError("format must be 'text' or 'jsonl'")
    effective_policy = _resolve_policy(policy, extra_keys, replacement)

    if format == "text":
        for line in lines:
            yield _scrub_text_with_policy(line, effective_policy)
        return

    for line_number, line in enumerate(lines, start=1):
        body, ending = _split_line_ending(line)
        if not body.strip():
            yield ScrubResult(line, 0)
            continue
        try:
            value = json.loads(body)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON on line {line_number}: {exc.msg}") from exc
        result = scrub_json(value, policy=effective_policy)
        encoded = json.dumps(
            result.value,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        yield ScrubResult(encoded + ending, result.replacements, result.rule_counts)
