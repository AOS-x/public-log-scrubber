"""Core redaction functions.

The module deliberately has no network access and no third-party dependencies.
It is intended to be a useful last pass before logs are pasted into an issue,
chat, support ticket, or public gist.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Generic, Protocol, TypeVar, runtime_checkable
from urllib.parse import unquote_plus

DEFAULT_REPLACEMENT = "[REDACTED]"
T = TypeVar("T")

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

_ASSIGNMENT_VALUE = (
    r'(?:(?:"[^"]*")|(?:\'[^\']*\')|'
    r"(?:Bearer|Basic)\s+[^\s,;}\]&#\"'()]+|"
    r"[^\s,;}\]&#\"'()]+)"
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
    scan_json_strings: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.replacement, str) or not self.replacement:
            raise ValueError("replacement must be a non-empty string")
        if not isinstance(self.scan_json_strings, bool):
            raise TypeError("scan_json_strings must be a boolean")

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
        if any(not _normalize_key(key) for key in extra_keys):
            raise ValueError("extra_sensitive_keys must contain usable key names")
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
class ScrubResult(Generic[T]):
    """The scrubbed value, replacement count, and safe rule counts."""

    value: T
    replacements: int
    rule_counts: Mapping[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        counts = {str(rule): int(count) for rule, count in self.rule_counts.items()}
        object.__setattr__(self, "rule_counts", MappingProxyType(counts))


def _normalize_key(key: Any) -> str:
    normalized = unicodedata.normalize("NFKC", str(key)).casefold()
    return "".join(character for character in normalized if character.isalnum())


def _legacy_extra_keys(extra_keys: Iterable[str]) -> tuple[str, ...]:
    if isinstance(extra_keys, str):
        extra_keys = (extra_keys,)
    keys = tuple(str(key).strip() for key in extra_keys if str(key).strip())
    if any(not _normalize_key(key) for key in keys):
        raise ValueError("extra_keys must contain usable key names")
    return keys


def _resolve_policy(
    policy: ScrubPolicy | None,
    extra_keys: Iterable[str],
    replacement: str,
) -> ScrubPolicy:
    if policy is not None and not isinstance(policy, ScrubPolicy):
        raise TypeError("policy must be a ScrubPolicy instance")
    legacy_keys = _legacy_extra_keys(extra_keys)
    if policy is not None and not legacy_keys and replacement == DEFAULT_REPLACEMENT:
        return policy
    if policy is None:
        return ScrubPolicy(
            replacement=replacement,
            extra_sensitive_keys=legacy_keys,
        )

    # The legacy default is indistinguishable from an omitted argument, which
    # lets a policy file control the replacement while preserving old callers.
    effective_replacement = (
        policy.replacement if replacement == DEFAULT_REPLACEMENT else replacement
    )
    return ScrubPolicy(
        replacement=effective_replacement,
        extra_sensitive_keys=policy.extra_sensitive_keys + legacy_keys,
        disabled_rules=policy.disabled_rules,
        scan_json_strings=policy.scan_json_strings,
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


def scrub_json(
    value: Any,
    *,
    extra_keys: Iterable[str] = (),
    replacement: str = DEFAULT_REPLACEMENT,
    policy: ScrubPolicy | None = None,
) -> ScrubResult[Any]:
    """Scrub credential-like values from a JSON-compatible Python value.

    The input is not mutated. Values under sensitive keys are replaced as a
    whole, including nested objects and arrays.
    """

    effective_policy = _resolve_policy(policy, extra_keys, replacement)
    return Scrubber(effective_policy).scrub_json(value)


def _replacement_starts_at(text: str, start: int, replacement: str) -> bool:
    if not replacement or not text.startswith(replacement, start):
        return False
    end = start + len(replacement)
    return end == len(text) or text[end] in "\r\n\t ,;:]}>&)\"'"


def _is_redacted_value(value: str, replacement: str) -> bool:
    if value == replacement:
        return True
    return (
        len(value) >= 2
        and value[0] == value[-1]
        and value[0] in "\"'"
        and value[1:-1] == replacement
    )


def scrub_text(
    text: str,
    *,
    extra_keys: Iterable[str] = (),
    replacement: str = DEFAULT_REPLACEMENT,
    policy: ScrubPolicy | None = None,
) -> ScrubResult[str]:
    """Scrub high-signal credentials from plain text.

    Text redaction is intentionally conservative. It catches common token
    formats and key/value assignments, but it cannot guarantee that arbitrary
    secrets or personal data have been removed.
    """

    effective_policy = _resolve_policy(policy, extra_keys, replacement)
    return Scrubber(effective_policy).scrub_text(text)


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
) -> Iterator[ScrubResult[str]]:
    """Lazily scrub text or JSON Lines input.

    JSONL line endings are preserved exactly. Blank JSONL lines are passed
    through unchanged. A malformed JSONL record raises ``ValueError`` after
    all preceding records have been yielded.
    """

    effective_policy = _resolve_policy(policy, extra_keys, replacement)
    return Scrubber(effective_policy).scrub_lines(lines, format=format)


@dataclass(frozen=True)
class DetectionSpan:
    """A value-free character range returned by a custom text detector."""

    start: int
    end: int

    def __post_init__(self) -> None:
        if isinstance(self.start, bool) or isinstance(self.end, bool):
            raise TypeError("detection span bounds must be integers")
        if not isinstance(self.start, int) or not isinstance(self.end, int):
            raise TypeError("detection span bounds must be integers")
        if self.start < 0 or self.end <= self.start:
            raise ValueError("detection span must be non-empty and ordered")


@runtime_checkable
class TextDetector(Protocol):
    """Protocol for explicitly registered, local Python text detectors."""

    rule_id: str
    description: str

    def find_spans(self, text: str) -> Iterable[DetectionSpan]:
        """Return value-free spans for matches in ``text``."""


@dataclass(frozen=True)
class RuleInfo:
    """Stable metadata describing one built-in detector rule."""

    rule_id: str
    description: str


_RULE_INFOS: tuple[RuleInfo, ...] = (
    RuleInfo(RULE_JSON_SENSITIVE_KEY, "credential-like JSON object keys"),
    RuleInfo(RULE_CUSTOM_KEY, "keys supplied by the caller"),
    RuleInfo(RULE_URL_PARAMETER, "credential-like URL query parameters"),
    RuleInfo(RULE_ASSIGNMENT, "credential-like text assignments"),
    RuleInfo(RULE_GITHUB_TOKEN, "classic GitHub token prefixes"),
    RuleInfo(RULE_GITHUB_FINE_GRAINED_TOKEN, "fine-grained GitHub token prefixes"),
    RuleInfo(RULE_AWS_ACCESS_KEY, "AWS access-key prefixes"),
    RuleInfo(RULE_JWT, "JWT-shaped three-part tokens"),
    RuleInfo(RULE_OPENAI_KEY, "OpenAI sk- key shapes"),
    RuleInfo(RULE_SLACK_TOKEN, "Slack xox token shapes"),
    RuleInfo(RULE_GITLAB_TOKEN, "GitLab glpat token shapes"),
    RuleInfo(RULE_STRIPE_KEY, "Stripe test/live secret key shapes"),
    RuleInfo(RULE_DATABASE_URL_PASSWORD, "passwords in supported database URLs"),
    RuleInfo(RULE_BEARER_TOKEN, "Bearer authorization values"),
    RuleInfo(RULE_BASIC_CREDENTIALS, "Basic authorization values"),
)


def list_rules() -> tuple[RuleInfo, ...]:
    """Return stable metadata for the built-in detector rules."""

    return _RULE_INFOS


@dataclass(frozen=True)
class _TextMatch:
    start: int
    end: int
    rule_id: str
    priority: int
    order: int


_GENERIC_ASSIGNMENT_RE = re.compile(
    r"(?<![\w?&])(?P<key_name>[^\s:=,;{}\[\]\"'()<>]+)"
    r"(?P<separator>\s*[:=]\s*)"
    # Keep the value in a lookahead so an unrelated prefix such as
    # ``RuntimeError:`` cannot consume a later ``token=...`` assignment.
    rf"(?=(?P<value>{_ASSIGNMENT_VALUE}))",
    re.UNICODE,
)
_GENERIC_URL_RE = re.compile(
    r"(?i)(?P<prefix>[?&])(?P<key>[^=&#\s]+)="
    r"(?P<value>[^&#\s]*)"
)
_CUSTOM_RULE_ID_RE = re.compile(r"custom\.[a-z0-9][a-z0-9.-]{0,62}\Z")


def _merge_rule_counts(target: dict[str, int], result: ScrubResult[Any]) -> None:
    for rule_id, count in result.rule_counts.items():
        target[rule_id] = target.get(rule_id, 0) + count


def _span_from_assignment(match: re.Match[str]) -> DetectionSpan | None:
    start = match.start("value")
    end = match.end("value")
    value = match.group("value")
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        start += 1
        end -= 1
    else:
        auth_prefix = re.match(r"(?i)(?:Bearer|Basic)\s+", value)
        if auth_prefix:
            start += auth_prefix.end()
        else:
            database_match = _DATABASE_URL_RE.search(value)
            if database_match and database_match.group("value"):
                start += database_match.start("value")
                end = match.start("value") + database_match.end("value")
    if end <= start:
        return None
    return DetectionSpan(start, end)


def _span_from_token(match: re.Match[str]) -> DetectionSpan:
    if "value" in match.groupdict():
        return DetectionSpan(match.start("value"), match.end("value"))
    if "prefix" in match.groupdict():
        return DetectionSpan(match.end("prefix"), match.end(0))
    return DetectionSpan(match.start(0), match.end(0))


def _candidate_is_marker(text: str, span: DetectionSpan, replacement: str) -> bool:
    return _is_redacted_value(text[span.start : span.end], replacement) or (
        _replacement_starts_at(text, span.start, replacement)
    )


class Scrubber:
    """Reusable prepared scrubber for text, JSON, and JSONL workflows."""

    def __init__(
        self,
        policy: ScrubPolicy | None = None,
        detectors: Iterable[TextDetector] = (),
    ) -> None:
        if policy is None:
            policy = ScrubPolicy()
        if not isinstance(policy, ScrubPolicy):
            raise TypeError("policy must be a ScrubPolicy instance")
        self.policy = policy
        self._default_keys = frozenset(
            _normalize_key(key) for key in DEFAULT_SENSITIVE_KEYS
        )
        self._custom_keys = _custom_key_set(policy)
        self._sensitive_keys = _sensitive_key_set(policy)
        self._assignment_pattern = _GENERIC_ASSIGNMENT_RE
        self._url_pattern = _GENERIC_URL_RE
        self.detectors = self._validate_detectors(detectors)

    @staticmethod
    def _validate_detectors(
        detectors: Iterable[TextDetector],
    ) -> tuple[TextDetector, ...]:
        try:
            registered = tuple(detectors)
        except TypeError as exc:
            raise TypeError("detectors must be an iterable") from exc
        seen: set[str] = set()
        for detector in registered:
            rule_id = getattr(detector, "rule_id", None)
            description = getattr(detector, "description", None)
            find_spans = getattr(detector, "find_spans", None)
            if not isinstance(rule_id, str) or not _CUSTOM_RULE_ID_RE.fullmatch(
                rule_id
            ):
                raise ValueError("custom detector rule IDs must match custom.<slug>")
            if rule_id in KNOWN_RULE_IDS or rule_id in seen:
                raise ValueError(f"duplicate detector rule ID: {rule_id}")
            if not isinstance(description, str) or not description.strip():
                raise ValueError(f"detector {rule_id} needs a description")
            if not callable(find_spans):
                raise TypeError(f"detector {rule_id} needs find_spans(text)")
            seen.add(rule_id)
        return registered

    def _text_matches(self, text: str) -> list[_TextMatch]:
        matches: list[_TextMatch] = []
        order = 0

        for rule_id, pattern in _TOKEN_RULES:
            if rule_id in self.policy.disabled_rules:
                continue
            for match in pattern.finditer(text):
                span = _span_from_token(match)
                if _candidate_is_marker(text, span, self.policy.replacement):
                    continue
                matches.append(_TextMatch(span.start, span.end, rule_id, 100, order))
                order += 1

        for detector in self.detectors:
            rule_id = detector.rule_id
            try:
                spans = tuple(detector.find_spans(text))
            except Exception:  # noqa: BLE001
                raise ValueError(f"detector {rule_id} failed") from None
            validated: list[DetectionSpan] = []
            for span in spans:
                if not isinstance(span, DetectionSpan):
                    raise TypeError(
                        f"detector {rule_id} must return DetectionSpan values"
                    )
                if span.end > len(text):
                    raise ValueError(
                        f"detector {rule_id} returned an out-of-range span"
                    )
                validated.append(span)
            validated.sort(key=lambda item: (item.start, item.end))
            previous_end = -1
            for span in validated:
                if span.start < previous_end:
                    raise ValueError(f"detector {rule_id} returned overlapping spans")
                previous_end = span.end
                if _candidate_is_marker(text, span, self.policy.replacement):
                    continue
                matches.append(_TextMatch(span.start, span.end, rule_id, 90, order))
                order += 1

        if RULE_URL_PARAMETER not in self.policy.disabled_rules:
            for match in self._url_pattern.finditer(text):
                key = unquote_plus(match.group("key"))
                normalized = _normalize_key(key)
                if not _is_sensitive_key(normalized, self._sensitive_keys):
                    continue
                start = match.start("value")
                end = match.end("value")
                if start == end:
                    continue
                span = DetectionSpan(start, end)
                if _candidate_is_marker(text, span, self.policy.replacement):
                    continue
                matches.append(_TextMatch(start, end, RULE_URL_PARAMETER, 80, order))
                order += 1

        for match in self._assignment_pattern.finditer(text):
            normalized = _normalize_key(match.group("key_name"))
            if normalized in self._custom_keys:
                rule_id = RULE_CUSTOM_KEY
            elif _is_sensitive_key(normalized, self._sensitive_keys):
                rule_id = RULE_ASSIGNMENT
            else:
                continue
            if rule_id in self.policy.disabled_rules:
                continue
            assignment_span = _span_from_assignment(match)
            if assignment_span is None or _candidate_is_marker(
                text, assignment_span, self.policy.replacement
            ):
                continue
            matches.append(
                _TextMatch(
                    assignment_span.start,
                    assignment_span.end,
                    rule_id,
                    60,
                    order,
                )
            )
            order += 1

        return matches

    def _scrub_text_value(self, text: str) -> ScrubResult[str]:
        matches = self._text_matches(text)
        if not matches:
            return ScrubResult(text, 0)

        ordered = sorted(matches, key=lambda item: (item.start, item.end))
        groups: list[list[_TextMatch]] = []
        group_end = -1
        for match in ordered:
            if not groups or match.start >= group_end:
                groups.append([match])
                group_end = match.end
            else:
                groups[-1].append(match)
                group_end = max(group_end, match.end)

        replacements: list[tuple[int, int, str]] = []
        counts: dict[str, int] = {}
        for group in groups:
            start = min(item.start for item in group)
            end = max(item.end for item in group)
            winner = max(
                group,
                key=lambda item: (item.priority, item.end - item.start, -item.order),
            )
            replacements.append((start, end, self.policy.replacement))
            _increment(counts, winner.rule_id)

        scrubbed = text
        for start, end, replacement in reversed(replacements):
            scrubbed = scrubbed[:start] + replacement + scrubbed[end:]
        return ScrubResult(scrubbed, len(replacements), counts)

    def scrub_text(self, text: str) -> ScrubResult[str]:
        """Scrub a plain-text value using the prepared policy and detectors."""

        if not isinstance(text, str):
            raise TypeError("text must be a string")
        return self._scrub_text_value(text)

    def _scrub_json_value(
        self,
        value: Any,
        counts: dict[str, int],
        ancestors: set[int],
    ) -> Any:
        if isinstance(value, str):
            if not self.policy.scan_json_strings:
                return value
            result = self._scrub_text_value(value)
            _merge_rule_counts(counts, result)
            return result.value

        if isinstance(value, Mapping):
            marker = id(value)
            if marker in ancestors:
                raise ValueError("cyclic JSON-compatible value")
            ancestors.add(marker)
            try:
                scrubbed: dict[Any, Any] = {}
                for key, child in value.items():
                    normalized = _normalize_key(key)
                    if _is_sensitive_key(normalized, self._sensitive_keys):
                        if (
                            normalized in self._custom_keys
                            and normalized not in self._default_keys
                        ):
                            rule_id = RULE_CUSTOM_KEY
                        else:
                            rule_id = RULE_JSON_SENSITIVE_KEY
                        if rule_id not in self.policy.disabled_rules:
                            if child == self.policy.replacement:
                                scrubbed[key] = child
                            else:
                                scrubbed[key] = self.policy.replacement
                                _increment(counts, rule_id)
                            continue
                    scrubbed[key] = self._scrub_json_value(child, counts, ancestors)
                return scrubbed
            finally:
                ancestors.remove(marker)

        if isinstance(value, list):
            marker = id(value)
            if marker in ancestors:
                raise ValueError("cyclic JSON-compatible value")
            ancestors.add(marker)
            try:
                return [
                    self._scrub_json_value(child, counts, ancestors) for child in value
                ]
            finally:
                ancestors.remove(marker)

        return value

    def scrub_json(self, value: Any) -> ScrubResult[Any]:
        """Scrub a JSON-compatible value without mutating the input."""

        counts: dict[str, int] = {}
        try:
            scrubbed = self._scrub_json_value(value, counts, set())
        except RecursionError:
            raise ValueError("JSON value is too deeply nested") from None
        return ScrubResult(scrubbed, sum(counts.values()), counts)

    def scrub_lines(
        self,
        lines: Iterable[str],
        *,
        format: str,
    ) -> Iterator[ScrubResult[str]]:
        """Lazily scrub text or JSON Lines with prepared detectors."""

        if format not in ("text", "jsonl"):
            raise ValueError("format must be 'text' or 'jsonl'")
        if format == "text":
            for line in lines:
                yield self.scrub_text(line)
            return

        for line_number, line in enumerate(lines, start=1):
            body, ending = _split_line_ending(line)
            if not body.strip():
                yield ScrubResult(line, 0)
                continue
            try:
                value = json.loads(body)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"invalid JSON on line {line_number}: {exc.msg}"
                ) from exc
            result = self.scrub_json(value)
            encoded = json.dumps(
                result.value,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            yield ScrubResult(encoded + ending, result.replacements, result.rule_counts)
