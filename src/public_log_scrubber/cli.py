"""Command-line interface for the public log scrubber."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence, TextIO

from .core import DEFAULT_REPLACEMENT, scrub_json, scrub_text


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log-scrub",
        description="Remove common credentials from logs before sharing them.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default="-",
        help="input file, or - to read stdin (default: -)",
    )
    parser.add_argument(
        "--format",
        choices=("auto", "json", "jsonl", "text"),
        default="auto",
        help="input format (default: auto)",
    )
    parser.add_argument(
        "--key",
        action="append",
        dest="extra_keys",
        default=[],
        metavar="NAME",
        help="additional key to redact; may be repeated",
    )
    parser.add_argument(
        "--replacement",
        default=DEFAULT_REPLACEMENT,
        help=f"replacement text (default: {DEFAULT_REPLACEMENT})",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit 1 if anything would be redacted, without printing input",
    )
    return parser


def _read_input(path: str, stdin: TextIO) -> str:
    if path == "-":
        return stdin.read()
    return Path(path).read_text(encoding="utf-8")


def _scrub_json_text(
    raw: str, extra_keys: Sequence[str], replacement: str
) -> tuple[str, int]:
    value = json.loads(raw)
    result = scrub_json(
        value, extra_keys=extra_keys, replacement=replacement
    )
    return (
        json.dumps(result.value, ensure_ascii=False, indent=2) + "\n",
        result.replacements,
    )


def _scrub_jsonl_text(
    raw: str, extra_keys: Sequence[str], replacement: str
) -> tuple[str, int]:
    output: list[str] = []
    replacements = 0
    for line_number, line in enumerate(raw.splitlines(keepends=True), start=1):
        if not line.strip():
            output.append(line)
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"invalid JSON on line {line_number}: {exc.msg}"
            ) from exc
        result = scrub_json(
            value, extra_keys=extra_keys, replacement=replacement
        )
        output.append(
            json.dumps(
                result.value,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            + "\n"
        )
        replacements += result.replacements
    return "".join(output), replacements


def _scrub_input(
    raw: str,
    input_format: str,
    extra_keys: Sequence[str],
    replacement: str,
) -> tuple[str, int]:
    if input_format == "json":
        return _scrub_json_text(raw, extra_keys, replacement)
    if input_format == "jsonl":
        return _scrub_jsonl_text(raw, extra_keys, replacement)
    if input_format == "text":
        result = scrub_text(
            raw, extra_keys=extra_keys, replacement=replacement
        )
        return result.value, result.replacements

    # Auto mode only treats the complete input as JSON when it parses as JSON.
    # JSON Lines remains explicit so a malformed line cannot be silently
    # downgraded to text and leave nested credential keys untouched.
    try:
        return _scrub_json_text(raw, extra_keys, replacement)
    except json.JSONDecodeError:
        result = scrub_text(
            raw, extra_keys=extra_keys, replacement=replacement
        )
        return result.value, result.replacements


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        raw = _read_input(args.path, sys.stdin)
        scrubbed, replacements = _scrub_input(
            raw,
            args.format,
            args.extra_keys,
            args.replacement,
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        print(f"log-scrub: {exc}", file=sys.stderr)
        return 2

    if args.check:
        return 1 if replacements else 0

    sys.stdout.write(scrubbed)
    return 0
