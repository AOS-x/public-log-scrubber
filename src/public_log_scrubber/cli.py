"""Command-line interface for the public log scrubber."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import TextIO

from .core import (
    DEFAULT_REPLACEMENT,
    ScrubPolicy,
    ScrubResult,
    scrub_json,
    scrub_lines,
    scrub_text,
)


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
        help="input format (default: auto; use text/jsonl for streaming)",
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
        default=None,
        metavar="TEXT",
        help=f"replacement text (default: {DEFAULT_REPLACEMENT})",
    )
    parser.add_argument(
        "--policy",
        metavar="FILE",
        help="JSON policy file controlling replacement, keys, and rules",
    )
    parser.add_argument(
        "--report",
        metavar="FILE",
        help="write safe replacement counts as JSON",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="write scrubbed output atomically instead of stdout",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="allow --output or --report to replace existing files",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit 1 if anything would be redacted, without printing input",
    )
    return parser


def _load_policy(path: str | None) -> ScrubPolicy:
    if path is None:
        return ScrubPolicy()

    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid policy JSON: {exc.msg}") from exc

    if not isinstance(raw, dict):
        raise TypeError("policy must be a JSON object")

    allowed = {"replacement", "extra_sensitive_keys", "disabled_rules"}
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ValueError(f"unknown policy field: {unknown[0]}")

    extra_keys = raw.get("extra_sensitive_keys", ())
    disabled_rules = raw.get("disabled_rules", ())
    if not isinstance(extra_keys, (list, tuple)):
        raise TypeError("extra_sensitive_keys must be a JSON array")
    if not isinstance(disabled_rules, (list, tuple)):
        raise TypeError("disabled_rules must be a JSON array")

    replacement = raw.get("replacement", DEFAULT_REPLACEMENT)
    return ScrubPolicy(
        replacement=replacement,
        extra_sensitive_keys=tuple(extra_keys),
        disabled_rules=tuple(disabled_rules),
    )


def _effective_policy(args: argparse.Namespace) -> ScrubPolicy:
    base = _load_policy(args.policy)
    replacement = base.replacement if args.replacement is None else args.replacement
    return ScrubPolicy(
        replacement=replacement,
        extra_sensitive_keys=base.extra_sensitive_keys + tuple(args.extra_keys),
        disabled_rules=base.disabled_rules,
    )


def _add_counts(total: dict[str, int], result: ScrubResult) -> None:
    for rule_id, count in result.rule_counts.items():
        total[rule_id] = total.get(rule_id, 0) + count


@contextmanager
def _input_handle(path: str, stdin: TextIO) -> Iterator[TextIO]:
    if path == "-":
        yield stdin
        return
    with Path(path).open("r", encoding="utf-8", newline="") as handle:
        yield handle


@contextmanager
def _atomic_writer(path: str, force: bool) -> Iterator[TextIO]:
    destination = Path(path)
    if destination.exists() and not force:
        raise FileExistsError(
            f"refusing to overwrite {destination}; use --force to replace it"
        )

    file_descriptor, temporary_name = tempfile.mkstemp(
        dir=str(destination.parent),
        prefix=f".{destination.name}.",
        suffix=".tmp",
    )
    os.close(file_descriptor)
    try:
        with open(temporary_name, "w", encoding="utf-8", newline="") as handle:
            yield handle
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, destination)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def _scrub_complete(raw: str, input_format: str, policy: ScrubPolicy) -> ScrubResult:
    if input_format == "json":
        value = json.loads(raw)
        result = scrub_json(value, policy=policy)
        return ScrubResult(
            json.dumps(result.value, ensure_ascii=False, indent=2) + "\n",
            result.replacements,
            result.rule_counts,
        )

    if input_format == "text":
        return scrub_text(raw, policy=policy)

    if input_format == "auto":
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            return scrub_text(raw, policy=policy)
        result = scrub_json(value, policy=policy)
        return ScrubResult(
            json.dumps(result.value, ensure_ascii=False, indent=2) + "\n",
            result.replacements,
            result.rule_counts,
        )

    raise ValueError(f"unsupported format: {input_format}")


def _validate_paths(args: argparse.Namespace) -> None:
    if args.check and args.output:
        raise ValueError("--check cannot be combined with --output")

    paths = [path for path in (args.output, args.report) if path]
    resolved = [Path(path).resolve() for path in paths]
    if len(resolved) != len(set(resolved)):
        raise ValueError("--output and --report must be different files")

    if args.path != "-":
        input_path = Path(args.path).resolve()
        for label, path in (("--output", args.output), ("--report", args.report)):
            if path and Path(path).resolve() == input_path:
                raise ValueError(f"{label} cannot overwrite the input file")


def _write_report(
    path: str, force: bool, replacements: int, counts: dict[str, int]
) -> None:
    report = {
        "replacements": replacements,
        "rule_counts": {rule: counts[rule] for rule in sorted(counts)},
    }
    with _atomic_writer(path, force) as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        _validate_paths(args)
        policy = _effective_policy(args)

        output_context = (
            nullcontext(None)
            if args.check or args.output is None
            else _atomic_writer(args.output, args.force)
        )
        total_counts: dict[str, int] = {}
        total_replacements = 0

        with (
            _input_handle(args.path, sys.stdin) as input_handle,
            output_context as output_handle,
        ):
            if args.format in ("text", "jsonl"):
                results = scrub_lines(
                    input_handle,
                    format=args.format,
                    policy=policy,
                )
                for result in results:
                    total_replacements += result.replacements
                    _add_counts(total_counts, result)
                    if not args.check:
                        destination = output_handle or sys.stdout
                        destination.write(result.value)
            else:
                result = _scrub_complete(input_handle.read(), args.format, policy)
                total_replacements = result.replacements
                _add_counts(total_counts, result)
                if not args.check:
                    destination = output_handle or sys.stdout
                    destination.write(result.value)

        if args.report:
            _write_report(
                args.report,
                args.force,
                total_replacements,
                total_counts,
            )
    except (OSError, UnicodeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"log-scrub: {exc}", file=sys.stderr)
        return 2

    if args.check:
        return 1 if total_replacements else 0
    return 0
