"""Command-line interface for the public log scrubber."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import TextIO

from . import __version__
from .core import (
    DEFAULT_REPLACEMENT,
    ScrubPolicy,
    ScrubResult,
    list_rules,
    scrub_json,
    scrub_lines,
    scrub_text,
)
from .policy import load_policy


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
    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="list built-in detector IDs and exit",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def _load_policy(path: str | None) -> ScrubPolicy:
    if path is None:
        return ScrubPolicy()
    return load_policy(path)


def _effective_policy(args: argparse.Namespace) -> ScrubPolicy:
    base = _load_policy(args.policy)
    replacement = base.replacement if args.replacement is None else args.replacement
    return ScrubPolicy(
        replacement=replacement,
        extra_sensitive_keys=base.extra_sensitive_keys + tuple(args.extra_keys),
        disabled_rules=base.disabled_rules,
        scan_json_strings=base.scan_json_strings,
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


class _StagedFile:
    """Stage one destination and commit it only after all work succeeds."""

    def __init__(self, path: str, force: bool) -> None:
        self.destination = Path(path)
        self.force = force
        self.temporary_name: str | None = None
        self.handle: TextIO | None = None

    def open(self) -> TextIO:
        if self.destination.exists() and not self.force:
            raise FileExistsError(
                f"refusing to overwrite {self.destination}; use --force to replace it"
            )
        file_descriptor, temporary_name = tempfile.mkstemp(
            dir=str(self.destination.parent),
            prefix=f".{self.destination.name}.",
            suffix=".tmp",
        )
        self.temporary_name = temporary_name
        try:
            self.handle = os.fdopen(
                file_descriptor,
                "w",
                encoding="utf-8",
                newline="",
            )
        except BaseException:
            os.close(file_descriptor)
            self.cleanup()
            raise
        return self.handle

    def finish(self) -> None:
        if self.handle is None:
            return
        self.handle.flush()
        os.fsync(self.handle.fileno())
        self.handle.close()
        self.handle = None

    def commit(self) -> None:
        self.finish()
        if self.temporary_name is None:
            return
        if self.destination.exists() and not self.force:
            raise FileExistsError(
                f"refusing to overwrite {self.destination}; use --force to replace it"
            )
        os.replace(self.temporary_name, self.destination)
        self.temporary_name = None

    def cleanup(self) -> None:
        if self.handle is not None:
            try:
                self.handle.close()
            finally:
                self.handle = None
        if self.temporary_name is not None:
            try:
                os.unlink(self.temporary_name)
            except FileNotFoundError:
                pass
            finally:
                self.temporary_name = None


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

    for path in paths:
        if Path(path).exists() and not args.force:
            raise FileExistsError(
                f"refusing to overwrite {Path(path)}; use --force to replace it"
            )


def _write_report(handle: TextIO, replacements: int, counts: dict[str, int]) -> None:
    report = {
        "schema_version": 1,
        "tool_version": __version__,
        "replacements": replacements,
        "rule_counts": {rule: counts[rule] for rule in sorted(counts)},
    }
    json.dump(report, handle, ensure_ascii=False, indent=2)
    handle.write("\n")


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.list_rules:
        for rule in list_rules():
            print(f"{rule.rule_id}\t{rule.description}")
        return 0
    try:
        _validate_paths(args)
        policy = _effective_policy(args)
        total_counts: dict[str, int] = {}
        total_replacements = 0

        output_stage = (
            _StagedFile(args.output, args.force)
            if args.output and not args.check
            else None
        )
        report_stage = _StagedFile(args.report, args.force) if args.report else None
        try:
            output_handle = output_stage.open() if output_stage else None
            report_handle = report_stage.open() if report_stage else None
            with _input_handle(args.path, sys.stdin) as input_handle:
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

            if output_stage:
                output_stage.finish()
            if report_stage and report_handle:
                _write_report(report_handle, total_replacements, total_counts)
                report_stage.finish()
            if report_stage:
                report_stage.commit()
            if output_stage:
                output_stage.commit()
        except BaseException:
            if output_stage:
                output_stage.cleanup()
            if report_stage:
                report_stage.cleanup()
            raise
    except (
        OSError,
        UnicodeError,
        TypeError,
        ValueError,
        RecursionError,
        json.JSONDecodeError,
    ) as exc:
        print(f"log-scrub: {exc}", file=sys.stderr)
        return 2

    if args.check:
        return 1 if total_replacements else 0
    return 0
