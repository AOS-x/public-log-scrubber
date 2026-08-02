"""Pre-commit entry point for local credential checks."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from .core import Scrubber, ScrubPolicy
from .policy import load_policy


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log-scrub-pre-commit",
        description="Check text files for high-confidence credentials locally.",
    )
    parser.add_argument("paths", nargs="+", help="text files supplied by pre-commit")
    parser.add_argument("--policy", metavar="FILE")
    parser.add_argument("--key", action="append", default=[], dest="extra_keys")
    parser.add_argument("--replacement", default=None)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        base = load_policy(args.policy) if args.policy else ScrubPolicy()
        policy = ScrubPolicy(
            replacement=(
                base.replacement if args.replacement is None else args.replacement
            ),
            extra_sensitive_keys=base.extra_sensitive_keys + tuple(args.extra_keys),
            disabled_rules=base.disabled_rules,
            scan_json_strings=base.scan_json_strings,
        )
        scrubber = Scrubber(policy)
    except (OSError, TypeError, ValueError) as exc:
        print(f"log-scrub-pre-commit: {exc}", file=sys.stderr)
        return 2

    matched = 0
    operational_error = False
    for path_text in args.paths:
        path = Path(path_text)
        try:
            with path.open("r", encoding="utf-8", newline="") as handle:
                results = scrubber.scrub_lines(handle, format="text")
                file_replacements = 0
                file_counts: dict[str, int] = {}
                for result in results:
                    file_replacements += result.replacements
                    for rule_id, count in result.rule_counts.items():
                        file_counts[rule_id] = file_counts.get(rule_id, 0) + count
        except (OSError, UnicodeError, TypeError, ValueError, RecursionError):
            print(f"log-scrub-pre-commit: failed to check {path}", file=sys.stderr)
            operational_error = True
            continue

        if file_replacements:
            matched += file_replacements
            rules = ", ".join(
                f"{rule_id}={file_counts[rule_id]}" for rule_id in sorted(file_counts)
            )
            print(
                f"{path}: {file_replacements} potential replacement(s) ({rules})",
                file=sys.stderr,
            )

    if operational_error:
        return 2
    return 1 if matched else 0
