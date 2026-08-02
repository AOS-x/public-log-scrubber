"""Informational comparison of wrapper and prepared streaming paths.

This is intentionally not a CI timing gate. It demonstrates the preparation
trade-off on a local machine without printing any input values.
"""

from __future__ import annotations

import argparse
import time

from public_log_scrubber import Scrubber, scrub_text


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lines", type=int, default=50_000)
    args = parser.parse_args()
    if args.lines < 1:
        parser.error("--lines must be positive")

    lines = tuple("password=synthetic-value status=ok\n" for _ in range(args.lines))

    started = time.perf_counter()
    for line in lines:
        scrub_text(line)
    wrapper_seconds = time.perf_counter() - started

    scrubber = Scrubber()
    started = time.perf_counter()
    for _ in scrubber.scrub_lines(lines, format="text"):
        pass
    prepared_seconds = time.perf_counter() - started

    print(f"lines={args.lines}")
    print(f"wrapper_seconds={wrapper_seconds:.6f}")
    print(f"prepared_seconds={prepared_seconds:.6f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
