"""Standard-library integrations for local log scrubbing."""

from __future__ import annotations

import logging
from typing import Literal

from .core import Scrubber


class ScrubbingFormatter(logging.Formatter):
    """Format a record and scrub the final rendered message locally.

    The formatter does not modify ``LogRecord.msg`` or ``LogRecord.args``.
    If formatting or scrubbing fails, it returns a fixed safe message instead
    of allowing an unsanitized record to be emitted.
    """

    def __init__(
        self,
        fmt: str | None = None,
        datefmt: str | None = None,
        style: Literal["%", "{", "$"] = "%",
        validate: bool = True,
        *,
        scrubber: Scrubber | None = None,
        failure_text: str = "[LOG REDACTION FAILED]",
    ) -> None:
        super().__init__(fmt=fmt, datefmt=datefmt, style=style, validate=validate)
        if scrubber is not None and not isinstance(scrubber, Scrubber):
            raise TypeError("scrubber must be a Scrubber instance")
        if not isinstance(failure_text, str) or not failure_text:
            raise ValueError("failure_text must be non-empty")
        self.scrubber = scrubber or Scrubber()
        self.failure_text = failure_text

    def format(self, record: logging.LogRecord) -> str:
        try:
            rendered = super().format(record)
            result = self.scrubber.scrub_text(rendered)
            if not isinstance(result.value, str):
                raise TypeError("scrubber returned a non-text value")
            return result.value
        except Exception:  # noqa: BLE001
            return self.failure_text
