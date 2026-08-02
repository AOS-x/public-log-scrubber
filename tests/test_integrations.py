import logging
import sys
import unittest

from public_log_scrubber import (
    DetectionSpan,
    Scrubber,
    ScrubbingFormatter,
)


class ScrubbingFormatterTests(unittest.TestCase):
    def test_formats_message_and_exception_without_mutating_record_fields(self):
        formatter = ScrubbingFormatter("%(levelname)s %(message)s")
        record = logging.LogRecord(
            "test",
            logging.ERROR,
            __file__,
            1,
            "password=%s",
            ("message-secret",),
            None,
        )
        original_msg = record.msg
        original_args = record.args

        try:
            raise RuntimeError("token=exception-secret")
        except RuntimeError:
            record.exc_info = sys.exc_info()

        rendered = formatter.format(record)

        self.assertNotIn("message-secret", rendered)
        self.assertNotIn("exception-secret", rendered)
        self.assertIn("[REDACTED]", rendered)
        self.assertEqual(record.msg, original_msg)
        self.assertEqual(record.args, original_args)

    def test_multiline_messages_are_scrubbed(self):
        formatter = ScrubbingFormatter("%(message)s")
        record = logging.LogRecord(
            "test",
            logging.INFO,
            __file__,
            1,
            "first\npassword=hidden\nlast",
            (),
            None,
        )

        rendered = formatter.format(record)

        self.assertEqual(rendered, "first\npassword=[REDACTED]\nlast")

    def test_formatting_failure_fails_closed(self):
        class FailingDetector:
            rule_id = "custom.failing"
            description = "synthetic failure"

            def find_spans(self, text):
                raise RuntimeError("detector failed")

        formatter = ScrubbingFormatter(
            "%(message)s",
            scrubber=Scrubber(detectors=(FailingDetector(),)),
        )
        record = logging.LogRecord(
            "test", logging.INFO, __file__, 1, "password=hidden", (), None
        )

        self.assertEqual(formatter.format(record), "[LOG REDACTION FAILED]")

    def test_custom_detector_span_is_used_by_formatter(self):
        class CaseDetector:
            rule_id = "custom.case-id"
            description = "synthetic case IDs"

            def find_spans(self, text):
                start = text.find("CASE-")
                if start < 0:
                    return ()
                return (DetectionSpan(start, start + len("CASE-123456")),)

        formatter = ScrubbingFormatter(
            "%(message)s", scrubber=Scrubber(detectors=(CaseDetector(),))
        )
        record = logging.LogRecord(
            "test", logging.INFO, __file__, 1, "CASE-123456", (), None
        )

        self.assertEqual(formatter.format(record), "[REDACTED]")


if __name__ == "__main__":
    unittest.main()
