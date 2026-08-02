import io
import json
import unittest
from unittest.mock import patch

from public_log_scrubber.cli import main


class CliTests(unittest.TestCase):
    def test_json_from_stdin_is_pretty_printed_and_scrubbed(self):
        source = '{"password":"hidden","message":"hello"}'
        stdout = io.StringIO()

        with patch("sys.stdin", io.StringIO(source)), patch(
            "sys.stdout", stdout
        ):
            exit_code = main(["--format", "json"])

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            json.loads(stdout.getvalue()),
            {"password": "[REDACTED]", "message": "hello"},
        )

    def test_jsonl_preserves_blank_lines(self):
        source = '{"token":"hidden"}\n\n{"ok":true}\n'
        stdout = io.StringIO()

        with patch("sys.stdin", io.StringIO(source)), patch(
            "sys.stdout", stdout
        ):
            exit_code = main(["--format", "jsonl"])

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            stdout.getvalue(),
            '{"token":"[REDACTED]"}\n\n{"ok":true}\n',
        )

    def test_check_mode_does_not_print_input(self):
        stdout = io.StringIO()
        with patch("sys.stdin", io.StringIO("password=hidden\n")), patch(
            "sys.stdout", stdout
        ):
            exit_code = main(["--check", "--format", "text"])

        self.assertEqual(exit_code, 1)
        self.assertEqual(stdout.getvalue(), "")

    def test_invalid_json_returns_usage_error(self):
        stderr = io.StringIO()
        with patch("sys.stdin", io.StringIO("{")), patch(
            "sys.stderr", stderr
        ):
            exit_code = main(["--format", "json"])

        self.assertEqual(exit_code, 2)
        self.assertIn("log-scrub:", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
