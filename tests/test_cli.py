import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from public_log_scrubber.cli import main


class CliTests(unittest.TestCase):
    def test_json_from_stdin_is_pretty_printed_and_scrubbed(self):
        source = '{"password":"hidden","message":"hello"}'
        stdout = io.StringIO()

        with patch("sys.stdin", io.StringIO(source)), patch("sys.stdout", stdout):
            exit_code = main(["--format", "json"])

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            json.loads(stdout.getvalue()),
            {"password": "[REDACTED]", "message": "hello"},
        )

    def test_jsonl_preserves_blank_lines(self):
        source = '{"token":"hidden"}\n\n{"ok":true}\n'
        stdout = io.StringIO()

        with patch("sys.stdin", io.StringIO(source)), patch("sys.stdout", stdout):
            exit_code = main(["--format", "jsonl"])

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            stdout.getvalue(),
            '{"token":"[REDACTED]"}\n\n{"ok":true}\n',
        )

    def test_check_mode_does_not_print_input(self):
        stdout = io.StringIO()
        with (
            patch("sys.stdin", io.StringIO("password=hidden\n")),
            patch("sys.stdout", stdout),
        ):
            exit_code = main(["--check", "--format", "text"])

        self.assertEqual(exit_code, 1)
        self.assertEqual(stdout.getvalue(), "")

    def test_invalid_json_returns_usage_error(self):
        stderr = io.StringIO()
        with patch("sys.stdin", io.StringIO("{")), patch("sys.stderr", stderr):
            exit_code = main(["--format", "json"])

        self.assertEqual(exit_code, 2)
        self.assertIn("log-scrub:", stderr.getvalue())

    def test_policy_report_and_output_are_safe_and_atomic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / "policy.json"
            output = root / "safe.log"
            report = root / "report.json"
            policy.write_text(
                json.dumps(
                    {
                        "replacement": "<REMOVED>",
                        "extra_sensitive_keys": ["employee_id"],
                        "disabled_rules": [],
                    }
                ),
                encoding="utf-8",
            )

            with patch("sys.stdin", io.StringIO("employee_id=secret\n")):
                exit_code = main(
                    [
                        "--format",
                        "text",
                        "--policy",
                        str(policy),
                        "--output",
                        str(output),
                        "--report",
                        str(report),
                    ]
                )

            self.assertEqual(exit_code, 0)
            self.assertEqual(
                output.read_text(encoding="utf-8"), "employee_id=<REMOVED>\n"
            )
            report_value = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(report_value["replacements"], 1)
            self.assertEqual(report_value["rule_counts"], {"custom-key": 1})
            self.assertNotIn("secret", report.read_text(encoding="utf-8"))

    def test_output_refuses_overwrite_without_force(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "safe.log"
            output.write_text("old", encoding="utf-8")
            stderr = io.StringIO()
            with (
                patch("sys.stdin", io.StringIO("password=hidden\n")),
                patch("sys.stderr", stderr),
            ):
                exit_code = main(["--format", "text", "--output", str(output)])

            self.assertEqual(exit_code, 2)
            self.assertEqual(output.read_text(encoding="utf-8"), "old")
            self.assertIn("refusing to overwrite", stderr.getvalue())

    def test_force_replaces_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "safe.log"
            output.write_text("old", encoding="utf-8")
            with patch("sys.stdin", io.StringIO("password=hidden\n")):
                exit_code = main(
                    ["--format", "text", "--output", str(output), "--force"]
                )

            self.assertEqual(exit_code, 0)
            self.assertEqual(
                output.read_text(encoding="utf-8"), "password=[REDACTED]\n"
            )

    def test_failed_stream_does_not_commit_output_or_leave_temp_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "safe.jsonl"
            stderr = io.StringIO()
            source = '{"password":"hidden"}\n{"broken":\n'
            with patch("sys.stdin", io.StringIO(source)), patch("sys.stderr", stderr):
                exit_code = main(["--format", "jsonl", "--output", str(output)])

            self.assertEqual(exit_code, 2)
            self.assertFalse(output.exists())
            self.assertEqual(list(root.glob(".safe.jsonl.*.tmp")), [])
            self.assertIn("invalid JSON on line 2", stderr.getvalue())

    def test_output_cannot_overwrite_input(self):
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "input.log"
            input_path.write_text("password=hidden\n", encoding="utf-8")
            stderr = io.StringIO()
            with patch("sys.stderr", stderr):
                exit_code = main(
                    ["--format", "text", str(input_path), "--output", str(input_path)]
                )

            self.assertEqual(exit_code, 2)
            self.assertIn("cannot overwrite the input file", stderr.getvalue())

    def test_check_mode_can_write_a_safe_report_but_not_output(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            stdout = io.StringIO()
            with (
                patch("sys.stdin", io.StringIO("password=hidden\n")),
                patch("sys.stdout", stdout),
            ):
                exit_code = main(
                    ["--format", "text", "--check", "--report", str(report)]
                )

            self.assertEqual(exit_code, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(
                json.loads(report.read_text(encoding="utf-8"))["replacements"],
                1,
            )

    def test_jsonl_streams_prior_safe_records_before_late_error(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        source = '{"password":"hidden"}\n{"broken":\n'
        with (
            patch("sys.stdin", io.StringIO(source)),
            patch("sys.stdout", stdout),
            patch("sys.stderr", stderr),
        ):
            exit_code = main(["--format", "jsonl"])

        self.assertEqual(exit_code, 2)
        self.assertEqual(stdout.getvalue(), '{"password":"[REDACTED]"}\n')
        self.assertNotIn("hidden", stdout.getvalue())
        self.assertIn("invalid JSON on line 2", stderr.getvalue())

    def test_policy_rejects_unknown_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.json"
            policy.write_text(json.dumps({"secret": "value"}), encoding="utf-8")
            stderr = io.StringIO()
            with patch("sys.stdin", io.StringIO("ok\n")), patch("sys.stderr", stderr):
                exit_code = main(["--policy", str(policy), "--format", "text"])

            self.assertEqual(exit_code, 2)
            self.assertIn("unknown policy field", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
