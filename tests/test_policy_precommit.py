import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from public_log_scrubber import ScrubPolicy, load_policy
from public_log_scrubber.precommit import main as precommit_main


class PolicyLoaderTests(unittest.TestCase):
    def test_load_policy_accepts_json_string_scan_option(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(
                json.dumps(
                    {
                        "replacement": "<SAFE>",
                        "extra_sensitive_keys": ["case_id"],
                        "disabled_rules": ["jwt"],
                        "scan_json_strings": False,
                    }
                ),
                encoding="utf-8",
            )

            policy = load_policy(path)

        self.assertEqual(
            policy,
            ScrubPolicy(
                replacement="<SAFE>",
                extra_sensitive_keys=("case_id",),
                disabled_rules=("jwt",),
                scan_json_strings=False,
            ),
        )

    def test_load_policy_rejects_unknown_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps({"regex": "secret"}), encoding="utf-8")

            with self.assertRaises(ValueError):
                load_policy(path)


class PreCommitTests(unittest.TestCase):
    def test_matching_files_report_only_safe_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.log"
            path.write_text("password=synthetic-secret\n", encoding="utf-8")
            stderr = io.StringIO()

            with patch("sys.stderr", stderr):
                exit_code = precommit_main([str(path)])

        self.assertEqual(exit_code, 1)
        self.assertIn("synthetic.log", stderr.getvalue())
        self.assertIn("assignment-sensitive-key=1", stderr.getvalue())
        self.assertNotIn("synthetic-secret", stderr.getvalue())

    def test_clean_and_already_scrubbed_files_return_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            clean = Path(directory) / "clean.log"
            scrubbed = Path(directory) / "scrubbed.log"
            clean.write_text("status=ok\n", encoding="utf-8")
            scrubbed.write_text("password=[REDACTED]\n", encoding="utf-8")

            self.assertEqual(precommit_main([str(clean), str(scrubbed)]), 0)

    def test_policy_and_custom_key_are_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / "policy.json"
            log = root / "log.txt"
            policy.write_text(
                json.dumps(
                    {
                        "replacement": "<SAFE>",
                        "extra_sensitive_keys": ["employee_id"],
                    }
                ),
                encoding="utf-8",
            )
            log.write_text("employee_id=synthetic-id\n", encoding="utf-8")
            stderr = io.StringIO()

            with patch("sys.stderr", stderr):
                exit_code = precommit_main(
                    ["--policy", str(policy), "--key", "case_id", str(log)]
                )

        self.assertEqual(exit_code, 1)
        self.assertNotIn("synthetic-id", stderr.getvalue())
        self.assertIn("custom-key=1", stderr.getvalue())

    def test_invalid_utf8_returns_operational_error_without_echoing_data(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.log"
            path.write_bytes(b"password=secret\xff\n")
            stderr = io.StringIO()

            with patch("sys.stderr", stderr):
                exit_code = precommit_main([str(path)])

        self.assertEqual(exit_code, 2)
        self.assertNotIn("password=secret", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
