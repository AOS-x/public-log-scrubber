import unittest

from public_log_scrubber import (
    DEFAULT_REPLACEMENT,
    is_sensitive_key,
    scrub_json,
    scrub_text,
)


class ScrubJsonTests(unittest.TestCase):
    def test_nested_sensitive_values_are_replaced_without_mutating_input(self):
        original = {
            "event": "login",
            "password": "do-not-share",
            "profile": {
                "access_token": "token-value",
                "name": "Ada",
            },
            "items": [{"api-key": "key-value"}, {"count": 2}],
        }

        result = scrub_json(original)

        self.assertEqual(result.replacements, 3)
        self.assertEqual(result.value["password"], DEFAULT_REPLACEMENT)
        self.assertEqual(
            result.value["profile"]["access_token"], DEFAULT_REPLACEMENT
        )
        self.assertEqual(
            result.value["items"][0]["api-key"], DEFAULT_REPLACEMENT
        )
        self.assertEqual(original["password"], "do-not-share")
        self.assertEqual(original["profile"]["access_token"], "token-value")

    def test_custom_keys_and_suffix_variants_are_supported(self):
        self.assertTrue(is_sensitive_key("user_token"))
        result = scrub_json(
            {"national_id": "1234", "display_name": "A"},
            extra_keys=["national_id"],
        )
        self.assertEqual(result.value["national_id"], DEFAULT_REPLACEMENT)
        self.assertEqual(result.value["display_name"], "A")
        self.assertEqual(result.replacements, 1)

    def test_non_sensitive_values_are_preserved(self):
        value = {"token_count": 4, "message": "token accepted"}
        result = scrub_json(value)
        self.assertEqual(result.value, value)
        self.assertEqual(result.replacements, 0)


class ScrubTextTests(unittest.TestCase):
    def test_common_assignments_and_tokens_are_replaced(self):
        github_token = "ghp_" + "x" * 24
        aws_key = "AKIA" + "A" * 16
        text = (
            "password=secret-value "
            f"Authorization: Bearer {'b' * 16} "
            f"keys={github_token} aws={aws_key}"
        )

        result = scrub_text(text)

        self.assertEqual(result.replacements, 4)
        self.assertNotIn("secret-value", result.value)
        self.assertNotIn(github_token, result.value)
        self.assertNotIn(aws_key, result.value)
        self.assertIn(DEFAULT_REPLACEMENT, result.value)

    def test_custom_text_key_is_supported(self):
        result = scrub_text(
            "employee_id=private-123 message=keep",
            extra_keys=["employee_id"],
        )
        self.assertEqual(result.value, "employee_id=[REDACTED] message=keep")
        self.assertEqual(result.replacements, 1)

    def test_unrelated_text_is_not_changed(self):
        text = "status=ok message=hello world"
        result = scrub_text(text)
        self.assertEqual(result.value, text)
        self.assertEqual(result.replacements, 0)


if __name__ == "__main__":
    unittest.main()
