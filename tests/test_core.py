import unittest

from public_log_scrubber import (
    DEFAULT_REPLACEMENT,
    KNOWN_RULE_IDS,
    ScrubPolicy,
    is_sensitive_key,
    scrub_json,
    scrub_lines,
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
        self.assertEqual(result.value["profile"]["access_token"], DEFAULT_REPLACEMENT)
        self.assertEqual(result.value["items"][0]["api-key"], DEFAULT_REPLACEMENT)
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

    def test_url_query_parameters_preserve_other_parameters(self):
        result = scrub_text(
            "GET /events?access_token=private-value&next=page-2 HTTP/1.1"
        )
        self.assertEqual(
            result.value,
            "GET /events?access_token=[REDACTED]&next=page-2 HTTP/1.1",
        )
        self.assertEqual(result.replacements, 1)

    def test_unrelated_text_is_not_changed(self):
        text = "status=ok message=hello world"
        result = scrub_text(text)
        self.assertEqual(result.value, text)
        self.assertEqual(result.replacements, 0)

    def test_all_high_confidence_detectors_have_stable_rule_ids(self):
        samples = {
            "github-token": "ghp_" + "a" * 24,
            "github-fine-grained-token": "github_pat_" + "a" * 24,
            "aws-access-key": "AKIA" + "A" * 16,
            "jwt": "eyJabcde.abcdef.ghijkl",
            "openai-key": "sk-" + "a" * 24,
            "slack-token": "xoxb-" + "a" * 16,
            "gitlab-token": "glpat-" + "a" * 24,
            "stripe-key": "sk_live_" + "a" * 20,
            "database-url-password": "postgres://user:secret@db.example",
            "bearer-token": "Bearer " + "b" * 16,
            "basic-credentials": "Basic " + "YWFhYWFhYWFh",
        }

        for rule_id, sample in samples.items():
            with self.subTest(rule_id=rule_id):
                result = scrub_text(sample)
                self.assertEqual(result.rule_counts, {rule_id: 1})
                self.assertNotIn(sample.split()[-1], result.value)
                self.assertIn(rule_id, KNOWN_RULE_IDS)

    def test_detector_can_be_disabled_without_affecting_other_rules(self):
        github_token = "ghp_" + "a" * 24
        policy = ScrubPolicy(disabled_rules=("github-token",))

        result = scrub_text(f"github={github_token} aws=AKIA{'A' * 16}", policy=policy)

        self.assertIn(github_token, result.value)
        self.assertNotIn("AKIA" + "A" * 16, result.value)
        self.assertNotIn("github-token", result.rule_counts)

    def test_custom_keys_are_applied_to_url_parameters(self):
        result = scrub_text(
            "GET /case?employee_id=private-123&next=page-2",
            extra_keys=["employee_id"],
        )
        self.assertEqual(
            result.value,
            "GET /case?employee_id=[REDACTED]&next=page-2",
        )
        self.assertEqual(result.rule_counts, {"url-sensitive-parameter": 1})

    def test_replacement_text_is_literal_even_when_it_looks_like_regex(self):
        replacement = r"\\1-$&"
        result = scrub_text("password=hidden", replacement=replacement)
        self.assertEqual(result.value, f"password={replacement}")

    def test_policy_rejects_unknown_rules_and_non_string_keys(self):
        with self.assertRaises((ValueError, TypeError)):
            ScrubPolicy(disabled_rules=("not-a-rule",))
        with self.assertRaises((ValueError, TypeError)):
            ScrubPolicy(extra_sensitive_keys=("valid", 7))  # type: ignore[arg-type]
        with self.assertRaises((ValueError, TypeError)):
            ScrubPolicy(replacement="")

    def test_json_custom_key_can_be_disabled(self):
        result = scrub_json(
            {"employee_id": "private-123"},
            extra_keys=["employee_id"],
            policy=ScrubPolicy(disabled_rules=("custom-key",)),
        )
        self.assertEqual(result.value, {"employee_id": "private-123"})
        self.assertEqual(result.replacements, 0)

    def test_scrub_lines_is_lazy_and_preserves_jsonl_endings(self):
        consumed = []

        def lines():
            for line in ('{"password":"one"}\r\n', '{"ok":true}'):
                consumed.append(line)
                yield line

        results = scrub_lines(lines(), format="jsonl")
        self.assertEqual(consumed, [])
        first = next(results)
        self.assertEqual(consumed, ['{"password":"one"}\r\n'])
        self.assertEqual(first.value, '{"password":"[REDACTED]"}\r\n')
        self.assertEqual(next(results).value, '{"ok":true}')

    def test_scrub_lines_reports_malformed_json_without_echoing_input(self):
        with self.assertRaisesRegex(ValueError, "invalid JSON on line 2"):
            list(
                scrub_lines(
                    ['{"password":"secret"}\n', '{"broken":'],
                    format="jsonl",
                )
            )


if __name__ == "__main__":
    unittest.main()
