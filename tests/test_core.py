import unittest

from public_log_scrubber import (
    DEFAULT_REPLACEMENT,
    KNOWN_RULE_IDS,
    DetectionSpan,
    Scrubber,
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

    def test_unicode_custom_keys_only_redact_the_configured_key(self):
        value = {"كلمة_المرور": "hidden", "الاسم": "keep", "名": "keep"}
        result = scrub_json(value, extra_keys=["كلمة_المرور"])
        self.assertEqual(result.value["كلمة_المرور"], DEFAULT_REPLACEMENT)
        self.assertEqual(result.value["الاسم"], "keep")
        self.assertEqual(result.value["名"], "keep")
        self.assertEqual(result.replacements, 1)

    def test_nfkc_casefold_handles_accented_and_full_width_keys(self):
        value = {
            "État": "configured",
            "état": "same-normalized-key",
            "Ｆｕｌｌｗｉｄｔｈ": "configured-too",
            "普通话": "keep",
        }
        result = scrub_json(
            value,
            extra_keys=(
                "état",
                "fullwidth",
            ),
        )

        self.assertEqual(result.value["État"], DEFAULT_REPLACEMENT)
        self.assertEqual(result.value["état"], DEFAULT_REPLACEMENT)
        self.assertEqual(result.value["Ｆｕｌｌｗｉｄｔｈ"], DEFAULT_REPLACEMENT)
        self.assertEqual(result.value["普通话"], "keep")
        self.assertEqual(result.replacements, 3)

    def test_punctuation_only_custom_keys_are_rejected(self):
        with self.assertRaises(ValueError):
            ScrubPolicy(extra_sensitive_keys=("!!!",))
        with self.assertRaises(ValueError):
            scrub_text("!!!=hidden", extra_keys=("!!!",))


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

    def test_assignments_preserve_quotes_and_punctuation(self):
        result = scrub_text('password="hidden", next=ok; token=keep')
        self.assertEqual(
            result.value,
            'password="[REDACTED]", next=ok; token=[REDACTED]',
        )

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

    def test_scrubbing_is_idempotent(self):
        samples = (
            "password=hidden",
            "Authorization: Bearer abcdefgh",
            "GET /events?token=hidden&next=ok",
            'password="hidden"',
        )
        for sample in samples:
            with self.subTest(sample=sample):
                first = scrub_text(sample)
                second = scrub_text(first.value)
                self.assertEqual(second.value, first.value)
                self.assertEqual(second.replacements, 0)
                self.assertEqual(dict(second.rule_counts), {})

    def test_idempotency_covers_json_jsonl_and_custom_replacements(self):
        policy = ScrubPolicy(
            replacement=r"\\safe-$1",
            extra_sensitive_keys=("employee_id",),
        )
        first_json = scrub_json(
            {
                "employee_id": "synthetic-id",
                "message": "https://example.test/?employee_id=synthetic-id",
            },
            policy=policy,
        )
        second_json = scrub_json(first_json.value, policy=policy)
        self.assertEqual(second_json.value, first_json.value)
        self.assertEqual(second_json.replacements, 0)
        self.assertEqual(dict(second_json.rule_counts), {})

        first_lines = list(
            scrub_lines(
                ['{"message":"ghp_aaaaaaaaaaaaaaaaaaaaaaaa"}\n'],
                format="jsonl",
                policy=policy,
            )
        )
        second_lines = list(
            scrub_lines(
                (result.value for result in first_lines),
                format="jsonl",
                policy=policy,
            )
        )
        self.assertEqual(second_lines[0].value, first_lines[0].value)
        self.assertEqual(second_lines[0].replacements, 0)

    def test_specific_detector_wins_over_assignment_without_losing_context(self):
        token = "ghp_" + "a" * 24
        result = scrub_text(f"password={token}")
        self.assertEqual(result.value, "password=[REDACTED]")
        self.assertEqual(dict(result.rule_counts), {"github-token": 1})
        self.assertEqual(sum(result.rule_counts.values()), result.replacements)

    def test_json_string_values_are_scanned_by_default(self):
        token = "ghp_" + "a" * 24
        result = scrub_json({"message": f"failed with {token}"})
        self.assertEqual(result.value, {"message": "failed with [REDACTED]"})
        self.assertEqual(dict(result.rule_counts), {"github-token": 1})

    def test_json_string_scanning_can_be_disabled(self):
        token = "ghp_" + "a" * 24
        result = scrub_json(
            {"message": f"failed with {token}"},
            policy=ScrubPolicy(scan_json_strings=False),
        )
        self.assertIn(token, result.value["message"])
        self.assertEqual(result.replacements, 0)

    def test_prepared_scrubber_reuses_one_engine_for_streaming(self):
        scrubber = Scrubber()
        results = list(
            scrubber.scrub_lines(("password=hidden\n" for _ in range(3)), format="text")
        )
        self.assertEqual([result.replacements for result in results], [1, 1, 1])

    def test_custom_detector_spans_are_replaced_without_exposing_values(self):
        class CaseDetector:
            rule_id = "custom.case-id"
            description = "synthetic case identifiers"

            def find_spans(self, text):
                start = text.find("CASE-")
                return (
                    ()
                    if start < 0
                    else (DetectionSpan(start, start + len("CASE-123456")),)
                )

        result = Scrubber(detectors=(CaseDetector(),)).scrub_text(
            "case CASE-123456 message=ok"
        )
        self.assertEqual(result.value, "case [REDACTED] message=ok")
        self.assertEqual(dict(result.rule_counts), {"custom.case-id": 1})

    def test_custom_detector_ids_and_spans_are_validated(self):
        class BadId:
            rule_id = "case-id"
            description = "bad"

            def find_spans(self, text):
                return ()

        class BadSpan:
            rule_id = "custom.bad-span"
            description = "bad"

            def find_spans(self, text):
                return (DetectionSpan(0, len(text) + 1),)

        with self.assertRaises(ValueError):
            Scrubber(detectors=(BadId(),))
        scrubber = Scrubber(detectors=(BadSpan(),))
        with self.assertRaises(ValueError):
            scrubber.scrub_text("secret")

        class DuplicateId:
            rule_id = "custom.bad-span"
            description = "duplicate"

            def find_spans(self, text):
                return ()

        with self.assertRaises(ValueError):
            Scrubber(detectors=(BadSpan(), DuplicateId()))

        class Overlapping:
            rule_id = "custom.overlap"
            description = "overlap"

            def find_spans(self, text):
                return (DetectionSpan(0, 2), DetectionSpan(1, 3))

        with self.assertRaises(ValueError):
            Scrubber(detectors=(Overlapping(),)).scrub_text("abcd")

    def test_cycles_fail_safely_without_serializing_input(self):
        value = []
        value.append(value)

        with self.assertRaisesRegex(ValueError, "cyclic"):
            scrub_json(value)

    def test_invalid_policy_type_is_rejected(self):
        with self.assertRaises(TypeError):
            scrub_text("password=hidden", policy="not-a-policy")  # type: ignore[arg-type]

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
