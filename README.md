# public-log-scrubber

[![CI](https://github.com/AOS-x/public-log-scrubber/actions/workflows/ci.yml/badge.svg)](https://github.com/AOS-x/public-log-scrubber/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Scrub high-confidence credentials from diagnostic logs before sharing them in
an issue, support ticket, chat, or public gist.

public-log-scrubber is a small, dependency-free Python library and CLI for
support engineers, SREs, and open-source maintainers. It handles JSON objects,
JSON Lines, and plain text. It runs locally, makes no network requests, and
does not mutate the original Python value.

## Why this exists

Debugging often requires sharing logs. Copying logs directly can expose an API
token, password, cookie, or connection-string password. `public-log-scrubber`
provides a local last pass before a log leaves a private environment.

It is intentionally narrow: it is not a complete data-loss-prevention system,
secret scanner, or guarantee that all personal data has been removed. Review
the output before publishing it and rotate any credential that may already
have been exposed.

## Guarantees and boundaries

- Runtime dependencies: none.
- Network access: none; input is never uploaded or sent to a service.
- JSON input: copied and scrubbed without mutating the source value.
- Text and JSONL: stream line-by-line when `--format text` or `--format jsonl`
  is selected.
- Standard JSON documents and `--format auto`: buffered because complete JSON
  parsing is required.
- Reports contain counts and rule IDs, never matched values.
- A successful result does not prove that arbitrary secrets or personal data
  are absent. See [SECURITY.md](SECURITY.md) for the threat model.

## Install

After the first PyPI release:

~~~bash
python -m pip install public-log-scrubber
~~~

From a checkout:

~~~bash
python -m pip install .
~~~

The installed command is `log-scrub`.

## Quick start

Scrub a JSON document:

~~~bash
printf '%s\n' '{"event":"login","password":"do-not-share","message":"ok"}' \
  | log-scrub --format json
~~~

The output contains `[REDACTED]` in place of the password. Scrub a text log
to a new file:

~~~bash
log-scrub --format text application.log --output application-safe.log
~~~

`--output` refuses to overwrite an existing file unless `--force` is supplied.
Output files are written through a temporary file and atomically replaced only
after successful processing.

## Command-line usage

Stream plain text:

~~~bash
cat application.log | log-scrub --format text > application-safe.log
~~~

Stream JSON Lines while preserving blank lines and line endings:

~~~bash
log-scrub --format jsonl application.jsonl > application-safe.jsonl
~~~

Check whether a log needs redaction without printing any input or output:

~~~bash
log-scrub --check --format text application.log
~~~

Exit codes are `0` when the input is clean or processing succeeds, `1` when
`--check` finds a match, and `2` for invalid input or an I/O error.

Write a safe machine-readable summary:

~~~bash
log-scrub --format jsonl application.jsonl \
  --output application-safe.jsonl \
  --report application-safe.report.json
~~~

The report has this shape and never contains secret values:

~~~json
{
  "replacements": 2,
  "rule_counts": {
    "json-sensitive-key": 1,
    "github-token": 1
  }
}
~~~

## Policy files

Use a JSON policy file for repeatable local workflows:

~~~json
{
  "replacement": "<REMOVED>",
  "extra_sensitive_keys": ["employee_id", "internal_case_id"],
  "disabled_rules": []
}
~~~

~~~bash
log-scrub --format text --policy scrub-policy.json input.log
~~~

Policy files reject unknown fields, non-string keys, empty replacements, and
unknown detector IDs. Command-line `--replacement` overrides the policy
replacement, and repeated `--key` values append to the policy keys.

## Supported detector rules

The default profile targets high-confidence credential shapes. It deliberately
does not redact ordinary emails, phone numbers, IP addresses, or payment-card
numbers.

| Rule ID | Detects |
| --- | --- |
| `json-sensitive-key` | Credential-like JSON keys such as `password` and `access_token` |
| `custom-key` | Keys supplied through `--key` or `extra_sensitive_keys` |
| `url-sensitive-parameter` | Credential-like URL query parameters |
| `assignment-sensitive-key` | Text assignments such as `password=...` |
| `github-token` | Classic GitHub token prefixes |
| `github-fine-grained-token` | Fine-grained GitHub token prefixes |
| `aws-access-key` | AWS access-key prefixes |
| `jwt` | JWT-shaped three-part tokens |
| `openai-key` | OpenAI `sk-` key shapes |
| `slack-token` | Slack `xox...` token shapes |
| `gitlab-token` | GitLab `glpat-` token shapes |
| `stripe-key` | Stripe test/live secret and restricted key shapes |
| `database-url-password` | Passwords embedded in supported database URLs |
| `bearer-token` | Bearer authorization values |
| `basic-credentials` | Basic authorization values |

Disable a rule only when the false-positive trade-off is understood:

~~~json
{
  "disabled_rules": ["jwt"]
}
~~~

## Python API

~~~python
from public_log_scrubber import ScrubPolicy, scrub_json, scrub_text

policy = ScrubPolicy(
    replacement="<REMOVED>",
    extra_sensitive_keys=("employee_id",),
)

json_result = scrub_json(
    {"password": "hidden", "employee_id": "case-123", "message": "hello"},
    policy=policy,
)
assert json_result.value["password"] == "<REMOVED>"
assert json_result.rule_counts["json-sensitive-key"] == 1

text_result = scrub_text(
    "Authorization: Bearer example-token-value",
    policy=policy,
)
safe_text = text_result.value
~~~

`ScrubResult` exposes `value`, `replacements`, and safe `rule_counts`.
Existing calls using `extra_keys` and `replacement` remain supported.

For a streaming library workflow, use `scrub_lines()` with `format="text"` or
`format="jsonl"`. It yields each scrubbed line lazily.

## Maintenance

AOS-x is the primary maintainer. The project uses focused pull requests,
regression tests for each detector, GitHub Actions across supported Python
versions, Dependabot, documented releases, and private vulnerability reports.
See [MAINTAINING.md](MAINTAINING.md) for the operating workflow and the
specific ways Codex/API credits support it.

## Development

~~~bash
python -m pip install -e ".[dev]"
python -m unittest discover -s tests -v
python -m ruff format --check .
python -m ruff check .
python -m mypy src/public_log_scrubber
python -m build --sdist --wheel
~~~

When adding a detector, use synthetic values only. Never commit a real
credential, personal identifier, or customer log.

## License

MIT. See [LICENSE](LICENSE).
