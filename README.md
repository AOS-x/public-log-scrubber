# public-log-scrubber

Remove common credentials from logs before sharing them in an issue, support
ticket, chat, or public gist.

This is a small, dependency-free Python library and command-line tool. It
handles JSON objects, JSON Lines, and plain text. It does not make network
requests, upload input, or mutate the original Python value.

## Why this exists

Debugging often requires sharing logs. Copying logs directly can expose an API
token, password, cookie, or personal identifier. public-log-scrubber gives
teams a simple local last pass before a log leaves a private environment.

It is intentionally narrow. It is not a complete data-loss-prevention system,
secret scanner, or guarantee that all personal data has been removed. Rotate
any credential that may already have been exposed and review the scrubbed
output before publishing it.

## Install from a checkout

~~~bash
python -m pip install .
~~~

The package has no runtime dependencies. The CLI is called log-scrub.

## Command-line examples

Scrub a JSON document:

~~~bash
printf '%s\n' '{"event":"login","password":"do-not-share","message":"ok"}' \
  | log-scrub --format json
~~~

Scrub JSON Lines:

~~~bash
log-scrub --format jsonl application.jsonl > application-safe.jsonl
~~~

Scrub plain-text logs:

~~~bash
cat application.log | log-scrub --format text > application-safe.log
~~~

Check whether a file would need redaction without printing it:

~~~bash
log-scrub --check --format text application.log
~~~

The check command exits with 0 when no matches are found, 1 when a
replacement would be made, and 2 for invalid input or an I/O error.

Add project-specific key names:

~~~bash
log-scrub --format json --key national_id --key internal_case_id input.json
~~~

## Python API

~~~python
from public_log_scrubber import scrub_json, scrub_text

json_result = scrub_json({"password": "hidden", "message": "hello"})
assert json_result.value["password"] == "[REDACTED]"

text_result = scrub_text("Authorization: Bearer example-token-value")
safe_text = text_result.value
~~~

ScrubResult.replacements reports how many values or token matches were
replaced. JSON scrubbing returns a new value and does not mutate the input.

## Maintainer and maintenance plan

AOS-x is the primary maintainer for the public repository. The project is
small by design so review and release work can stay responsive:

- Pull requests receive focused review and regression tests.
- Issues are triaged for false positives, missed credential shapes, and
  portability problems.
- GitHub Actions runs the test suite across supported Python versions.
- Dependabot watches packaging metadata and GitHub Actions.
- Releases are tagged from tested commits and documented in CHANGELOG.md.
- Security reports should use GitHub Private Vulnerability Reporting, not a
  public issue.


## Development

~~~bash
python -m unittest discover -s tests -v
python -m compileall -q src
~~~

When adding a redaction rule, add a small test with synthetic values. Never
commit a real credential, personal identifier, or customer log.

## License

MIT. See LICENSE.
