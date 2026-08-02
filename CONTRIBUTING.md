# Contributing

Thanks for helping make shared logs safer.

## Before opening a pull request

- Keep the change focused.
- Add or update tests for every redaction rule.
- Use synthetic values only; never commit real credentials or private logs.
- Document false-positive or false-negative trade-offs.
- Run `python -m unittest discover -s tests -v`.
- Run `python -m ruff format --check .`, `python -m ruff check .`, and
  `python -m mypy src/public_log_scrubber` when development dependencies are
  installed.
- Run `python -m pre_commit validate-manifest .pre-commit-hooks.yaml` and
  verify that pre-commit output contains no matching lines or values.
- Exercise `ScrubbingFormatter` and `log-scrub-pre-commit` with synthetic
  messages before changing integration behavior.

## Pull requests

Explain the user problem, the behavior change, and the validation you ran.
Security-sensitive changes may receive an additional focused review before
merge.

Do not include real logs, credentials, or personal data in an issue or pull
request. Use a private security advisory for bypasses or accidental exposure.

## Releases

The primary maintainer tags releases from tested commits using semantic
versioning. Update CHANGELOG.md, run the full test suite, and describe
limitations or migration notes in the GitHub release.
