# Contributing

Thanks for helping make shared logs safer.

## Before opening a pull request

- Keep the change focused.
- Add or update tests for every redaction rule.
- Use synthetic values only; never commit real credentials or private logs.
- Document false-positive or false-negative trade-offs.
- Run python -m unittest discover -s tests -v.

## Pull requests

Explain the user problem, the behavior change, and the validation you ran.
Security-sensitive changes may receive an additional focused review before
merge.

## Releases

The primary maintainer tags releases from tested commits using semantic
versioning. Update CHANGELOG.md, run the full test suite, and describe
limitations or migration notes in the GitHub release.
