# Maintaining public-log-scrubber

AOS-x is the primary maintainer of this public repository. The project is
small by design so reviews, security fixes, and releases can remain responsive.

## Regular maintenance

- Triage new issues for missed credential shapes, false positives, portability,
  and unsafe output behavior.
- Reproduce reports with synthetic values only; never request a private log or
  real credential in a public issue.
- Review pull requests for tests, documented trade-offs, and the local-only
  guarantee.
- Review Dependabot pull requests weekly and GitHub Actions updates monthly.
- Run the full test, lint, type-check, and distribution-build checks before a
  release.
- Publish release notes with detector changes, compatibility notes, and known
  limitations.
- Exercise the logging formatter and pre-commit hook with synthetic fixtures;
  these integrations must remain fail-closed and local-only.

## Security handling

Use GitHub Private Vulnerability Reporting for bypasses, accidental exposure,
or vulnerabilities. Do not copy a reported credential into an issue, test, or
log. Add a synthetic regression test after the fix is understood.

## Release process

1. Confirm the working tree and CI are clean.
2. Update `CHANGELOG.md` and the package version in `pyproject.toml` and
   `src/public_log_scrubber/__init__.py`.
3. Run the complete local validation commands from the README.
4. Merge the release pull request into `main`.
5. Create a GitHub release for the matching tag.
6. The release workflow builds an sdist and wheel, attests provenance, and
   publishes through the PyPI trusted publisher.

For v0.2.1, release only reliability fixes. For v0.3.0, also verify the
prepared `Scrubber`, JSON string scanning, custom-detector validation, logging
formatter, pre-commit hook, `py.typed`, and `--list-rules`/`--version` smoke
tests. Do not close the PyPI publication issue until the public package page
and a clean installation have both been checked.

The first PyPI release also requires configuring the `pypi` GitHub environment
and trusted publisher in the PyPI project settings.

## Pilot feedback and adoption

Invite users to a public pilot-feedback issue and request only synthetic
examples, operating-system/Python information, approximate file size, and safe
rule counts. Do not request private logs or credentials. Record an adopter,
integration, download metric, or testimonial only with permission and a
verifiable public link; never manufacture users, downloads, or historical
maintenance activity. A v0.3.1 should be driven by real feedback and not by a
calendar target.

## How Codex/API credits help

Credits are useful for concrete maintenance work that benefits users:

- review pull requests for missed regressions and unsafe redaction behavior;
- generate focused synthetic tests for new token formats;
- reproduce and triage issue reports without sending log input to a remote
  service;
- review Dependabot and GitHub Actions dependency updates;
- prepare release notes and verify package artifacts;
- perform security-focused regression reviews and keep detector documentation
  accurate.

All work must preserve the project’s local-only boundary. Real logs,
credentials, and customer data must not be sent to Codex or committed to the
repository.
