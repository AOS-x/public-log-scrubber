# Changelog

All notable changes to this project are documented here.

The format follows the principles of Keep a Changelog, and releases use
semantic versioning.

## [0.3.0] - 2026-08-02

### Added

- Reusable `Scrubber`, value-free `DetectionSpan`, trusted Python detector
  protocol, stable `RuleInfo` metadata, `list_rules()`, and `--list-rules`.
- JSON string scanning by default with a `scan_json_strings` compatibility
  opt-out.
- Standard-library `ScrubbingFormatter` with fail-closed behavior.
- `log-scrub-pre-commit` and the repository pre-commit hook manifest.
- `load_policy()`, `py.typed`, report schema/version fields, and `--version`.

### Changed

- Prepared engines compile shared patterns and normalized keys once per
  operation, then resolve overlapping findings by detector specificity.
- Provider/token-specific findings receive attribution over generic assignment
  findings, while replacement counts remain internally consistent.
- Documentation now covers integrations, idempotency, JSON string scanning,
  trusted custom detectors, and the threat-model boundaries.

## [0.2.1] - 2026-08-02

### Fixed

- Preserve Unicode custom-key matching without treating every non-Latin key as
  the same key.
- Make repeated scrubbing idempotent, including the default replacement marker.
- Preserve assignment quotes and punctuation while redacting values.
- Validate policy types before applying a policy.
- Stage output and report files before committing either destination.
- Return a safe operational error for recursion failures.

## [0.2.0] - 2026-08-02

### Added

- Immutable `ScrubPolicy` configuration and stable detector rule IDs.
- High-confidence JWT, OpenAI, Slack, GitLab, Stripe, database-URL, and
  authorization-token detection.
- Lazy text and JSONL scrubbing through the `scrub_lines()` API.
- JSON policy files, safe count reports, atomic output files, and overwrite
  protection.
- Expanded regression tests, static checks, distribution builds, macOS smoke
  testing, PyPI trusted publishing, and build provenance attestations.
- Threat-model and maintainer documentation.

### Changed

- Replacement text is always treated literally, including backslashes and
  regex-like characters.
- JSONL output preserves blank lines and original line endings.
- Package metadata is maintained in `pyproject.toml` only.

## [0.1.0] - 2026-08-02

### Added

- Dependency-free Python API for scrubbing JSON-compatible values.
- CLI support for JSON, JSON Lines, and plain-text logs.
- Conservative patterns for common bearer, basic, GitHub, and AWS-style
  credentials.
- Custom sensitive-key support and check-only mode.
- Tests, CI, Dependabot, issue templates, security policy, and contribution
  guidance.
