# Changelog

All notable changes to this project are documented here.

The format follows the principles of Keep a Changelog, and releases use
semantic versioning.

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
