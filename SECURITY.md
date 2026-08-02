# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security vulnerability, credential
pattern bypass, or accidental secret exposure.

Use GitHub Private Vulnerability Reporting:

https://github.com/AOS-x/public-log-scrubber/security/advisories/new

Include the affected version, a minimal synthetic reproduction, and the
potential impact. Do not include a real credential or private log.

## Threat model

The tool protects against accidental disclosure when a user intentionally
runs it over a log before sharing the resulting output. It is designed to
reduce the chance that common, high-signal credentials remain in copied text,
JSON, or JSONL. JSON string values are scanned by default; callers can opt out
with `scan_json_strings: false` when they explicitly need older key-only
behavior.

The tool does not protect against:

- secrets that do not match a built-in rule or configured key;
- secrets split across text lines when using streaming text mode;
- secrets hidden in binary data, screenshots, archives, or encoded payloads;
- secrets in directories or archives that were never passed to the tool;
- personal data that is not configured for redaction;
- a compromised local machine, shell history, terminal scrollback, or output
  destination;
- a user who shares the original input instead of the scrubbed output.

The process has no network code and does not upload input. Reports contain only
rule IDs and counts. A scrubbed result is not a compliance certification or a
proof that all secrets and personal data have been removed. Review output and
rotate credentials if exposure is possible.

Overlapping findings are resolved before replacement. Provider/token-specific
rules take precedence over explicitly registered Python detectors, URL
parameters, and generic assignments. This makes reports more useful but does
not increase coverage.

Custom detectors and `ScrubbingFormatter` run trusted local Python code. A
custom detector can inspect log text, so register only code that the maintainer
has reviewed. The pre-commit hook prints safe summaries rather than matching
lines, but pre-commit itself still runs on the local workstation and does not
replace review of the resulting files.

## Scope and limitations

The default profile intentionally avoids generic email, phone, IP-address, and
payment-card detection because false positives can make diagnostic logs less
useful. Add project-specific keys through a policy file or `--key` when the
local data policy requires it.

The project intentionally does not provide arbitrary regular expressions in
JSON policies, entropy detection, broad PII profiles, directory recursion, or
archive scanning. Those omissions are documented boundaries rather than a
claim that the input is safe after one pass.
