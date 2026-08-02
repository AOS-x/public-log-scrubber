# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security vulnerability, credential
pattern bypass, or accidental secret exposure.

Use GitHub Private Vulnerability Reporting:

https://github.com/AOS-x/public-log-scrubber/security/advisories/new

Include the affected version, a minimal synthetic reproduction, and the
potential impact. Do not include a real credential or private log.

## Scope and limitations

This project is a local redaction helper, not a complete DLP system. It has no
network code and cannot prove that arbitrary secrets or personal data are
absent. Users should review output and rotate credentials if exposure is
possible.
