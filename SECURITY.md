# Security policy

Version 0.1.x receives security fixes. Report exploitable vulnerabilities
privately to `research@gemacode.org`; do not open a public issue before a fix is
available.

Version 0.1.8 is the minimum safe release for GOVP-STATUS-1. Version 0.1.7 can
miss a revocation when callers supply an otherwise valid record object through
alternate field-name casing; upgrade immediately. Current trust in 0.1.8 also
requires bounded `generated_at` freshness.

Include the affected version, minimal record, expected and observed checks and
practical impact. The project aims to acknowledge complete reports within 72
hours.

GOVP limitations documented by the protocol—such as issuer-asserted time and
the distinction between signature validity and trust—are not vulnerabilities by
themselves.
