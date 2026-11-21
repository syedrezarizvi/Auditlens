---
name: cryptographic-weaknesses
description: Passive review of transport security, token/ID predictability, and weak cryptographic choices visible in traffic.
---
1. Transport: any in-scope request made over plain HTTP, or HTTPS downgraded via a redirect chain? Missing HSTS (Strict-Transport-Security) on the main host?
2. Token/ID predictability: collect several session ids, password-reset tokens, or object ids issued across different requests (from traffic already captured, not by requesting many new ones) and eyeball for sequential, timestamp-based, or short/low-entropy patterns (extract with a regex to pull several samples and compare lengths/charset/increments).
3. Weak hashing/encoding mistaken for encryption: base64 or hex-encoded values presented as if secure (convert to decode and check if it's just encoded plaintext, e.g. an encoded "userId:role" pair with no signature).
4. JWT algorithm/key issues: reuse jwt-review for alg confusion, missing expiry, weak/default signing hints.
5. Mixed content: HTTPS pages loading HTTP sub-resources (check Content-Security-Policy / resource URLs in HTML responses).
6. Do not attempt to actually break a cryptographic primitive (no offline brute force of hashes, no attempts to forge signatures without a known key) — report the weakness pattern (e.g. "sequential reset tokens observed: 10234, 10235, 10236") as evidence.
7. add_finding per distinct weakness with the observed samples (redact if sensitive) and concrete remediation (CSPRNG tokens, HSTS, proper JWT validation, TLS-everywhere).
