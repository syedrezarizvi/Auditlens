---
name: authn-session-review
description: Review authentication and session handling from traffic: cookie flags, token storage, fixation, logout, CSRF, password flows.
---
Passive first (no new requests):
1. Find login/refresh/logout/reset flows with list_endpoints and search_traffic `login|signin|token|session|reset|otp|mfa`.
2. Inspect Set-Cookie on the login response: Secure, HttpOnly, SameSite, Path, Domain, expiry. Session id in URL? Credentials over HTTP?
3. Does the session identifier change after login (compare pre/post login cookies)? If not, session fixation candidate.
4. State-changing requests: is there an anti-CSRF token or a custom header requirement? Is SameSite relied upon?
5. Tokens in JSON/localStorage patterns: use convert kind=jwt to decode and apply the jwt-review skill.
6. Error messages on login/reset: differences that reveal valid accounts (compare_messages on captured failures).
Active (needs approval, tiny volume): replay one authenticated request after removing the cookie to confirm the server really enforces the session; do NOT test logout/reset endpoints (they are blocked) and never brute force.
