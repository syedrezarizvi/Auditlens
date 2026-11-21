---
name: jwt-review
description: Review JWT/bearer token usage: claims, algorithm, lifetime, storage, and server-side validation behaviour.
---
1. Locate tokens: search_traffic `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.`; extract the token from the request/response.
2. convert kind=jwt. Note alg, kid, jku/x5u (attacker-controlled key URLs are a smell), iss/aud, exp/iat (lifetime), and claims carrying authorization data (role, admin, tenant, user id).
3. Static issues: alg none/HS256 with a guessable-looking secret cannot be tested here; report only what is observable (long lifetime, sensitive data in payload, no exp, token in URL).
4. Validation tests (need approval, tiny volume): replay one authenticated request with (a) the signature part removed, (b) a payload byte altered (the token must be rejected with 401). Acceptance of either = candidate. Do not forge privileged claims against production data.
5. Check refresh/logout: does the token stay valid after logout (replay a captured request later)? Logout endpoints are blocked, so only test with a previously captured logout, if the pentester provided one.
