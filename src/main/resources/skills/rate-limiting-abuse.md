---
name: rate-limiting-abuse
description: Passively assess whether sensitive operations (login, OTP, password reset, coupon) have effective rate limiting, without performing a real brute force.
---
1. Identify sensitive, abuse-prone endpoints from traffic: login, OTP/2FA verification, password reset request/confirm, invite/coupon redemption, search/export (cost-heavy).
2. Passive review: does the response include rate-limit headers (`X-RateLimit-*`, `Retry-After`)? Does the app's own documentation/UI mention attempt limits (e.g. "account locked after 5 attempts")?
3. Minimal active probe (needs approval; small volume only): send 3-5 sequential requests with an intentionally wrong value (e.g. wrong OTP) using the pentester's own test account, observing whether the Nth attempt is throttled/blocked/delayed. Stop as soon as you observe either a limit kicking in or reaching 5 attempts — never continue toward an actual brute-force attempt count, and never target another user's account.
4. If no throttling is observed within that small sample, report it as a candidate rather than proven absence — proving absence would require a real brute force, which you must not perform.
5. add_finding (medium, tentative unless you clearly observed unlimited attempts) and recommend the pentester decide whether a larger, explicitly-authorized throttling test is warranted.
