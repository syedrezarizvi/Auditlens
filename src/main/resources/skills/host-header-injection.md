---
name: host-header-injection
description: Test Host header trust for password-reset poisoning, cache poisoning and routing bypass indicators.
---
1. Find flows where the server reflects the Host header or absolute URLs derived from it: password reset emails/links (can't observe the email itself, but look for the reset link being built from request data in any API response), redirect targets, canonical URLs, CORS reflection.
2. Baseline a relevant request (e.g. password-reset-request endpoint — DO NOT actually submit real recipient data repeatedly; use the pentester's own test account only, once).
3. Safe probe: replay_request with set_headers Host set to an arbitrary attacker-controlled-looking value (`ollamaat.invalid`) and/or add `X-Forwarded-Host: ollamaat.invalid`. Check if any URL in the JSON/HTML response (not just the Host header echo) is built using that value.
4. Cache-poisoning angle: if the response varies by Host/X-Forwarded-Host and the response looks cacheable (Cache-Control, CDN headers), flag this as a cache-poisoning risk too and point to the security-headers-cors and cache-poisoning-testing skills.
5. Do not repeatedly trigger real password-reset emails or any outbound notification; one probe per account is enough. add_finding describing which header controlled which output URL and why that enables reset-link poisoning or routing bypass.
