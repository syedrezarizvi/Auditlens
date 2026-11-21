---
name: cache-poisoning-testing
description: Identify web cache deception and cache-key poisoning via unkeyed inputs reflected into cacheable responses.
---
1. Identify cacheable responses: Cache-Control (public/max-age), Age, X-Cache/CF-Cache-Status/Via headers in traffic.
2. Unkeyed header probe: replay_request adding a harmless custom header or unusual Accept/Accept-Encoding/X-Forwarded-* value to a cacheable request, and check whether it changes the response AND whether the response is still served from cache (Age increasing, X-Cache: HIT) on a second identical replay — if so, that header is unkeyed and poison-capable.
3. Cache deception: for an endpoint that returns personalized/sensitive data, try appending a static-looking suffix to the path (e.g. `/account/profile/nonexistent.css`) and see if the app still serves the personalized content while a CDN might cache it as a static asset by extension.
4. Only test with your own test account's data — never attempt to actually poison a shared cache for other users (no need to validate from a second, unauthenticated vantage point against production; describe the risk instead of proving cross-user impact).
5. add_finding describing the unkeyed input, the caching evidence (headers before/after), and remediation (vary header correctly, normalize cache key, disable caching for personalized responses).
