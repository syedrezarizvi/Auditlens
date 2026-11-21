---
name: security-headers-cors
description: Passive review of security headers, CORS, caching and information disclosure across responses.
---
1. list_endpoints, then get_message (response) on a main HTML page, an authenticated API response, and a static asset.
2. Check: Content-Security-Policy (unsafe-inline/eval, wildcards), Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options/frame-ancestors, Referrer-Policy, Permissions-Policy, Cache-Control on authenticated or sensitive responses.
3. CORS: for API responses note Access-Control-Allow-Origin and -Credentials. One safe active test: replay_request adding header Origin: https://ollamaat.invalid and see if it is reflected with Allow-Credentials true (reflected origin + credentials = candidate; wildcard with credentials is invalid and not a finding).
4. Disclosure: Server/X-Powered-By versions, verbose errors, internal hostnames/IPs, source maps, debug endpoints seen in traffic (search_traffic `\.map|debug|trace|stack`).
5. Group findings by root cause; one finding per missing control per host, severity low/info unless combined with an exploitable condition.
