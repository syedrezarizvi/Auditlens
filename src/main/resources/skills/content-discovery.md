---
name: content-discovery
description: Discover hidden directories, backup files, and leftover admin/debug endpoints using targeted, low-volume probes against common paths.
---
1. Review what the app already reveals (robots.txt, sitemap.xml, any captured 404/403 custom pages that might leak a path structure) before sending new requests.
2. Build a SHORT, targeted candidate list (10-20 paths max per host, not a generic wordlist sweep) based on what the app's stack/framework suggests from headers and JS filenames: `.git/config`, `.env`, `.env.local`, `web.config`, `/actuator/health`, `/actuator/env`, `/swagger.json`, `/openapi.json`, `/api/docs`, `/.well-known/security.txt`, `/admin`, `/debug`, `/_profiler`, `/graphql` (if not already found), common backup suffixes on a file you already know exists (`.bak`, `.old`, `~`, `.zip` on the main index page's path).
3. Send each candidate as a single GET via send_request (respect the normal request budget and rate limit — do not fan out hundreds of guesses). Treat a 200/3xx with real content, or a 403 (exists but blocked) as a hit; 404 is not.
4. For each hit, get_message to confirm it's not a generic catch-all/soft-404 page (compare body length/content against a known-404 response).
5. Never attempt to brute-force a large wordlist, enumerate usernames at volume, or download/exfiltrate the contents of discovered backup/config files beyond confirming they exist and skimming for an obvious secret (then follow sensitive-data-exposure's redaction rule).
6. add_finding per real hit (severity depends on content: exposed `.git`/`.env` is high; an open debug endpoint without data is medium); note_add the full candidate list and which were tried so repeat runs don't resend them.
