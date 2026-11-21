---
name: open-redirect-ssrf-triage
description: Triage parameters that carry URLs or hosts for open redirect, SSRF indicators and unsafe URL handling, without internal probing.
---
1. search_traffic for params like `url|redirect|next|return|callback|dest|uri|path|file|image|webhook|host`, in query and JSON.
2. Open redirect: replay with the parameter set to `https://ollamaat.invalid/` and inspect for a 3xx Location (or meta/JS redirect) to that host. Also try the protocol-relative form `//ollamaat.invalid/`. A redirect to an arbitrary external host = finding (low/medium depending on auth flow).
3. SSRF indicators: for server-fetches (image proxy, webhook test, import-by-URL), only test with the harmless external `.invalid` host and observe error behaviour/timing differences that show the server attempted a fetch. Do NOT target loopback, link-local, cloud metadata or private ranges, and do not scan ports; those are out of this skill's scope and need explicit pentester instruction.
4. Report indicators as tentative and hand off via send_to_repeater for manual out-of-band confirmation.
