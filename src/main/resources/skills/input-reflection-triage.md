---
name: input-reflection-triage
description: Find where user input is reflected or stored and judge output-encoding context (XSS triage) using harmless canaries.
---
1. Choose a request with parameters (list_proxy_history with_params=true). Pick text-like parameters, not tokens.
2. Replay with a unique inert canary such as `ollamaat7x1` in ONE parameter (replay_request query_set or body_replace). Use extract/search to see whether and where it appears in the response.
3. Classify context from the response: HTML text, attribute value (quoted/unquoted), JS string, URL, JSON (check Content-Type), HTML comment.
4. Probe encoding with a second canary containing only characters needed for that context, e.g. `ollamaat7x2"'<>`. Compare how each character is returned (raw vs entity-encoded). Raw `<` in HTML text context or raw quote in an attribute context = XSS candidate.
5. Check Content-Type, X-Content-Type-Options and CSP on that response; they change exploitability.
6. Do not send script payloads or event handlers; reporting an unencoded reflection with context is sufficient evidence. Stored input: only re-fetch pages already in traffic.
Confidence: firm when raw dangerous characters are reflected in an exploitable context; tentative otherwise.
