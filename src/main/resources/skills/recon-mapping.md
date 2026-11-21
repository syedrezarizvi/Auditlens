---
name: recon-mapping
description: Map the application from captured traffic: endpoints, roles, parameters, tech stack, trust boundaries. Start here.
---
Goal: build a prioritised picture of the attack surface WITHOUT sending new traffic.
1. Call list_endpoints (no filters) and note hosts, API prefixes (/api, /v1, /graphql), and id-bearing paths ({n}/{uuid}).
2. Identify authentication artefacts: search_traffic for `authorization|set-cookie|csrf|token|jwt` and note where credentials travel (header, cookie, body).
3. Identify roles/tenants: look for user ids, org ids, role names in responses (get_message on 2-3 representative JSON responses).
4. Identify technology hints: Server/X-Powered-By headers, error formats, framework-specific paths.
5. Rank targets by risk: endpoints that take object ids, change state (POST/PUT/PATCH/DELETE), upload files, accept URLs, render user input, or sit behind admin-like paths.
6. note_add the ranked list (title "Attack surface") so later runs reuse it. Finish with the top 5 hypotheses to test and which skill fits each.
