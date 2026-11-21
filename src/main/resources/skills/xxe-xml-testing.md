---
name: xxe-xml-testing
description: Review XML/SOAP-accepting endpoints for XXE and unsafe parser configuration using non-exfiltrating entity probes.
---
1. Find XML/SOAP endpoints: Content-Type application/xml, text/xml, application/soap+xml in captured traffic, or file uploads accepting .xml/.svg/.docx-like formats.
2. Baseline: replay the captured XML body unchanged to confirm you can resend it (get_message, then replay_request with body unchanged first).
3. Internal entity probe (safe): add a DOCTYPE defining an entity that resolves to a short harmless local string (not a file path) and reference it in a field the response echoes, e.g. `<!DOCTYPE x [<!ENTITY e "ollamaat-xxe-test">]>` then `&e;` in a text field. If `ollamaat-xxe-test` appears in the response, external entity substitution is active in principle.
4. Do NOT reference `file://`, internal URLs, `php://filter`, or any SSRF-capable external entity — that would read real files or reach internal systems. If step 3 shows entity substitution is enabled, that alone (general entity expansion active) is enough to report as a candidate; let the pentester decide whether to pursue file-read testing manually with explicit authorization.
5. Also check for permissive parsing generally: whether a DOCTYPE at all is accepted without error (some parsers reject any DOCTYPE, which is good practice) and note billion-laughs protections are out of scope here (no expansion/DoS payloads).
6. add_finding describing entity-substitution behaviour observed, the exact DOCTYPE used, and recommend disabling external entity resolution/DTD processing.
