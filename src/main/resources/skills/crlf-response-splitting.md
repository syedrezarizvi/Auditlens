---
name: crlf-response-splitting
description: Detect CRLF injection into response headers leading to header injection, response splitting or reflected header-based XSS.
---
1. Candidate parameters: anything echoed into a redirect Location header, a Set-Cookie value, or any other response header (check via input-reflection-triage first to find header-context reflection, not just body reflection).
2. Probe: replay_request inserting an encoded CRLF sequence (`%0d%0a`) followed by a new harmless header name/value (e.g. `%0d%0aX-Ollamaat-Test:%201`) into the suspect parameter.
3. Confirm by checking get_message (response) for the injected header appearing as a real header in the response (not just reflected in the body) — this is the proof, not just the encoded string being present somewhere.
4. If the injected header lands inside the body only (not as a real header), the platform/framework is likely normalizing it — note as not vulnerable rather than guessing.
5. Do not attempt full response splitting (injecting a second complete HTTP response) — a single extra header is sufficient evidence of the underlying flaw.
6. add_finding with the exact encoded payload, both refs, and remediation (reject/encode CR/LF in any value written to a header, use the framework's header-setting API rather than raw string concatenation).
