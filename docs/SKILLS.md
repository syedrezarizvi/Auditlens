# Built-in skills

Skills are methodology notes the agent loads on demand (`load_skill`). Each is a Markdown file with `name` and `description` front matter, bundled from `src/main/resources/skills/` and listed in `index.txt`.
You can add your own: point **Settings → Custom skills folder** at a folder of `.md` files with the same front matter. A custom skill with the same `name` as a built-in one replaces it.

There are **36 built-in skills**.

| Skill | What it covers |
|---|---|
| `access-control-idor` | Test broken object-level and function-level access control (IDOR/BOLA, missing auth, privilege escalation) by controlled replay. |
| `api-mass-assignment` | Test property-level authorization and mass assignment on JSON/form APIs, plus excessive data exposure. |
| `authn-session-review` | Review authentication and session handling from traffic: cookie flags, token storage, fixation, logout, CSRF, password flows. |
| `business-logic-review` | Passive review of workflows for logic flaws: step skipping, client-side trust, price/quantity manipulation candidates, state machines. |
| `cache-poisoning-testing` | Identify web cache deception and cache-key poisoning via unkeyed inputs reflected into cacheable responses. |
| `clickjacking-ui-redress` | Passive review for missing frame protections on sensitive, state-changing pages. |
| `clickjacking-ui-redressing` | Alias entry point; see clickjacking-ui-redress for the full methodology. |
| `command-injection-testing` | Detect OS command injection via safe, non-destructive arithmetic/time markers in parameters that may reach a shell. |
| `content-discovery` | Discover hidden directories, backup files, and leftover admin/debug endpoints using targeted, low-volume probes against common paths. |
| `crlf-response-splitting` | Detect CRLF injection into response headers leading to header injection, response splitting or reflected header-based XSS. |
| `cryptographic-weaknesses` | Passive review of transport security, token/ID predictability, and weak cryptographic choices visible in traffic. |
| `csv-formula-injection` | Test for CSV/Excel formula injection in data that is later exportable to spreadsheet format. |
| `file-upload-testing` | Review file-upload functionality for unrestricted type/extension handling, path traversal in filenames, and unsafe storage, using harmless files only. |
| `finding-quality` | Checklist to apply before add_finding so reports are accurate, reproducible and honest about confidence. |
| `graphql-security` | Assess a GraphQL endpoint for introspection exposure, excessive data exposure, missing depth/complexity limits and BOLA via field-level access. |
| `host-header-injection` | Test Host header trust for password-reset poisoning, cache poisoning and routing bypass indicators. |
| `http-request-smuggling` | Passive and low-risk active checks for CL.TE/TE.CL desync conditions in front-end/back-end chains. |
| `injection-signals` | Detect SQL/NoSQL/template/command injection signals via error and behavioural differences, without exploitation. |
| `input-reflection-triage` | Find where user input is reflected or stored and judge output-encoding context (XSS triage) using harmless canaries. |
| `insecure-deserialization` | Spot insecure deserialization surfaces (Java, PHP, Python pickle, .NET, Node) from traffic without attempting gadget-chain exploitation. |
| `jwt-review` | Review JWT/bearer token usage: claims, algorithm, lifetime, storage, and server-side validation behaviour. |
| `ldap-xpath-injection` | Detect LDAP and XPath injection in directory-lookup or XML-query features using syntax-only probes. |
| `nextjs-react-vulnerabilities` | Test Next.js and React applications for framework-specific flaws: middleware-only authorization bypass, Server Actions reachable without authorization, secrets in __NEXT_DATA__, dangerouslySetInnerHTML and javascript: URL XSS, image optimizer SSRF, source map exposure, and outdated framework versions. |
| `open-redirect-ssrf-triage` | Triage parameters that carry URLs or hosts for open redirect, SSRF indicators and unsafe URL handling, without internal probing. |
| `path-traversal-lfi` | Detect path traversal and local file inclusion in parameters that reference files, templates or static resources. |
| `prototype-pollution-dom-xss` | Review client-side JavaScript and DOM sinks for prototype pollution and DOM-based XSS using static analysis of captured JS, plus harmless URL-fragment probes. |
| `race-condition-testing` | Identify likely time-of-check/time-of-use race conditions (coupon redemption, balance transfer, limited-use tokens) from application logic, flagged for supervised parallel testing. |
| `rate-limiting-abuse` | Passively assess whether sensitive operations (login, OTP, password reset, coupon) have effective rate limiting, without performing a real brute force. |
| `recon-mapping` | Map the application from captured traffic: endpoints, roles, parameters, tech stack, trust boundaries. Start here. |
| `security-headers-cors` | Passive review of security headers, CORS, caching and information disclosure across responses. |
| `sensitive-data-exposure` | Passive sweep of in-scope traffic for exposed secrets, PII and internal data in responses, errors, comments and client-side code. |
| `sql-injection-testing` | Confirm SQL injection via error, boolean and time-based signals, and map extraction surface without dumping data. |
| `ssti-testing` | Identify server-side template injection by testing arithmetic expressions specific to common template engines. |
| `subdomain-cors-takeover` | Spot dangling-CNAME subdomain takeover risk and unsafe CORS trust from in-scope hostnames and headers, passively. |
| `websocket-security` | Review WebSocket handshake and message handling for origin validation, authentication and injection issues. |
| `xxe-xml-testing` | Review XML/SOAP-accepting endpoints for XXE and unsafe parser configuration using non-exfiltrating entity probes. |
