# Changelog

All notable changes to AuditLens are recorded here. The project has no tagged releases yet; entries are
grouped by the development build they shipped in (`patched-vN`). The newest build is listed first.

## Unreleased — build 23

### Added
- **CAPTCHA detection (informational).** Passive analysis now notes when an HTML page protects an action with Google reCAPTCHA, hCaptcha, Cloudflare Turnstile or a generic CAPTCHA input. The finding says automated testing of that flow is limited and suggests manual testing with test accounts. AuditLens does not solve, bypass or evade CAPTCHAs.

### Added
- **Triage selected (AI)** button on the Findings tab. It runs the AI false-positive check on the selected rows only. The right-click item *Re-check selected with AI* does the same.

### Changed — BApp Store readiness
- **Declare AI support (`enhancedCapabilities()` → `AI_FEATURES`).** Without this flag Burp keeps `api.ai()` disabled, so Burp AI (the default provider) never worked and the per-extension "Use AI" checkbox never appeared. Required by the BApp Store AI extension best practices. The Burp AI "not enabled" message now points to the exact checkbox.
- **Clean unload.** `stop()` now advances the run id so the triage and proxy-review background loops exit promptly on cancel or extension unload (they already checked it; `stop()` didn't signal it). Short UI worker threads now run on daemon threads so they can't pile up across reloads.
- **Cope with large projects.** The in-memory evidence store is now bounded (LRU-evicted, 2000 handles) so a long engagement can't grow the heap without limit, and the site-map fallback walk is capped so a huge site map can't cause a long synchronous scan.
- **GUI parenting.** The agent "investigate" prompt is now parented to the Burp suite frame instead of a null parent, so it appears on the correct monitor.

### Fixed
- **Active-scan probes were rejected by the target with HTTP 400, so XSS/SQLi still weren't detected.** Burp inserts URL/form parameter values verbatim — it does not percent-encode them — so a probe value with raw `<`, `>` or spaces (XSS markers, boolean-SQLi conditions) went on the wire unencoded, and a strict server (Tomcat/Apache-Coyote, which demo.testfire.net runs) returned `400 Bad Request` before the application saw it. Probe values are now percent-encoded, so the request is well-formed and the server decodes it back to the real payload. Verified live: reflected XSS on testfire's `search.jsp` is now flagged HIGH/FIRM.
- **Active-scan SQLi/XSS probes were silently blocked, so injection was never detected.** The policy gate validated every probe URL with `URI.create()`, which rejects the characters injection payloads rely on — `<`/`>` (XSS markers) and spaces (boolean-SQLi conditions) — as an "invalid URL", so the probe was never sent. The gate now parses probe URLs leniently (percent-encoding those characters only for its own validation, never changing the request that is sent).
- **Injection checks now test blank-valued parameters** (`?query=` or an empty form field is still an injection point; these were skipped entirely before).
- **Blind (error-free) SQL injection detection** added: a logically-true (`' AND '1'='1`) and logically-false (`' AND '1'='2`) condition pair, flagged on the classic true≈baseline / false-differs asymmetry. Both conditions only narrow a query (AND), never broaden or modify data.
- **Broader SQL error fingerprints** (MSSQL "Incorrect syntax near" / "Unclosed quotation mark", PostgreSQL, MySQL, DB2, and more).
- **Reflected-XSS context is now judged from the probe response** (content-type, or an HTML-looking body) rather than the captured baseline, which may have been a redirect or a differently-typed response.
- **Most AI triage results showed NEEDS REVIEW even for clear-cut findings.** A required security header, or a cookie flag, that is provably absent from the captured response is now a deterministic rule verdict of TRUE POSITIVE (medium confidence) — the same way a header that is present is already a rule FALSE POSITIVE. These no longer go to the model, so they are instant and never hedge to NEEDS REVIEW. The model prompt was also changed to decide TRUE/FALSE POSITIVE when a quoted line shows the condition (or its absence) directly, and NEEDS REVIEW only when the evidence shows neither. The quote-verification guard still blocks invented verdicts.
- **Reloaded findings reported "no evidence".** AuditLens kept each imported finding's captured request/response only as an in-session reference, which was lost whenever the extension was reloaded; triage then had nothing to show the model. It now falls back to the matching Burp issue's request/responses, then to the site map for the finding's URL, so triage works after a reload.
- **A failed model call left a stale verdict with no visible error.** Triage failures now write a `NEEDS REVIEW (AI error, …)` verdict on the row and log the cause to Burp's Extensions → Errors tab.
- **Too many AI triage results showed NEEDS REVIEW.** The adversarial second pass treated "no proof for the opposite side" as a disagreement. Now only a clear opposing verdict sends a finding to review; otherwise the first verdict stands and the method says so.
- **Triage method labels were wrong.** A NEEDS REVIEW result from the model, a quote that didn't match, or low confidence was labelled "quote verified". Each now shows its real reason ("model unsure", "quote not verified", "low confidence"). A missing confidence with a verified quote is treated as medium, so the verdict stands.
- **Findings with no captured traffic** now show "no evidence" with a clear reason, instead of a quote-not-found message.

### Changed
- **Default report file name** is now `AuditLens_<project>_<yyyy-MM-dd>.html` (or `.xlsx`). The report dialog has a new "Project name" field; when it is empty, the scope's host is used, then "Project".
- **Excel export contains only the Findings sheet.** The Cover and management summary remain in the HTML report.

## Unreleased — build 22

### Changed
- **AI false-positive analysis works more like a human reviewer.** The model restates the claim, checks the evidence (status, content type, encoding), considers what an attacker needs, and names the one check that would confirm or refute the finding. Rationales now say what the evidence shows and what to check next.
- More category checks: cookies (session versus non-sensitive), missing headers (whether the page needs framing protection), source maps (content, not existence), and version or disclosure findings (public values are not flagged).

## Unreleased — build 21

### Fixed
- **Send to Repeater opened the wrong request** (for example a third-party image host). Agent and selected evidence refs (`a…`, `s…`) are numbered per session and are not saved, so a finding reloaded later could point at unrelated traffic. Refs are now used only when the request is on one of the finding's hosts, in Repeater, triage and the HTML report. Otherwise Repeater falls back to the finding's own URL.

## Unreleased — build 20

### Added
- A **Mark false positive** checkbox on each row of the Findings table, next to the AI Triage column.

## Unreleased — build 19

### Changed
- **Burp AI is the default model provider.** Prompts go through `api.ai()` and use Burp AI credits. Settings → Model provider switches to **Local Ollama** for engagements that must keep data on the machine. Burp AI has no native tool calling, so it runs the JSON tool protocol.
- The README and user guide describe both providers, and the data-handling statements are corrected.

### Added
- `LlmBackend` interface with `BurpAiBackend`, `OllamaClient` and `LlmRouter`. The provider is read on each call.

## Unreleased — build 18

### Changed
- Renamed the extension to **AuditLens** (formerly OllamaAT). The jar is now `AuditLens.jar`, and the Burp tab, menus, log messages and reports use the new name. Java packages stay `ollamaat`.

## Unreleased — build 17

### Added
- **Mark a finding as a false positive** from the Findings tab (checkbox under the description). Marked findings stay in the tab but are left out of the HTML and Excel reports. The mark is saved with the Burp project. A *Marked false positive* column shows the state.

## Unreleased — build 16

### Added
- **Suggested CVSS v3.1 base score** for every finding, with its vector, in the HTML report (pill, index table and finding block) and the Excel Severity cell. Scores come from the finding category and stay consistent with the reported severity.
- **Management summary by severity** (issues, share, affected locations and target timeline) in the HTML report and on the Excel Cover sheet.
- **Option to hide engine information** (the model name on the HTML cover). On by default.

### Changed
- Excel report no longer has an Evidence sheet; evidence snapshots remain in the HTML report.
- HTML executive summary expanded: top-priority issues by CVSS, a business-impact statement and remediation timelines.

## Build 15

### Added
- Evidence references in the HTML report are links. Each one jumps to its captured request in the proof-of-concept section.
- Excel **Evidence** sheet with request and response snapshots for every evidence reference, plus each reference's source (proxy history, agent-sent, or selected).
- Organization name and logo on the report dialog. The logo appears on the HTML cover and on the Excel **Cover** sheet.
- Excel **Cover** sheet (report details, organization, logo) ahead of the Findings and Evidence sheets.

### Changed
- Excel Findings columns: SL.No, Finding Name, Issue Description, Severity, Affected URLs, Impact, Remediations, AI Triage.
- The workbook now has three sheets. Parts are named by tab order, so the Findings table is `sheet2.xml`.

## Build 14

### Changed
- HTML report redesigned with an AuditLens layout: cover page, executive summary with severity bars, a findings overview table, numbered finding sections, and print styling. No external resources.
- Excel columns set to: SL.No, Finding Name, Issue Description, Severity, Affected URLs, Impact, Remediations, AI Triage.

## Build 13

### Added
- **AuditLens** request-editor tab in Repeater (and Proxy) with an *Analyze with AuditLens* button. It runs a read-only review of the request.
- Burp issue menu: *Investigate with AuditLens agent* for a single selected issue.

### Changed
- Findings with the same name are merged into one entry, with all affected URLs and the highest severity. This applies to both reports.
- Excel columns rearranged (Sl.No, Issue Description, Severity, Affected URL, Impact, Remediations).

## Build 12

### Added
- Manual analysis: *Send to Repeater* from the Findings tab (button and right-click).
- Burp issue menu: *Send to AuditLens for AI analysis*. It imports the selected issues and runs the triage.
- **Staged false-positive analysis**: deterministic rules, quote-grounded model verdicts, and an adversarial second pass. Disagreements become *needs review*.
- Passive checks for Next.js and React markers, secrets in `__NEXT_DATA__`, Server Action calls, `x-middleware-subrequest`, image-optimizer remote fetches, `dangerouslySetInnerHTML` and source maps.
- Built-in skill `nextjs-react-vulnerabilities`, and remediation entries for Next.js and React.

## Build 11

### Added
- AI false-positive analysis with verdicts stored on each finding, shown in the Findings tab and in both reports.

## Build 10

### Added
- **Import Burp issues** (all issues, including those from other extensions), de-duplicated by name and URL.
- Affected URLs listed for each merged finding in the reports.

## Build 9

### Added
- Passive checks for secrets and PII in response bodies, CORS misconfiguration, and security-header hardening (Referrer-Policy, Permissions-Policy).

## Build 8

### Fixed
- Excel reports failed to open in Excel. The worksheet XML elements are now written in schema order.

## Build 7

### Added
- Passive checks for object identifiers and sensitive values in URLs (possible IDOR and data exposure).

## Build 6

### Fixed
- Findings tab was empty because of a null-engine error during panel construction.

## Build 5

### Added
- Remediation knowledge base with impact statements, guidance and reference links, used by both reports.
- Proof of concept taken from captured evidence in the HTML report.

### Fixed
- Findings were routed to the wrong category when a description contained a stray keyword. Routing is now title-first.

## Build 4

### Changed
- `add_finding` and `note_add` are always allowed, because they record only local annotations. Previously an approval gate could drop findings.

## Builds 2–3

### Added
- AI passive review findings are recorded in the Findings tab, through a shared reviewer.
