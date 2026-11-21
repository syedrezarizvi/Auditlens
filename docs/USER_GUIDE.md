# AuditLens User Guide

This guide covers installation, each tab, the main workflows, report generation and troubleshooting.
For the design, read [Architecture](ARCHITECTURE.md).

## Contents

1. [Installation](#1-installation)
2. [First run](#2-first-run)
3. [The Agent tab](#3-the-agent-tab)
4. [Context-menu actions](#4-context-menu-actions)
5. [Active Scan](#5-active-scan)
6. [The Findings tab](#6-the-findings-tab)
7. [AI false-positive analysis](#7-ai-false-positive-analysis)
8. [Manual analysis in Repeater](#8-manual-analysis-in-repeater)
9. [Reports](#9-reports)
10. [Audit log, Notes and Settings](#10-audit-log-notes-and-settings)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. Installation

1. Choose a model provider. The default is **Burp AI**, which needs Burp AI enabled with credits and no extra install.
   To use a local model instead, install [Ollama](https://ollama.com) and pull a model that supports tool calling. Example:
   ```
   ollama pull gpt-oss:20b
   ```
2. If you use Local Ollama, confirm the server is running (default `http://127.0.0.1:11434`).
3. In Burp Suite, open **Extensions → Installed → Add**. Set **Extension type** to *Java* and select `AuditLens.jar`.
4. A new **AuditLens** tab appears in the top-level tab bar.

**Upgrading:** Burp caches the jar. Toggling the extension off and on does not reload it. Use **Remove**, then **Add**
the new jar, or restart Burp.

## 2. First run

1. Open **AuditLens → Settings**.
2. Click **Refresh models**, choose your model, and click **Save**.
3. Check the scope. Add your target under **Target → Scope**. AuditLens only reads and sends in-scope traffic.
4. Choose an **Autonomy** mode (see [§3](#3-the-agent-tab)). Start with *Strict* on sensitive targets.
5. Optional: enable **AI passive scan** in Settings. It is off by default.

## 3. The Agent tab

Write a task in plain language, choose the skills to preload (**Skills…**), set the **Autonomy** level, and press
**Run agent**. Stop it at any time with **Stop**.

| Autonomy | Behaviour |
|---|---|
| **Strict** | Every request asks for approval. |
| **Smart** (default) | In-scope `GET`, `HEAD` and `OPTIONS` requests without a body run. State-changing requests ask. |
| **Autonomous** | In-scope requests run without asking. Destructive-looking requests still ask. |

Approvals appear in the queue on the right: **Allow once**, **Allow for this run**, **Deny**, or **Deny & stop**.

Two rules hold in every mode:
- `DELETE` requests and URLs that look destructive (delete, remove, checkout, pay, reset, revoke) always ask.
- Patterns on the hard block list (for example logout or delete-account) can never be approved.

A **read-only** run hides and blocks all network tools. Use it for reviewing traffic you have already captured.

### Tools the agent can use

| Group | Tools |
|---|---|
| Traffic | `list_proxy_history`, `list_endpoints`, `get_message`, `search_traffic`, `extract`, `compare_messages` |
| Requests (policy-gated) | `send_request`, `replay_request` |
| Burp handoff | `send_to_repeater`, `send_to_organizer` |
| Issues and findings | `list_issues`, `add_finding` (creates a `[AI]` Burp issue with evidence) |
| Helpers | `convert` (base64, URL, hex, HTML, JWT decode), `scope_check` |
| Memory | `note_add`, `notes_list` |
| Methodology | `list_skills`, `load_skill` |
| Control | `finish` |

## 4. Context-menu actions

Right-click in Proxy, Target, Repeater or any message editor:

| Menu | Action | What it does |
|---|---|---|
| AuditLens → **Add to agent context** | Adds the selected messages to the next run. |
| AuditLens → **Review selected (read-only)** | Read-only review of the selected messages. |
| AuditLens → **Investigate with agent…** | Asks for a task and runs it on the selected messages. |
| AuditLens → **Active scan selected…** | Runs the active scan on the selected endpoints. |

Right-click a row in **Burp's Issues list** (the issue list in Burp's Dashboard or Target site map; the item appears only for issue rows):

| Item | What it does |
|---|---|
| **Send to AuditLens for AI analysis (n)** | Imports the selected issues into the Findings tab and runs AI false-positive analysis. Sends no requests. |
| **Investigate with AuditLens agent** | Runs the read-only agent on one selected issue, using its captured requests. Greyed out when several issues are selected. |

In a **Repeater** request editor, an **AuditLens** tab has an **Analyze with AuditLens** button. It runs a read-only
review of the request, and of its response if one was captured. The tab never edits or sends the request.

## 5. Active Scan

The **Active Scan** tab runs a fixed, deterministic scanner. It does not use the model to choose requests.

1. **Load in-scope endpoints from Proxy history**, or select traffic and use *Active scan selected…*.
2. Tick the checks to run, or enable **Passive only** to send nothing.
3. Press **Start scan**. The estimated request count appears first.

Every probe goes through the same policy gate as the agent: scope, budgets, the block list and Autonomy all apply.

| Check | Summary |
|---|---|
| Reflected XSS | Inert canary tag, not an executable payload |
| SQL injection signals | One quote-probe per parameter; no data extraction |
| Path traversal | Signal only; never reads a real system file |
| Open redirect | Uses a `.invalid` target host |
| OS command injection | Single timing probe, at most two attempts, targeted parameter names only |
| CORS misconfiguration | Origin reflection and wildcard checks |
| Insecure HTTP methods | Once per host |
| Sensitive files | A short curated list (for example `.git`, `.env`, actuator, swagger), once per host |
| Passive pass | Security headers, cookie flags, stack traces, directory listings, secrets and PII in responses, and Next.js/React markers |

Results appear in the Findings tab and in Burp's issue list, tagged `[AI]`.

## 6. The Findings tab

The Findings tab is the working area for everything AuditLens has recorded.

**Table columns:** Time, Severity, Confidence, Title, URL, AI Triage (FP), Mark false positive, Evidence, In Burp issues.
The *Mark false positive* checkbox on each row marks that finding in one click, as does the checkbox under the description.
Selecting a row shows its description, remediation and evidence below the table.

**Buttons:**

| Button | Purpose |
|---|---|
| **Generate report (HTML / Excel)…** | Builds the report. See [§9](#9-reports). |
| **Sync [AI] issues from Burp** | Imports `[AI]`-tagged issues. Runs automatically every 20 seconds. |
| **Import Burp issues** | Imports all of Burp's issues, including those from other extensions. |
| **AI false-positive analysis** | Judges all findings, or only the ones from Burp issues. See [§7](#7-ai-false-positive-analysis). |
| **Review proxy history (AI)** | Runs the model over a set number of in-scope captured exchanges. Sends no new requests. |
| **Send selected to Repeater** | Opens the selected findings' requests in Repeater. See [§8](#8-manual-analysis-in-repeater). |

**Mark a false positive:** with a row selected, tick *Mark as false positive (leave out of the final report)* under the description. The finding stays in this tab, so you can review or restore it, but no generated report includes it. The mark is saved with the Burp project. Untick the box to include the finding again.

**Duplicates:** findings with the same name are merged into one entry. The entry lists every affected URL and takes
the highest severity. The `[AI]` prefix and letter case are ignored when matching names.

**Right-click a row** for *Send to Repeater (manual analysis)* and *Re-check selected with AI*.

## 7. AI false-positive analysis

Each finding passes through these stages. A later stage runs only if the earlier ones did not settle the verdict.

1. **Rules.** Facts in the captured messages decide some findings without the model:
   - A "Missing X header" finding is a false positive if the captured response does contain header X.
   - A "Cookie missing flags" finding is a false positive if the Set-Cookie line carries every flag reported missing.
   - A "CORS wildcard" finding is a false positive if the captured response has no `Access-Control-Allow-Origin: *`.
   - Some findings need evidence in the capture. If the element is absent, the verdict is *needs review*.
2. **Grounded model verdict.** The model must quote a verbatim passage from the evidence. If the quote is not found
   in the captured text, the verdict becomes *needs review*. The model sees the part of the response that echoes a
   request parameter, not only the start of the body.
3. **Adversarial second pass.** The model is asked to argue the opposite side. Only agreement keeps a definite verdict.
4. **Confidence.** A low-confidence verdict becomes *needs review*.

The reviewer works the way a person would: it restates the claim, checks the evidence, considers what an attacker needs, and says which single check would settle the finding. Verdicts still need a verbatim quote from the evidence, and a second, opposing pass must agree.

The verdict appears in the AI Triage column, in the HTML report, and in the Excel report. Its method is stated,
for example `FALSE POSITIVE (rule: …)` or `TRUE POSITIVE (AI two-pass agree, quote verified)`.

Treat *needs review* as a prompt to check the evidence yourself. Local models can still be wrong, so
verdicts are advisory.

## 8. Manual analysis in Repeater

Use these when you want to validate a finding yourself:

- **Findings tab → Send selected to Repeater.** Select one or more rows, then press the button. Each finding's
  captured request opens in Repeater, named `AuditLens: <finding title>`. If no request was captured, the finding's URL is used.
- **Right-click a row → Send to Repeater (manual analysis).** Same action.
- **Repeater → AuditLens tab → Analyze with AuditLens.** Runs a read-only AI review of the request in the editor.

Nothing is sent until you press **Send** in Repeater.

## 9. Reports

Open **Generate report (HTML / Excel)…** from the Findings tab or the Active Scan tab.

| Field | Notes |
|---|---|
| Report title | Shown on the cover and in the file metadata |
| Project name | Used in the default file name: `AuditLens_<project>_<yyyy-MM-dd>.html` (or `.xlsx`). If empty, the scope's host is used, then `Project`. |
| Organization name | Shown on the HTML cover. The Excel export has no cover. |
| Organization logo | PNG, JPEG or GIF, up to 2 MB. Embedded in the file, so the report stays self-contained. |
| Target / scope, Prepared by | Optional; shown on the cover |
| Format | HTML, Excel, or both. The default file name follows the pattern above; the extension is added for you. |
| Include informational findings | Off removes `INFORMATION` items |
| Include evidence refs | Adds proof-of-concept requests and links |
| Include full audit log appendix | Adds the audit trail as an appendix (HTML) |
| Show engine information (model name) | On by default. Off removes the model name from the HTML cover, for reports shared outside the team |

### HTML report

A single self-contained file with no external fonts, scripts or network calls. It contains:

- A cover page with the organization logo and name, the overall rating and the highest suggested CVSS score.
- An executive summary: the issue and location counts, a severity breakdown, the three highest-priority issues by CVSS score, a business-impact statement and remediation timelines.
- A management summary table by severity (issues, share, affected locations and target timeline).
- A findings overview table that links to each finding, with its CVSS score.
- A numbered section for each finding: affected URLs, CVSS score and vector, description, impact, AI false-positive analysis,
  proof of concept, remediation with references, and evidence references.
- **Evidence links.** Each `p`, `a` or `s` reference links to its request in the proof-of-concept section.

CVSS scores are estimates. Each finding's category suggests a CVSS v3.1 base vector, and the reported severity keeps the rating consistent. Re-score a finding against its confirmed impact before you rely on it.

Reference prefixes:

| Prefix | Meaning |
|---|---|
| `p` | An item from Burp's Proxy history (`p12` is history item 12) |
| `a` | A request the agent sent |
| `s` | A request you selected in Burp, or one carried over from an imported Burp issue |

### Excel report

A single **Findings** sheet: one row per issue, with these columns: SL.No, Finding Name, Issue Description, Severity,
Affected URLs, Impact, Remediations, AI Triage. The Severity cell also shows the suggested CVSS v3.1 score and vector.
The cover page, management summary, logo and evidence snapshots are in the HTML report only.

## 10. Audit log, Notes and Settings

- **Audit log** records every tool call, policy verdict and approval decision, and who made the decision. It is stored in the
  Burp project. Export it as Markdown from the tab.
- **Notes** holds engagement notes. The agent reads them in later runs.
- **Settings** holds the model provider, the model and Ollama URL (Local Ollama only), the context window (`num_ctx`, default 16384),
  the custom skills folder, the AI passive scan switch, and redaction of sensitive headers.

The model provider defaults to **Burp AI**. Burp AI sends prompts to PortSwigger's AI service and uses Burp AI credits.
Choose **Local Ollama** to keep prompts and evidence on your machine. Burp AI has no native tool calling, so AuditLens runs
its JSON tool protocol with it.

Keep the Ollama URL on loopback unless you have a reason to change it. AuditLens refuses non-loopback URLs unless you
allow remote hosts explicitly.

## 11. Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| Findings tab is empty | Check Settings: a model must be selected for AI features. Confirm the traffic is in scope. Use **Import Burp issues** to pull Burp's own findings. |
| "AI passive scan is OFF" in the status line | Enable it in Settings. Active scan and imported Burp issues work without it. |
| Model replies time out | Choose a smaller model. Very large models can be too slow on a 16 GB laptop. |
| "Ollama is not reachable" | Start `ollama serve`, and check the URL in Settings. |
| Old version still runs after an upgrade | Burp caches the jar. Remove the extension, then add the new jar, or restart Burp. |
| Evidence references are not links | The captured message is no longer in Proxy history. The reference still appears as text. |
| Excel reports "Replaced part" or a repair prompt | Please report it with the file and the AuditLens version. Versions 8 and later write the sheet XML in schema order. |
| Repeater tab does not open | The finding has no captured request and no URL. Open the finding's URL manually. |
| Burp issue menu item missing | Select an issue row in the Issues list, not a message. Reload the extension if you updated it. |

If something else goes wrong, check **Burp → Extensions → AuditLens → Output** and **Errors**. Include the
relevant lines when you open an issue.
