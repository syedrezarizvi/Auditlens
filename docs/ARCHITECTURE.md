# AuditLens Architecture

This document describes how AuditLens is put together: the packages, the main flows, the control layer, the triage
pipeline and the report pipeline. It is written for contributors and for security reviewers who need to know where
each control lives.

## 1. Design principles

- **Provider choice.** Burp AI (`api.ai()`) is the default. A local Ollama server is available for engagements that must keep data on the machine. `LlmRouter` picks one per call.
- **The model proposes; code decides.** Scope, budgets, approvals and the block list are enforced in Java. A prompt
  cannot widen scope or skip an approval.
- **Models see references, not objects.** Captured HTTP messages are addressed by short refs (`p12`, `a3`, `s1`).
  The model cannot reach anything the tester has not exposed.
- **Evidence before verdicts.** A finding carries the captured messages it came from. Verdicts must quote that evidence.
- **Work in Burp's project.** Findings, notes and the audit log are stored in the Burp project, so they survive restarts.

## 2. Package map

| Package | Responsibility | Key classes |
|---|---|---|
| `ollamaat` | Entry point, orchestration, passive hooks | `AuditLens`, `Engine`, `AiPassiveCheck`, `PassiveReviewer`, `Settings` |
| `ollamaat.agent` | Agent loop, policy, approvals, memory, audit, skills | `Agent`, `Policy`, `PolicyGate`, `Action`, `Approvals`, `Memory`, `Persist`, `AuditLog`, `SkillLibrary`, `Tool`, `FnTool` |
| `ollamaat.llm` | Ollama HTTP client (native tool calling, JSON fallback) | `OllamaClient` |
| `ollamaat.tools` | Burp-facing tools, the evidence store, message formatting, throttling | `BurpTools`, `Evidence`, `Fmt`, `IssueReporter`, `Throttle` |
| `ollamaat.scan` | Active scanner and the passive check | `ActiveScanEngine`, `ScanCheck`, `ScanFinding`, `Signatures`, `checks/*` |
| `ollamaat.triage` | False-positive analysis pipeline | `Triage` |
| `ollamaat.report` | HTML and Excel reports, remediation knowledge base | `HtmlReport`, `ExcelReport`, `Xlsx`, `FindingGroup`, `RemediationKb`, `ReportOptions` |
| `ollamaat.ui` | Swing UI | `MainPanel`, `ReportDialog`, `ActiveScanPanel`, `SettingsPanel`, `OllamaRequestEditor` |
| `ollamaat.util` | JSON and text helpers | `Json`, `Text` |

Runtime dependencies: the Montoya API (provided by Burp) and the Java standard library. The Excel writer is
dependency-free.

## 3. Component overview

```
              ┌──────────────────────────── Burp Suite ───────────────────────────┐
              │  Proxy history   Scanner issues   Repeater   Issues menu   Editor │
              └───────▲─────────────▲───────────▲──────────────▲────────────▲─────┘
                      │ Montoya API │           │              │            │
┌─────────────────────┴─────────────┴───────────┴──────────────┴────────────┴──────┐
│ AuditLens                                                                         │
│                                                                                  │
│  UI (MainPanel, ReportDialog, OllamaRequestEditor) ──► Engine ◄── PassiveCheck   │
│                                                         │                        │
│        ┌──────────────┬────────────────┬───────────────┼──────────────┐         │
│        ▼              ▼                ▼               ▼              ▼         │
│   Agent + Policy   ActiveScan      Triage        Import/Repeater  Reports       │
│        │              │                │                              │         │
│        ▼              ▼                ▼                              ▼         │
│   BurpTools      PolicyGate      OllamaClient ──► Ollama      HtmlReport /     │
│   (Evidence refs)                                              ExcelReport     │
│                                                                                  │
│   Memory (findings, notes) ◄─► Persist ◄─► Burp project storage                 │
│   AuditLog ◄─ every decision                                                    │
└──────────────────────────────────────────────────────────────────────────────────┘
```

## 4. Main flows

### 4.1 Agent run

1. The user starts a run from the Agent tab or a context-menu action. `Engine.start` creates an `Agent`.
2. The agent sends the conversation, the memory digest and the tool list to the model.
3. The model returns tool calls (native tool calling) or a JSON action (fallback protocol).
4. Each tool call passes through `Policy` and `PolicyGate`. The verdict is one of *allow*, *ask*, or *block*.
   A request that needs approval waits in the approval queue.
5. The tool runs and its result, with refs in place of raw messages, goes back to the model.
6. The loop ends on `finish`, on a budget limit, on stop, or on loop detection. Everything is recorded in `AuditLog`.

### 4.2 Burp issue → AI analysis

1. The Issues menu calls `AuditLens.Menu.provideMenuItems(AuditIssueContextMenuEvent)`.
2. `MainPanel.analyzeBurpIssues` → `Engine.analyzeIssues`.
3. `findingFromBurpIssue` converts each issue into a `Memory.Finding` and captures up to three request/response pairs
   as `s` refs.
4. The finding is stored with `addFindingIfAbsent`, then `startTriage` runs the pipeline in §5 on a background thread.

### 4.3 Repeater hand-off

- **Findings → Send to Repeater.** `Engine.sendToRepeater` takes the first resolvable evidence ref's request, or
  `HttpRequest.httpRequestFromUrl(url)` as a fallback, and calls `api.repeater().sendToRepeater(request, name)`.
  Nothing is sent to the target.
- **Repeater editor tab.** `OllamaRequestEditor` is registered with `registerHttpRequestEditorProvider`. Its button calls
  `MainPanel.analyzeRequest`, which starts a read-only run on that request.

### 4.4 Report generation

1. `ReportDialog` collects the options (`ReportOptions`: title, organization, logo, scope, format, flags).
2. `FindingGroup.of` merges findings by normalised name and keeps the highest severity.
3. `HtmlReport.generate` or `ExcelReport.generate` renders the groups. Only the HTML path resolves evidence refs
   through `Evidence.get` to build the proof-of-concept blocks.
4. The output is written next to the chosen base name.

## 5. Triage pipeline

`ollamaat.triage.Triage` decides a verdict in four stages. Each stage runs only if the previous one did not settle it.

```
Finding + captured evidence
      │
      ▼
 1. ruleVerdict()         deterministic facts from the captured messages
      │  (null → continue)
      ▼
 2. analyze(): first      model verdict; must quote evidence verbatim
      │   quote not found / low confidence → NEEDS REVIEW
      ▼
 3. analyze(): second     adversarial pass argues the opposite side
      │   disagreement → NEEDS REVIEW
      ▼
 Verdict(label, confidence, method, rationale) → Memory.setTriage
```

**Rule stage** (`ruleVerdict`) returns:
- `FALSE POSITIVE` only when the reported condition is provably absent in the capture (for example a header that is present).
- `NEEDS REVIEW` when the element the finding is about is missing from the capture.
- `null` when no rule applies. It never returns `TRUE POSITIVE`.

**Grounding** (`quoteFound`): the quote is normalised for whitespace and case, must be 4 to 300 characters, and must
appear in the text the model was shown (`corpus`). The model sees the finding detail, the captured requests and responses,
and windows around any request parameter value echoed in the response (`Engine.valueWindows`).

**Checklists** (`checklist`): each finding category (XSS, SQL injection, redirect/SSRF, access control, CORS) adds a
short, category-specific question. This keeps small models from judging every finding the same way.

The pipeline is pure Java with a `Chat` interface for the model call, so it is unit-tested without Burp
(`TriageRulesTest`).

## 6. Control layer

Controls are enforced in code. Each one is listed with where it lives.

| Control | Enforced by | Notes |
|---|---|---|
| Scope | `PolicyGate`, `BurpTools` | Out-of-scope URLs are blocked. Out-of-scope history is refused. |
| Autonomy modes | `Policy` | *Strict*, *Smart* (default), *Autonomous*. |
| Always ask | `Policy` | `DELETE`, and destructive-looking URLs, in every mode. |
| Hard block list | `Policy` | Regex patterns that cannot be approved. |
| Budgets | `Agent`, `Throttle` | Request budget, requests per second, maximum steps, loop detection. |
| Read-only runs | `Agent`, `Policy` | Network tools are hidden and blocked. |
| Approvals | `Approvals` | *Allow once*, *Allow for this run*, *Deny*, *Deny & stop*. |
| Audit | `AuditLog` | Stored in the Burp project. Every decision records who decided. |
| Prompt-injection containment | `Agent`, `Triage` | Target data is framed as untrusted. Triage ignores instructions in evidence. |
| Provider choice | `Settings`, `LlmRouter`, `BurpAiBackend`, `OllamaClient` | Burp AI by default; Ollama only when chosen. Non-loopback Ollama URLs are refused unless explicitly allowed. |
| Redaction | `Fmt` | Authorization, Cookie and API-key values can be redacted in prompts and reports. |
| Escaping in reports | `HtmlReport.esc`, `Xlsx.esc` | All captured text is escaped before it is written. |

Passive and active checks work through the same gate as the agent: the active scanner's probes are subject to `Policy`.

## 7. Evidence references

`ollamaat.tools.Evidence` maps short refs to Burp message objects. The model and the reports use only the refs.

| Prefix | Source | Stored by |
|---|---|---|
| `p<N>` | Proxy history item N | Looked up on demand from `api.proxy().history()` |
| `a<N>` | A request the agent sent | `addAgent` |
| `s<N>` | A message the tester selected, or one captured from a Burp issue | `addSelected` |

Refs are per-session labels. Proxy refs can expire when Burp's history changes, so reports show a reference as plain
text when its message can no longer be resolved.

## 8. Persistence

- `Memory` holds notes and findings. Each finding has time, run, title, severity, confidence, URL, detail,
  remediation, evidence refs, a flag for whether it is in Burp's issues, and the AI triage verdict.
- `Persist` is the storage interface. `Engine` backs it with Burp's **extension data**
  (`api.persistence().extensionData()`), which is stored in the Burp project file.
- `AuditLog` writes its entries through the same project-scoped store.
- `Settings` uses Burp's **preferences** (`api.persistence().preferences()`), which are user-level, not per-project.

## 9. Reports

| Output | Class | Notes |
|---|---|---|
| HTML | `HtmlReport` | One self-contained file. Logo embedded as a base64 data URI. Inline CSS and anchor links only; no scripts. |
| Excel | `ExcelReport` + `Xlsx` | Cover and Findings sheets. The logo is a drawing part with an embedded image. |

`Xlsx` writes OOXML parts directly: workbook, sheets, styles, drawings and media. Parts are written in the schema order
Excel expects (for example `cols` before `sheetData`, and `drawing` after `autoFilter`). Tests check that every XML part
parses, and that the sheet order and the logo relationships are present.

`RemediationKb` supplies impact text, remediation guidance and reference links. Lookup is title-first, so a finding
title selects its entry before the description is considered. Specific rules come first (Next.js and React entries),
then general categories.

## 10. Passive analysis

- `AiPassiveCheck` runs the model over deduplicated in-scope responses. It is off by default and uses a single model slot, so it waits for the model to free up (up to five minutes) before skipping a response.
- `PassiveAnalysisCheck` runs deterministic checks on every response: security headers, cookies, verbose errors,
  directory listings, secrets and PII in bodies, CORS, URL-embedded credentials and identifiers, Next.js and React
  markers.

Both record findings through `Memory`, so they reach the Findings tab, the reports and Burp's issue list.

## 11. Testing strategy

Burp's own classes are not available outside Burp, so the suite uses:

- **Stub Montoya objects** built with `java.lang.reflect.Proxy` (`ScanStub`, `SmokeTest`).
- **A mock model** for agent and triage behaviour.
- **Pure-function tests** for logic that does not need Burp: the rule verdicts, quote grounding, the report
  renderers and the workbook structure.

Burp-facing code (the context-menu items, the editor tab and the Repeater call) is checked by compilation and the
smoke tests. It should also be exercised in a real Burp session before a release.

## 12. Extending AuditLens

- **New agent tool:** add an `FnTool` in `tools/BurpTools.java`, give it a `Policy` classification, and add a test.
- **New active check:** implement `ScanCheck`, add signatures to `Signatures` where useful, and register the check in
  `ActiveScanEngine.allChecks`.
- **New skill:** add a Markdown file with front matter to `src/main/resources/skills/` and list it in `index.txt`.
- **New remediation entry:** add a `Rule` to `RemediationKb`. Put specific rules before general ones.
- **New report section:** extend `HtmlReport.generate` or `ExcelReport.generate`, and cover it with a test.
