# AuditLens

**Agentic, policy-controlled AI security testing for Burp Suite, powered by Burp AI or a local Ollama model.**

AuditLens is a Burp Suite extension (Montoya API) that adds an AI testing assistant, false-positive analysis and
professional reporting to Burp. By default, AuditLens uses Burp AI through `api.ai()`, so prompts go to PortSwigger's AI
service and count against your Burp AI allowance. Choose **Local Ollama** in Settings to keep all inference on a model served
by your own Ollama instance, so no engagement data leaves your machine.

> **Design principle:** the model proposes, a deterministic layer enforces, and the tester decides.

---

## Features

- **Local AI agent** with 19 tools (traffic search, replay, comparison, issue listing, findings, notes and more).
  Every action passes through a policy gate: Burp scope, request budgets, a hard block list, and approval modes.
- **Active scan** with nine deterministic, policy-gated checks. It works without any model configured.
- **AI passive review** of in-scope proxy traffic (opt-in).
- **Findings workspace**
  - Import Burp's own scanner issues, and send selected issues to AuditLens for AI analysis from Burp's issue menu.
  - Staged AI false-positive analysis: deterministic rules first, then quote-grounded model verdicts with an
    adversarial second pass. Disagreements are marked *needs review*.
  - **Manual analysis**: send any finding's request to Burp Repeater, or analyse a single request from an
    *AuditLens* tab in the Repeater editor.
- **Professional reports.** The HTML report has a cover, executive summary, management table, CVSS v3.1 estimates,
  proof-of-concept requests, linked evidence references and remediation guidance with references. The Excel export is a
  single Findings sheet.
- **36 built-in methodology skills**, including Next.js and React vulnerability testing. You can add your own.
- **Auditable:** every tool call, policy verdict and approval decision is recorded in the Burp project.

## Requirements

| Component | Requirement |
|---|---|
| Burp Suite | Professional or Community with the Montoya API. Some scanner features need Professional. |
| Java | 17 or later (the extension is compiled with `--release 17`) |
| Burp AI | Enabled in Burp, with credits available (the default provider) |
| Ollama (optional) | A local or loopback Ollama server with a model that supports tool calling |
| Hardware | Model size drives the speed. Smaller models (3B–8B) run on a typical 16 GB laptop. Larger models may time out. |

## Quick start

1. **Install Ollama** from [ollama.com](https://ollama.com) and pull a model, for example:
   ```
   ollama pull qwen2.5-coder:3b
   ```
2. **Download** `AuditLens.jar` from the project's Releases page (or build it, see below).
3. In Burp: **Extensions → Add → Extension type: Java → select `AuditLens.jar`.**
4. Open the **AuditLens** tab → **Settings**, click *Refresh models*, pick your model, and save.
5. **Add your target to Burp's Target scope.** The agent cannot read or send anything outside scope.

For a full walkthrough, see the [User Guide](docs/USER_GUIDE.md).

## Documentation

| Document | Contents |
|---|---|
| [User Guide](docs/USER_GUIDE.md) | Installation, every tab, workflows, reports, troubleshooting |
| [Architecture](docs/ARCHITECTURE.md) | Packages, data flow, the control layer, the triage pipeline, the report pipeline |
| [Skills](docs/SKILLS.md) | The 36 built-in skills and how to write your own |
| [Design notes](docs/DESIGN-BURP-AT-COMPARISON.md) | How AuditLens relates to PortSwigger's Burp AT |
| [Changelog](CHANGELOG.md) | Notable changes by version |
| [Contributing](CONTRIBUTING.md) | Build, test and contribution guidelines |
| [Security policy](SECURITY.md) | How to report vulnerabilities in AuditLens |

## Building from source

```bash
# Needs a JDK 17+ and the Montoya API jar (from your Burp installation or the PortSwigger extension API release).
./build.sh /path/to/montoya-api.jar           # compiles to dist/AuditLens.jar
./build.sh /path/to/montoya-api.jar --test    # also compiles and runs the test suite
```

Gradle is also supported (`build.gradle`). Pin the Montoya API version in that file for reproducible builds.

## Testing

The test suite needs no Burp installation. It uses stubbed Montoya objects and a mock Ollama.

| Test class | Covers |
|---|---|
| `SelfTest` | Policy, agent loop, approvals, JSON-protocol fallback, injection containment, loop and step limits |
| `SmokeTest` | Engine, tools and Swing panel over stubbed Montoya API and a mock model |
| `ScanTest` | Detection signatures, request-count estimates, HTML rendering and escaping |
| `SyncTest` | Import of Burp issues, de-duplication, text conversion |
| `ExcelTest`, `ExcelMultiSheetTest` | Excel workbook structure, column order, the single Findings sheet, XML well-formedness |
| `CvssTest` | CVSS v3.1 scoring, rating bands, severity-consistent vectors, executive summary |
| `FalsePositiveTest` | Manual false-positive marks are kept and excluded from reports |
| `LlmBackendTest` | Provider routing (Burp AI default, Ollama when chosen) |
| `EvidenceHostTest` | Evidence refs are rejected when the host does not match the finding |
| `ReportFileNameTest` | Default report file name |
| `ReviewerInitTest` | Regression test for the passive reviewer initialisation |
| `UrlCheckTest` | URL, response-body, CORS and header checks |
| `TriageTest`, `TriageRulesTest` | Triage persistence, grouping, rule verdicts, quote grounding, two-pass pipeline, Next.js/React rules |

## Project layout

```
src/main/java/ollamaat/
  AuditLens.java        extension entry point, menus, editor tab
  Engine.java          orchestration: agent runs, scans, reviews, triage, Burp import, Repeater
  agent/               agent loop, policy gate, approvals, memory, audit log, skills
  llm/                 LLM backends: Burp AI, Ollama, and the provider router
  tools/               Burp-facing tools, evidence store, formatting
  scan/                active scanner and checks
  triage/              false-positive analysis pipeline
  report/              HTML and Excel reports, remediation knowledge base
  ui/                  Swing panels and dialogs
src/main/resources/skills/   built-in methodology skills
src/test/java/ollamaat/      test suite
```

## Safety model

AuditLens enforces its controls in code, not in the model's prompt. In summary:

- **Scope:** requests outside Burp's target scope are blocked, and out-of-scope history cannot be read.
- **Autonomy modes:** *Strict* asks for every request; *Smart* (default) runs in-scope safe reads and asks for state-changing requests; *Autonomous* runs in-scope requests without asking.
- **Always asks** for `DELETE` and for destructive-looking URLs, in every mode.
- **Hard block list:** patterns that can never be approved.
- **Budgets:** request limits, rate limits, step limits and loop detection.
- **Read-only runs** hide and block network tools.
- **Privacy:** Burp AI sends prompts to PortSwigger's AI service. Use Local Ollama when engagement data must stay on your machine. Non-loopback Ollama URLs are refused unless you allow them, and sensitive header values can be redacted.

Read [Architecture → Control layer](docs/ARCHITECTURE.md#6-control-layer) for details.

## Known limitations

- **Local models are weaker than frontier models.** Expect missed issues, false positives and tool-call mistakes, especially from small models. Every finding is advisory and must be verified manually.
- **Enforcement lives in the extension**, not in Burp's core. A bug in AuditLens could weaken its own controls. For sensitive targets, use Strict mode.
- **Scanner features depend on your Burp edition.** Where a feature is unavailable, AuditLens logs it and continues.
- **The active scanner is a first pass.** Its checks use signatures and response comparison. They are not a substitute for manual testing.

## Responsible use

Use AuditLens only on systems you are authorised to test. Keep reports, captured traffic and evidence out of public
repositories. The reports can contain sensitive client data.

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) first.

## License

No license has been chosen yet. Until the maintainer adds a `LICENSE` file, all rights are reserved by the author.

## Acknowledgements

Built on PortSwigger's [Montoya API](https://portswigger.github.io/burp-extensions-montoya-api/). Remediation references point to
the [OWASP](https://owasp.org) cheat sheets and testing guide, the [Next.js](https://nextjs.org) documentation, and the
[React](https://react.dev) documentation.
