# BurpAT analysis and the AuditLens design

## 1. What "BurpAT" is
"Burp AT" is **PortSwigger's agentic-AI product for Burp Suite Professional**, announced in public beta on 29 July 2026 and later extended
with an enterprise offering. It is a PortSwigger product, **not an open-source extension**, so I could not read its code. What follows comes
from PortSwigger's launch material and trade coverage (PR Newswire release, portswigger.net/burp/burp-at, The New Stack, Help Net Security, IT Brief).

### Architecture as publicly described
| Pillar | What PortSwigger says |
|---|---|
| Agents act through Burp's own tools | Agents use Burp's specialist HTTP tooling rather than a generic HTTP library, so malformed requests/edge cases behave like Burp. |
| Shared project context | Agents can read traffic, target structure, issues and discoveries from the project, and add to it, so later work builds on earlier work. |
| Skills bank | Task-specific methodology "skills" developed with PortSwigger Research, loaded as needed (e.g. a content-discovery skill). |
| Configurable autonomy | Actions can be allowed, require approval, or be blocked; "smart approvals" reduce approval fatigue. |
| Boundaries outside the model | Scope, tool access and approval rules are enforced in Burp's tooling layer, "architecturally separate from the model"; agents propose, Burp enforces, the pentester decides. |
| Evidence trail | Agent requests and tool activity are recorded in the Burp project. |

### What I could not establish
Its pricing, supported model providers, how credits are metered, internal tool list, and known limitations are in documentation I could not
retrieve. I therefore do not claim anything about those. For the Montoya API specifically: extensions reach Burp's built-in AI through
`api.ai()` / `Prompt.execute(...)` (and `EnhancedCapability.AI_FEATURES`), which is the credit-metered path. AuditLens uses it by default from build 19, with Ollama as an option.

## 2. What AuditLens copies, changes and adds
| Capability | Burp AT (public description) | AuditLens |
|---|---|---|
| Model | PortSwigger-provided / credit-based (as you described) | Burp AI by default; any local Ollama model (no credits, data stays local) when chosen |
| Agent loop with tools | Yes | Yes: native Ollama tool calling **plus automatic JSON-protocol fallback** for models without it |
| Project context | Native | Proxy history, endpoint map, issues, **persistent notes/findings in the Burp project** injected into later runs |
| Skills | PortSwigger Research library | 11 built-in methodology skills + **user-defined skills folder**; agent loads on demand |
| Autonomy | Allow/ask/block, smart approvals | Strict / Smart / Autonomous + always-ask for destructive actions + per-run "allow similar" |
| Enforcement | Burp core, separate from the model | Deterministic policy class in the extension (scope, budget, block list, rate limit); model cannot change it |
| Evidence | Recorded in project | Audit log persisted in project + Markdown export; `add_finding` creates `[AI]` Burp issues with evidence refs |
| Passive review | n/a in sources | Optional AI passive scan check (dedupe, serialised, tentative) |
| Privacy guards | n/a | Loopback-only by default, optional header-secret redaction |
| Manual hand-off | Burp tools remain | `send_to_repeater` / `send_to_organizer`, context-menu entry points |

## 3. Honest gaps versus Burp AT
1. **Enforcement strength.** Burp AT enforces inside Burp. AuditLens enforces inside an extension; it is robust against the model, not against a bug in itself or other extensions.
2. **Methodology depth.** PortSwigger Research-backed skills will outclass my generic ones; the skills are intentionally evidence-gathering/low-impact.
3. **Model capability.** A local 8B model reasons and calls tools far less reliably than a frontier model. Use the largest model you can run and keep Strict/Smart mode.
4. **Tooling breadth.** No Collaborator/OAST, crawler or Intruder-style tools yet; scanning is limited to the passive AI check.
5. **Verification status.** Core logic is covered by 41 automated checks plus a headless smoke test over stubs; it has not been exercised in a live Burp.

## 4. Update: skills, active scan and HTML reporting
Three additions since the first version, still with no Burp AI credits used anywhere:

- **35 skills total** (was 11): added SSTI, XXE, insecure deserialization, file upload, path traversal, HTTP
  request smuggling, host header injection, clickjacking, cache poisoning, prototype pollution/DOM XSS, GraphQL,
  WebSocket, race conditions, subdomain takeover, CRLF injection, sensitive data exposure, rate-limit abuse,
  cryptographic weaknesses, CSV injection, LDAP/XPath injection, and content discovery — covering the OWASP Top
  10, the OWASP API Top 10 and most of the Testing Guide's web categories.
- **Active Scan tab**: a *deterministic* scanner (payload + signature/diff detection, the same approach Burp's
  own scanner, ZAP and sqlmap use), not an LLM tool-calling loop — a local model cannot reliably drive hundreds of
  probe requests the way it can drive a dozen agent calls, and a rule-based scanner works even with no model
  configured. Every probe is routed through the same `PolicyGate` the chat agent uses (extracted during this work
  specifically so the two paths can't drift apart), so scope, approvals, rate limits and the block list apply
  identically regardless of which part of the extension sent the request.
- **HTML report generation**: a single self-contained, offline file (no CDN, no JS required — uses native
  `<details>`/`<summary>`) summarising findings from both the chat agent and the active scanner, with all
  finding text HTML-escaped (tested explicitly, since finding text can contain attacker-controlled content
  captured during testing).

This still falls short of Burp AT's PortSwigger-Research-backed skills and in-core enforcement (see section 3),
and the active-scan checks' detection logic, while compiled and unit-tested at the regex/estimate/report level,
has not been exercised against a live target in this sandbox (Burp's own HTTP object implementations aren't
available outside Burp itself).

## 5. Suggested next steps
Collaborator-backed blind-issue tools, a second-session role switcher for authorization testing, an LLM-assisted "smart approval" classifier layered on top of the deterministic rules,
Burp-native scan/crawl tools (`api.scanner()`), streaming responses in the transcript, a settings entry in Burp's native Settings panel, and letting the active scanner's ambiguous
signals be triaged/written up by the LLM (optional, mirroring how the AI passive check already works) before they're recorded as findings.
