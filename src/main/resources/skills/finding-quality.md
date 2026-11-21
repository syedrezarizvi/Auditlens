---
name: finding-quality
description: Checklist to apply before add_finding so reports are accurate, reproducible and honest about confidence.
---
Before add_finding confirm every point:
- Reproducible: you can state the exact request (ref) and the exact change that produced the behaviour. Re-run once if cheap.
- Evidenced: at least one ref shows the behaviour; for access control, two refs (baseline vs manipulated).
- Impact stated in one sentence tied to this application (what data/action is exposed to whom).
- Severity follows impact and preconditions (auth required? user interaction?). Missing headers and generic disclosures are low/info.
- Confidence: certain (unambiguous proof), firm (strong evidence, small residual doubt), tentative (signal only, needs manual confirmation). Prefer tentative to over-claiming.
- No duplicates: call list_issues and notes_list first.
- Remediation is concrete (control + where to apply it).
- Detail text includes reproduction steps referencing refs; it must not contain real secrets beyond what proves the issue.
