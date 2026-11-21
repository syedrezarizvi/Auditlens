---
name: ssti-testing
description: Identify server-side template injection by testing arithmetic expressions specific to common template engines.
---
1. Candidate inputs: fields later rendered into generated documents, emails, previews, names, or error/"not found" pages that echo input with templating (profile fields, search names, custom report titles).
2. Baseline with a plain inert marker (e.g. `ollamaat123`) via replay_request; confirm reflection and its context (input-reflection-triage).
3. Polyglot probe: submit `${7*7}{{7*7}}<%= 7*7 %>#{7*7}` (or a smaller engine-specific subset) in ONE parameter. If `49` appears alone (not the literal payload), template evaluation occurred.
4. Narrow the engine from which syntax evaluated: `{{7*7}}` suggests Jinja2/Twig-family, `${7*7}` suggests Freemarker/EL, `#{7*7}` suggests Ruby ERB-family.
5. Do NOT attempt file read, environment dump, or remote code execution gadgets (e.g. os.popen, Runtime.exec, __class__ traversal chains). Confirming arithmetic evaluation is sufficient; this is a critical/high finding on its own.
6. add_finding citing the exact reflected value and which syntax evaluated; recommend manual, authorized follow-up in Repeater for impact assessment.
