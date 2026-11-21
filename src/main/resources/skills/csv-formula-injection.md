---
name: csv-formula-injection
description: Test for CSV/Excel formula injection in data that is later exportable to spreadsheet format.
---
1. Find fields whose values plausibly end up in a CSV/XLSX export feature (names, addresses, notes, comments, product titles) — check the app for an "Export" button in captured traffic, or ask the pentester which export feature to target.
2. Safe probe: submit a value beginning with `=`, `+`, `-`, or `@` followed by a harmless formula that does nothing destructive and makes no outbound connection, e.g. `=1+1` or `=HYPERLINK("https://ollamaat.invalid","x")` ONLY if you will not actually open the exported file in a vulnerable spreadsheet app yourself — note instead that unescaped leading formula characters in exported data is itself the finding.
3. Confirm the export via replay of the app's own export endpoint if one exists in traffic (get the response body and check whether your field was wrapped/escaped with a leading apostrophe or quoted, or left raw).
4. Never use formulas that call external data (`=WEBSERVICE(...)`, `=IMPORTXML(...)`), execute commands (`=cmd|...!...`), or chain DDE — those are exploitation payloads for when the file is opened in a spreadsheet client, which this agent must not attempt or encourage beyond noting the pattern.
5. add_finding (low/medium) describing the unescaped leading-character output in exports and recommending the server prefix a safe character (`'`) or strip leading `= + - @` from exported fields.
