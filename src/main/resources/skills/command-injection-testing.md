---
name: command-injection-testing
description: Detect OS command injection via safe, non-destructive arithmetic/time markers in parameters that may reach a shell.
---
1. Candidate parameters: filenames, hostnames/IPs (ping/traceroute-style features), export/convert/report functions, anything that shells out to ImageMagick/ffmpeg/pandoc-like tools.
2. Benign separator probe: append command separators (`;`, `|`, `&&`, backtick) around an arithmetic marker that only proves execution, e.g. a shell expression that evaluates to a distinctive number, OR a short sleep (2-3s) as a single-shot time probe — never loops, never >5s, never more than two attempts.
3. Compare timing/response/length vs baseline (compare_messages or the "vs baseline" line from replay_request). A reproducible delay matching the requested duration, or the arithmetic result appearing in output, is strong evidence.
4. Never use payloads that write files, delete data, open reverse shells, download tools, or call network utilities beyond a single harmless local marker. Never target endpoints already flagged destructive by policy (they will be blocked/ask anyway — do not try to work around that).
5. If a signal appears, stop — do not escalate to interactive shell access. add_finding with the exact separator and marker used, both refs, and note this needs manual confirmation in Repeater before exploitation.
