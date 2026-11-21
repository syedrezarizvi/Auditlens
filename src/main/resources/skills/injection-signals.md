---
name: injection-signals
description: Detect SQL/NoSQL/template/command injection signals via error and behavioural differences, without exploitation.
---
1. Select parameters that likely reach a back end (filters, sort, search, ids, JSON fields).
2. Baseline each with get_message; record status, length, error format.
3. Send ONE benign syntax probe at a time: a single quote, a double quote, a trailing backslash, an unmatched bracket. Use replay_request and read the "vs baseline" line.
4. Interpret: DB/engine error strings, stack traces, status flips 200->500, large length changes, or timing changes are signals. Identical output means no signal for that probe.
5. Boolean confirmation (only if step 4 gave a signal): send a pair of syntactically valid conditions that should be true/false (e.g. `1=1` vs `1=2` in the appropriate context) and compare_messages. A consistent, reproducible difference supports injection.
6. Stop at confirmation of the signal. Do NOT extract data, enumerate schema, use stacked queries, time-delay loops, or file/command functions. Hand off to the pentester via send_to_repeater with a note describing the confirmed signal.
Report as tentative unless the boolean pair reproduces three times.
