---
name: sql-injection-testing
description: Confirm SQL injection via error, boolean and time-based signals, and map extraction surface without dumping data.
---
1. Candidate parameters: anything used in filters, sort, search, ids, pagination (list_endpoints with_params=true, then get_message).
2. Error-based: replay_request with a single quote inserted in the parameter. Compare vs baseline. DB error strings (SQL syntax, ORA-, SQLSTATE, pyodbc, Unclosed quotation) or a clean->500 flip = strong signal.
3. Boolean-based: send a pair of syntactically valid true/false conditions appended to the parameter (e.g. `' AND 1=1-- -` vs `' AND 1=2-- -`, or the numeric-context equivalents without quotes). compare_messages; a reproducible, consistent difference (status, length, or specific content) with no other variable changed is strong evidence.
4. Time-based (use ONLY if 2-3 give nothing and the field looks reachable): a single short delay condition (2-3s) vs a false/no-delay control, ONE pair, not a loop. A reproducible delay difference close to the requested seconds is evidence; run it at most twice to confirm.
5. Never use stacked queries, UNION-based extraction, OOB/DNS exfiltration, or multi-second loops. Never target authentication/logout endpoints. Do not attempt to dump schema or data — confirming the class of bug is sufficient; hand off to the pentester via send_to_repeater for exploitation.
6. add_finding with both refs (baseline + each probe), the exact syntax used, and database hints observed. Confidence firm only with two independent signals (e.g. error + consistent boolean pair).
