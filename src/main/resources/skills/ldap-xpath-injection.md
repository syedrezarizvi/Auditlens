---
name: ldap-xpath-injection
description: Detect LDAP and XPath injection in directory-lookup or XML-query features using syntax-only probes.
---
1. Candidate parameters: username/login lookups against a directory service, "search employee", SSO-adjacent lookups, or any XML-document query feature (XPath-based search).
2. LDAP probe: insert LDAP metacharacters that alter filter syntax without extracting data, e.g. a trailing `)(uid=*` style wildcard broadening or an unmatched `*`/`(` /`)` and compare behaviour vs baseline (error vs normal vs a broadened result set appearing in the response).
3. XPath probe: similarly, insert a syntax-breaking `'` or a boolean condition like `' or '1'='1` into the XML-query parameter and compare results/errors vs baseline (same boolean-pair approach as sql-injection-testing).
4. A clear syntax error (LDAP: "invalid filter syntax"; XPath parser errors) or an unexpectedly broadened/altered result set for a boolean-true vs boolean-false pair is the signal. Do not attempt full LDAP blind-boolean data extraction or XPath node-by-node extraction — confirming the class is enough.
5. add_finding with both refs and the exact probe strings; recommend parameterized LDAP/XPath queries (never string-concatenated filters) as remediation.
