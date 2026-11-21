---
name: graphql-security
description: Assess a GraphQL endpoint for introspection exposure, excessive data exposure, missing depth/complexity limits and BOLA via field-level access.
---
1. Find the GraphQL endpoint (commonly /graphql, /api/graphql) in traffic; confirm with get_message.
2. Introspection: replay_request with body set to a standard introspection query (`{"query":"{__schema{types{name,fields{name}}}}"}`). If it returns the full schema in production, that's an information-exposure finding (severity depends on what it reveals: internal type/field names, admin-only mutations visible to anonymous users).
3. From the schema (or from observed queries if introspection is off), look for: mutations that look sensitive (delete, updateRole, impersonate) and whether they're reachable by a low-privilege session; queries that accept an `id`/`userId` argument — test BOLA using the access-control-idor skill's replay approach, substituting an id observed elsewhere in traffic.
4. Excessive data exposure: compare fields returned by a query against what the UI actually displays; GraphQL often over-fetches by design, but flag object graphs exposing other users' PII in one hop.
5. Resource exhaustion indicators (do not actually exhaust): check whether deeply nested queries or large `first`/`limit` arguments are rejected with a controlled error (good) or accepted without limit (note as a finding, but do NOT send a genuinely expensive/nested query — a single moderately nested query to observe the error message is enough).
6. Batch query abuse: note if the endpoint accepts a JSON array of queries (query batching) which can bypass simple rate limiting — mention as a finding, do not mass-batch to prove it.
7. add_finding per distinct issue (introspection exposure, BOLA, missing limits) with query bodies used as evidence.
