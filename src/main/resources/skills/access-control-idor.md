---
name: access-control-idor
description: Test broken object-level and function-level access control (IDOR/BOLA, missing auth, privilege escalation) by controlled replay.
---
Pre-requisite: the pentester has captured traffic for at least one user. If two accounts exist, ask in your summary for the second session's refs rather than guessing tokens.
1. Pick endpoints from list_endpoints whose paths/params carry object ids ({n}/{uuid}, ?id=, ?user_id=).
2. Baseline: get_message on one captured request; note status, length, the owner of the object.
3. Unauthenticated check: replay_request with remove_headers ["Cookie","Authorization"]. A 200 with the same body similarity (>0.9) = missing authentication (candidate finding).
4. Object swap: replay_request with ONE changed identifier that the pentester already observed in other captured traffic (do not enumerate or guess ranges). Compare with compare_messages. Another user's data returned = BOLA candidate.
5. Method swap: for read-only endpoints try the same path with PUT/DELETE ONLY if approval is granted; prefer OPTIONS and look at the Allow header.
6. Function-level: for admin-looking paths seen in traffic, replay with the low-privilege session.
Evidence rules: a finding needs two refs (baseline + manipulated) showing different principals' data or an authorization decision that should have failed. Mark confidence firm only if the returned data clearly belongs to another principal. Never enumerate more than 3 ids per endpoint.
