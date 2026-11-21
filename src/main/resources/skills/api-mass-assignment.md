---
name: api-mass-assignment
description: Test property-level authorization and mass assignment on JSON/form APIs, plus excessive data exposure.
---
1. From list_endpoints pick POST/PUT/PATCH endpoints creating or updating objects. get_message to see the accepted JSON/form fields and the response object (response often shows server-managed fields: role, isAdmin, balance, ownerId, status).
2. Excessive data exposure: compare fields returned vs what the UI needs; flag secrets, hashes, internal ids, PII of other users.
3. Mass assignment (needs approval; state-changing): replay a captured update on an object belonging to the test account, adding ONE server-managed field seen in responses (body_replace to inject it). Re-read the object with a captured GET. A changed protected field = candidate. Revert the change in a follow-up request if you can, and say so in the summary.
4. Method/field tolerance: send unexpected types only for fields already in the request (string vs number) and watch for verbose errors.
5. Never modify objects you do not own; never use real customer data.
