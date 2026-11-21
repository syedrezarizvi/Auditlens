---
name: business-logic-review
description: Passive review of workflows for logic flaws: step skipping, client-side trust, price/quantity manipulation candidates, state machines.
---
1. Reconstruct multi-step flows from proxy history order (list_proxy_history, sorted by id): registration, checkout, approval, password change, invitation.
2. For each step list what the client sends that the server should own: prices, discounts, roles, status, totals, ids of other objects, hidden form fields.
3. Look for state tokens and whether later steps verify earlier ones (can step 3 be replayed without step 2? use replay_request only on non-payment, non-destructive flows and with approval).
4. Check numeric edge handling observed in traffic (negative/zero/huge quantities appear in errors?).
5. Output hypotheses with the exact refs involved and the minimal safe test; do not execute payment, transfer, deletion or messaging flows (the policy will ask the pentester, and you should not push for approval).
