---
name: race-condition-testing
description: Identify likely time-of-check/time-of-use race conditions (coupon redemption, balance transfer, limited-use tokens) from application logic, flagged for supervised parallel testing.
---
1. From business-logic-review, identify single-use or limit-checked operations: apply-coupon, redeem-reward, withdraw/transfer funds, accept-invite, vote-once, password-reset-token use.
2. This class of bug requires sending several identical requests in close to true parallel, which this agent's sequential, rate-limited tool calls cannot reliably reproduce — your job is to identify good CANDIDATES and the exact request to race, not to execute the race yourself.
3. For each candidate, capture the exact request (ref), note what state it mutates and what limit should prevent repeats (e.g. "coupon marked used after first redemption").
4. Do not attempt a manual rapid-fire sequence of state-changing requests yourself; this both won't reliably trigger the race and may leave the test account's state inconsistently mutated beyond what's useful as evidence.
5. note_add listing each candidate endpoint and the limit it should enforce. In your finish summary, recommend the pentester use Burp Repeater's "Send group in parallel" (single-packet attack) on these specific candidates; this is a hand-off, not an add_finding, unless the pentester has separately confirmed a duplication with you watching sequential replays (two sequential identical requests both succeeding when only one should is itself evidence worth add_finding, tentative).
