---
name: clickjacking-ui-redress
description: Passive review for missing frame protections on sensitive, state-changing pages.
---
1. Purely passive: for each sensitive page (login, payment, account settings, admin actions, consent/approval screens) in captured traffic, get_message (response) and check X-Frame-Options and Content-Security-Policy frame-ancestors.
2. Flag pages with neither control set, especially where a single click performs a state change (not just a view). A page that is read-only and has no sensitive action is lower priority.
3. Also check SameSite cookie attribute on the session cookie — a strict/lax SameSite cookie reduces (but does not eliminate) clickjacking impact for cross-origin framing; note it in the finding as a mitigating factor if present.
4. No active testing is needed or appropriate here (no iframe PoC page should be hosted against the real target); a missing header on a sensitive action page is sufficient evidence.
5. add_finding (low/medium depending on the action's sensitivity) recommending `X-Frame-Options: DENY` or `frame-ancestors 'none'` (or a specific allow-list if framing is legitimately needed).
