---
name: websocket-security
description: Review WebSocket handshake and message handling for origin validation, authentication and injection issues.
---
1. Use api.proxy().webSocketHistory() equivalent context already provided, or ask the pentester for the relevant WS traffic if not visible in proxy history (list_proxy_history may not show WS frames).
2. Handshake checks (passive): is there an Origin check server-side (can only be inferred from app behaviour, not from the handshake itself)? Is the WS authenticated via a cookie/token at handshake time, and does that token get revalidated on each message or only once?
3. Message-level checks: are messages JSON with a type/action field used for authorization decisions client-side only? Look for user ids/room ids/channel names a client could change to access another user's data (BOLA-over-WebSocket) — report as a hypothesis citing the message schema observed; you cannot open a live WS connection yourself, so hand off to the pentester for live confirmation if the agent has no WS send capability.
4. Injection: if message content is later rendered (chat, notifications), apply input-reflection-triage reasoning to the message schema.
5. add_finding (tentative, since confirmation needs an interactive WS client) describing the schema-level weaknesses found and recommending the pentester verify live with Burp's WebSocket tooling.
