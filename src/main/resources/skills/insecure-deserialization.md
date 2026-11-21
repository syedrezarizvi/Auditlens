---
name: insecure-deserialization
description: Spot insecure deserialization surfaces (Java, PHP, Python pickle, .NET, Node) from traffic without attempting gadget-chain exploitation.
---
1. Look for serialized-object fingerprints in requests/cookies/hidden fields: Java (`rO0AB` base64 / `aced0005` hex), PHP (`O:8:"ClassName"`, `a:2:{`), Python pickle (`\x80\x04` / base64 starting `gA`), .NET (`AAEAAAD//` / ViewState with MAC disabled), Node (`_$$ND_FUNC$$_`).
2. search_traffic for these fingerprints and for headers/params like `token`, `state`, `data`, `__VIEWSTATE`, `rememberMe` that often carry serialized blobs.
3. convert to inspect/decode (base64/hex) just to confirm the format; do not craft or send gadget-chain payloads (ysoserial-style, pickle opcodes, ViewState forgeries) — that is exploitation, not triage, and risks real code execution on the target.
4. Passive risk indicators worth reporting even without a working chain: serialized Java objects accepted from the client, PHP object injection sinks reachable from user input, ASP.NET ViewState without MAC/encryption (check for a `__VIEWSTATEGENERATOR` and whether tampering the end byte of `__VIEWSTATE` causes a generic vs validation-specific error).
5. One safe tamper test only: flip the last character of the serialized blob and resend (replay_request body_replace). A validation-aware error ("MAC validation failed") is reassuring; a stack trace mentioning deserialization classes, or a changed application state, is a strong signal.
6. add_finding as high/critical with confidence tentative unless you observed a clear deserialization-specific error; recommend the pentester pursue gadget-chain analysis only with explicit written authorization and offline tooling.
