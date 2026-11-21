---
name: http-request-smuggling
description: Passive and low-risk active checks for CL.TE/TE.CL desync conditions in front-end/back-end chains.
---
1. Passive clues first: look for a reverse proxy/CDN in front of the app (Via, X-Cache, Server headers differing between edge and app responses), and whether any captured request carries both Content-Length and Transfer-Encoding (should never both be present/trusted).
2. This class of bug is inherently about sending ambiguous, malformed requests that can desynchronize shared connections between other users and the server — it has a real risk of affecting OTHER users' traffic, not just your own. Do not attempt desync probes (CL.TE/TE.CL timing probes, header obfuscation) without the pentester explicitly approving a smuggling-specific test window, ideally on a dedicated/non-production instance.
3. If explicitly asked to proceed: send at most one single-shot, low-volume differential-timing probe via send_request (not replay_request, so you control the raw request precisely) and compare response timing; do not repeat, pipeline, or send follow-on requests that race with other connections.
4. Report this skill's output as a hypothesis with supporting passive clues (chain topology, duplicate length headers observed in any captured traffic) rather than a confirmed finding unless the pentester has already authorized and supervised an active probe.
5. add_finding (tentative) documenting the chain topology clues and recommending manual testing with Burp's HTTP Request Smuggler / dedicated tooling under supervision.
