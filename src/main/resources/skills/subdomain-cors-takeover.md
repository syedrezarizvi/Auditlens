---
name: subdomain-cors-takeover
description: Spot dangling-CNAME subdomain takeover risk and unsafe CORS trust from in-scope hostnames and headers, passively.
---
1. From list_endpoints and any multi-host scope, list distinct in-scope hostnames/subdomains seen in traffic (CDN, marketing, docs, status, old feature subdomains).
2. For each, get_message if traffic exists; a response showing a third-party "no such app/bucket/repo" placeholder page (common with abandoned GitHub Pages, S3, Heroku, Azure, Netlify, etc. endpoints) on an in-scope hostname is a takeover candidate.
3. You cannot resolve DNS/CNAME records yourself; note the hostname and the placeholder content as evidence and let the pentester verify the CNAME and claim/registration status out of band. Never attempt to claim/register the resource yourself.
4. CORS trust: reuse the security-headers-cors skill's safe Origin-reflection probe across every in-scope host that returns Access-Control-Allow-Origin; a wildcard subdomain policy (`*.example.com`) that would also trust a takeover candidate above compounds the severity — mention this linkage explicitly if both are present.
5. add_finding for a clear placeholder-page match (medium/high depending on what the subdomain's cookies/trust relationship would allow); tentative + hand-off note for anything needing DNS verification.
