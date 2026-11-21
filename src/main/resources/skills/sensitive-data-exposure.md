---
name: sensitive-data-exposure
description: Passive sweep of in-scope traffic for exposed secrets, PII and internal data in responses, errors, comments and client-side code.
---
1. search_traffic (response) for common secret/PII shapes, one pattern at a time, across in-scope traffic: API keys/tokens (`(?i)(api[_-]?key|secret|token)[\"'=:\\s]+[A-Za-z0-9_\\-]{16,}`), AWS-style keys (`AKIA[0-9A-Z]{16}`), private key headers (`BEGIN (RSA|EC|PRIVATE) KEY`), emails, credit-card-like digit runs, internal IPs/hostnames, stack traces (`Exception|Traceback|at .*\\(.*:[0-9]+\\)`), SQL fragments in errors, `# TODO|FIXME|password|internal only` comments in JS/HTML.
3. For each hit, get_message to see the surrounding context and confirm it's a real exposure (not a placeholder/example value, not already public, not the tester's own test data).
4. Check client-side code and source maps (`.map` files, if include_static requested from list_proxy_history) for leftover internal endpoint paths, feature flags, or hardcoded non-production credentials.
5. Do not use found credentials to authenticate elsewhere — that would be a separate, unauthorized access attempt. Reporting the exposure itself is the finding.
6. add_finding per distinct exposure type (don't bundle unrelated secrets into one finding); redact the actual secret value in your finding detail to a short recognizable prefix/suffix only, never the full value, even though it's your own test environment's data.
