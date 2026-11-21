---
name: path-traversal-lfi
description: Detect path traversal and local file inclusion in parameters that reference files, templates or static resources.
---
1. Candidate parameters: file, path, template, page, doc, download, include, lang/locale (file-based translations), image/thumbnail generators.
2. Baseline with the original value, then replay_request with a traversal sequence targeting a well-known, harmless-to-read file appropriate to the inferred OS (prefer one that reveals version/presence without exposing secrets, e.g. a public config or changelog file within the app itself) prefixed with `../` sequences (try a couple of depths: `../`, `../../`, `../../../`, including an encoded variant `%2e%2e%2f` if the first is sanitized).
3. Confirm via content, not just status: a distinctive file header/content you'd expect (not a generic error page) appearing in the response body is the signal, not merely a 200.
4. Do NOT target `/etc/passwd`, SAM files, credential stores, cloud metadata, application source/config files containing secrets, or attempt to write files (LFI-to-RCE via log/session poisoning). Reading one non-sensitive file to confirm the class of bug is enough.
5. Null-byte and wrapper tricks (`php://filter`, `data://`) are exploitation techniques, not triage — do not use them; report the base traversal signal and let the pentester escalate deliberately.
6. add_finding with the exact traversal string, both refs, and remediation (canonicalize + allow-list, chroot/jail the file root, reject `..`).
