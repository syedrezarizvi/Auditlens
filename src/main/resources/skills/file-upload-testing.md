---
name: file-upload-testing
description: Review file-upload functionality for unrestricted type/extension handling, path traversal in filenames, and unsafe storage, using harmless files only.
---
1. Find upload endpoints from traffic (multipart/form-data, Content-Disposition: form-data; filename=).
2. Passive checks: does the response or a later GET reveal the stored path/URL? Is the upload served from the same origin (executable risk) or a separate static/CDN origin (safer)?
3. Extension/type test (needs approval; each is one small harmless file): rename a harmless plain-text or image file to a web-executable-looking extension the server might run (.php, .jsp, .asp, .html, .svg with embedded script) while keeping its real content harmless (no payloads). A successful upload plus the file being served back as that content-type/extension is the finding, not actual code you place inside it — do not upload working web shells or scripts that execute.
4. Filename traversal: try a filename containing `../` sequences (e.g. `../../ollamaat-test.txt`) and see if the server sanitizes it or if the upload lands outside the intended directory (only confirmable if the app exposes a way to list/read the result).
5. Size/type/count limits: note whether declared Content-Type is trusted over actual content (magic-byte mismatch accepted?).
6. Never upload real malware, zip bombs, oversized files, or anything that could disrupt the service. add_finding describing exactly what was accepted and how it could be abused; remediation should cover extension allow-listing, content-type/magic-byte verification, storage outside the webroot, and randomized filenames.
