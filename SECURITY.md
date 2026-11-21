# Security Policy

## Supported versions

Only the most recent build of AuditLens receives security fixes. Please check that your issue still exists in the
latest build before you report it.

## Reporting a vulnerability

Please **do not** open a public issue for a security problem in AuditLens. Public disclosure could expose people who
use the tool on live systems.

Report privately through one of these channels:

- GitHub: use **Security → Report a vulnerability** on this repository (a private security advisory).
- Email: `[maintainer contact — to be added before publication]`.

Please include:

- The AuditLens build (the `patched-vN` number, or the commit hash) and the Burp Suite edition and version.
- Steps to reproduce, using synthetic targets where possible.
- The impact you observed, for example a bypass of scope, approvals, the block list or the audit log, or
  unexpected data leaving the machine.
- Whether you would like to be credited.

## What counts as a security issue

Examples in scope:

- A way to make the agent send requests outside Burp's target scope, or to skip approvals or the block list.
- Data sent to a host other than the configured loopback Ollama server without the remote-host setting enabled.
- Injection into the HTML or Excel reports from captured content (cross-site scripting, formula injection, or markup injection).
- A way to change or hide audit-log entries.
- Credentials or secrets written to logs, reports or the repository.

Out of scope: findings produced by the active scanner or the AI analysis about a target system. Those are
results, and they should be reported to the owner of that system.

## Handling of data

AuditLens stores findings, notes and the audit log in the Burp project. Reports and captured traffic can contain
sensitive client data. Do not attach them to a report unless you have removed that data.
