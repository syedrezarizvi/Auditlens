# Contributing to AuditLens

Thank you for helping improve AuditLens. This project tests live systems and handles client data, so please read the
guidelines below before you open an issue or a pull request.

## Ground rules

- **Never post captured traffic, client names, hostnames, credentials or report files** in issues, pull requests,
  commit messages or test fixtures. Use `example.com`-style placeholders and synthetic data.
- Use AuditLens only on systems you are authorised to test. Please don't propose features whose main purpose is to
  bypass the safety controls (scope, approvals, the block list, audit).
- Report security vulnerabilities privately, following [SECURITY.md](SECURITY.md).

## Getting set up

1. Install JDK 17 or later.
2. Obtain the Montoya API jar. It ships with Burp Suite, or can be taken from the PortSwigger extension API release.
3. Build and run the tests:
   ```bash
   ./build.sh /path/to/montoya-api.jar --test
   ```
   The build output is `dist/AuditLens.jar`. Everything under `build/` and `dist/` is generated and is not committed.

## Code guidelines

- **Java 17**, no new runtime dependencies. The Excel writer is intentionally dependency-free.
- Keep Burp-independent logic in plain classes (for example `triage/Triage`, `report/*`) so it can be unit-tested
  without Burp.
- **Escape everything** written to HTML or XML. Use `HtmlReport.esc` and `Xlsx.esc`. Captured data is attacker-controlled.
- **Policy first.** Anything that sends a request must go through `Policy` and `PolicyGate`. Do not call Burp's HTTP
  send APIs directly from new code paths.
- Keep the model out of security decisions. The model proposes; code decides.
- Prefer small, named methods and comments that explain *why*, especially around security controls.

## Tests

- Add or update tests for every behaviour change. Tests are plain `main` classes under `src/test/java/ollamaat/`
  and are registered in `build.sh` (and in `build.gradle`).
- New triage rules, report sections and workbook parts need tests that check the output, not only that it runs.
- The suite must pass with `./build.sh <jar> --test` before a pull request is opened.

## Adding content

- **Skill:** a Markdown file under `src/main/resources/skills/` with `name` and `description` front matter, listed in
  `index.txt`. Regenerate `docs/SKILLS.md`. Skills must describe test steps only, and must not contain exploit payloads
  for unauthorised use.
- **Remediation entry:** add a `Rule` to `report/RemediationKb.java`. Give concrete guidance and references to
  primary sources (OWASP, vendor documentation, RFCs). Specific rules go before general ones.
- **Agent tool:** add an `FnTool` in `tools/BurpTools.java` with a clear `Policy` classification and a test.

## Pull requests

1. Fork the repository and create a topic branch.
2. Keep the change focused. Explain the *why* in the description.
3. Fill in the pull request template, including the tests you ran.
4. Describe any change to a safety control or to what is written to reports or the audit log. Those need extra review.

## Commit messages

Use the imperative mood and a short summary line, for example `Add evidence sheet to Excel export`. Add a body when the
reason is not obvious from the diff.

## Licence of contributions

By contributing, you agree that your contribution may be distributed under the project's licence, once one is chosen.
