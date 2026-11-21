# Publishing AuditLens

This page is for the maintainer. It covers publishing the source on GitHub, cutting a release, and what is still needed
for a PortSwigger BApp Store submission.

## 1. Before the first push

- [ ] **Choose a licence** and add a `LICENSE` file. Until then the README states that all rights are reserved, which
      does not fit an open repository. The BApp Store also requires a licence.
- [ ] **Replace the placeholder** in `SECURITY.md` (`[maintainer contact — to be added before publication]`) with a
      real contact, or enable GitHub private vulnerability reporting and keep only that channel.
- [ ] **Check the artefacts.** Run `git status` and confirm that no reports, captured traffic, `.burp` project files or
      client names are staged. `.gitignore` excludes `*.html`, `*.xlsx`, `*.burp` and `*.log`, but check the
      staged list anyway.
- [ ] **Confirm the tests pass:** `./build.sh /path/to/montoya-api.jar --test`.

## 2. Create the repository

```bash
cd publish/OllamaAT
git init -b main
git add .
git commit -m "Initial public release of AuditLens"
gh repo create <owner>/AuditLens --public --source=. --remote=origin --push
```

Settings to check on GitHub:

- **Security → Private vulnerability reporting**: enable it, so `SECURITY.md` has a working route.
- **Branch protection** on `main`: require the `build` workflow to pass before merge.
- **Topics**: `burp-suite`, `burp-extension`, `montoya-api`, `pentesting`, `ai`, `ollama`.

The `build` workflow (`.github/workflows/build.yml`) fetches the Montoya API jar from Maven Central, builds the extension
and runs the test suite on every push and pull request. Update `MONTOYA_API_VERSION` when Burp ships a new API release.

## 3. Cut a release

1. Set the version in `CHANGELOG.md` (move the "Unreleased" heading to the version number and date).
2. Build: `./build.sh /path/to/montoya-api.jar --test`.
3. Tag and push:
   ```bash
   git tag -a v1.0.0 -m "AuditLens 1.0.0"
   git push origin v1.0.0
   ```
4. Create a GitHub release from the tag. Attach `dist/AuditLens.jar` and paste the matching changelog section into the notes.

Do not attach sample reports to a release. Use only synthetic data (`example.test`) if you publish a sample.

## 4. BApp Store submission

PortSwigger reviews each BApp against its published criteria. Check the current criteria and the submission process on
PortSwigger's site before you submit, because they can change. Items that are open for AuditLens:

- **Licence.** See section 1.
- **Networking.** BApp reviewers may expect HTTP traffic to go through Burp's networking API. The Ollama client uses
  Java's `java.net.http`, which goes around Burp. The Burp AI provider is the default, so the extension complies on the
  default path. Confirm how the reviewers treat the Ollama option before you submit, and document the choice in the
  submission.
- **Uniqueness.** Check the existing BApp Store listings for overlap with the agent, the false-positive analysis and the
  reporting features.
- **Testing.** Test the release jar in the current Burp Suite Professional and Community versions. The Burp AI behaviour
  (message roles, quotas and JSON output reliability) has not yet been tested against a live account.

## 5. Payment

PortSwigger's statement on BApps is that they are published for free. Check the current developer terms before you
assume any payment or revenue share.
