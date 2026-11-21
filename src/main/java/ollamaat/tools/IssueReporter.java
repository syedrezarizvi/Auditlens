package ollamaat.tools;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import ollamaat.agent.Memory;
import ollamaat.agent.ToolException;

import java.util.ArrayList;
import java.util.List;

/** Shared "turn a finding into a Burp issue + Memory.Finding" path, used by both the chat agent's add_finding
 *  tool and the active scanner, so findings look consistent regardless of where they came from. */
public final class IssueReporter {
    private IssueReporter() {}

    public static AuditIssueSeverity severity(String s) {
        return switch (s.toLowerCase()) {
            case "high", "critical" -> AuditIssueSeverity.HIGH;
            case "medium" -> AuditIssueSeverity.MEDIUM;
            case "low" -> AuditIssueSeverity.LOW;
            default -> AuditIssueSeverity.INFORMATION;
        };
    }

    public static AuditIssueConfidence confidence(String s) {
        return switch (s.toLowerCase()) {
            case "certain" -> AuditIssueConfidence.CERTAIN;
            case "firm" -> AuditIssueConfidence.FIRM;
            default -> AuditIssueConfidence.TENTATIVE;
        };
    }

    public static String esc(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br>");
    }

    /** Resolves refs via {@code resolver}, adds a Burp issue (best-effort) and records a Memory.Finding. */
    public static Memory.Finding report(MontoyaApi api, Memory memory, int runId, String source, String title, String severityStr,
                                        String confidenceStr, String url, String detail, String remediation,
                                        List<String> evidenceRefs, RefResolver resolver) throws ToolException {
        AuditIssueSeverity sev = severity(severityStr);
        AuditIssueConfidence conf = confidence(confidenceStr);
        List<HttpRequestResponse> rrs = new ArrayList<>();
        for (String r : evidenceRefs) rrs.add(resolver.resolve(r));
        boolean reported = false;
        try {
            AuditIssue issue = AuditIssue.auditIssue("[AI] " + title, "<p>" + esc(detail) + "</p>",
                    remediation == null || remediation.isEmpty() ? null : "<p>" + esc(remediation) + "</p>", url, sev, conf,
                    "<p>Reported by AuditLens (" + source + ") using a local LLM / deterministic checks. Verify manually before relying on this.</p>",
                    null, sev, rrs);
            api.siteMap().add(issue);
            reported = true;
        } catch (RuntimeException e) {
            api.logging().logToError("AuditLens: could not add issue to site map: " + e);
        }
        Memory.Finding f = new Memory.Finding(System.currentTimeMillis(), runId, title, sev.name(), conf.name(), url, detail,
                remediation == null ? "" : remediation, evidenceRefs, reported);
        memory.addFinding(f);
        return f;
    }

    public interface RefResolver { HttpRequestResponse resolve(String ref) throws ToolException; }
}
