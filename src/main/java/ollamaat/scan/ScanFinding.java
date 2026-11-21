package ollamaat.scan;

import java.util.List;

/** One result from a deterministic active-scan check, before it becomes a Memory.Finding. */
public record ScanFinding(String checkId, String title, String severity, String confidence, String url,
                          String detail, String remediation, List<String> evidence) {
    public static ScanFinding of(String checkId, String title, String severity, String confidence, String url,
                                 String detail, String remediation, List<String> evidence) {
        return new ScanFinding(checkId, title, severity, confidence, url, detail, remediation, evidence);
    }
}
