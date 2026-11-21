package ollamaat.report;

import ollamaat.agent.Memory;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;

/**
 * Builds an .xlsx findings report with the columns: SL.No, Finding Name, Issue Description, Severity (with the
 * suggested CVSS score and vector), Affected URLs, Impact, Remediations (including reference links) and AI Triage.
 * Findings of the same type across multiple endpoints are grouped into one row that lists every affected URL.
 * Impact and remediation come from {@link RemediationKb}.
 */
public final class ExcelReport {
    private ExcelReport() {}

    private static final DateTimeFormatter DAY = DateTimeFormatter.ofPattern("d MMMM yyyy").withZone(ZoneId.systemDefault());

    private static final List<String> HEADERS = List.of(
            "SL.No", "Finding Name", "Issue Description", "Severity", "Affected URLs", "Impact", "Remediations", "AI Triage");
    private static final List<Integer> WIDTHS = List.of(7, 32, 60, 26, 50, 46, 72, 40);
    private static final int MAX_URLS = 60;

    /**
     * Workbook with a single "Findings" sheet (one row per issue, duplicates merged). Cover, management summary
     * and evidence stay in the HTML report only.
     */
    public static byte[] generate(ReportOptions opt, List<Memory.Finding> findings) {
        List<FindingGroup> groups = FindingGroup.of(findings, opt.includeInfo);

        Xlsx x = new Xlsx("Findings").header(HEADERS, WIDTHS);
        int sl = 1;
        for (FindingGroup g : groups) {
            RemediationKb.Entry kb = RemediationKb.lookup(g.title, g.detail);
            x.row(List.of(
                    String.valueOf(sl++),
                    nz(g.title),
                    nz(g.detail),
                    severityCell(g),
                    affectedUrls(g),
                    nz(kb.impact()),
                    remediationCell(g, kb),
                    g.aiTriage == null || g.aiTriage.isBlank() ? "Not analyzed" : g.aiTriage));
        }
        if (groups.isEmpty())
            x.row(List.of("", "No findings recorded.", "", "", "", "", "", ""));

        return x.toBytes();
    }

    private static String severityCell(FindingGroup g) {
        Cvss.Score s = g.score();
        if (s.vector().isEmpty()) return cap(g.severity);
        return cap(g.severity) + "\nCVSS " + String.format(Locale.ROOT, "%.1f", s.base()) + " (" + s.rating() + ")\n" + s.vector();
    }

    private static String affectedUrls(FindingGroup g) {
        if (g.urls.isEmpty()) return "(not recorded)";
        StringBuilder b = new StringBuilder();
        int shown = Math.min(g.urls.size(), MAX_URLS);
        for (int i = 0; i < shown; i++) { if (i > 0) b.append("\n"); b.append(g.urls.get(i)); }
        if (g.urls.size() > MAX_URLS) b.append("\n…and ").append(g.urls.size() - MAX_URLS).append(" more");
        if (g.urls.size() > 1) b.insert(0, "(" + g.urls.size() + " affected)\n");
        return b.toString();
    }

    private static String remediationCell(FindingGroup g, RemediationKb.Entry kb) {
        StringBuilder b = new StringBuilder();
        if (!g.remediation.isBlank())
            b.append("Finding-specific: ").append(g.remediation.trim()).append("\n\n");
        b.append(kb.remediation().trim());
        if (!kb.refs().isEmpty()) {
            b.append("\n\nReferences:");
            for (RemediationKb.Ref ref : kb.refs())
                b.append("\n• ").append(ref.title()).append(" - ").append(ref.url());
        }
        return b.toString();
    }

    private static String nz(String s) { return s == null ? "" : s.trim(); }

    private static String cap(String s) {
        if (s == null || s.isBlank()) return "Information";
        String t = s.trim().toLowerCase();
        return Character.toUpperCase(t.charAt(0)) + t.substring(1);
    }
}
