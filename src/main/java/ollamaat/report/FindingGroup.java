package ollamaat.report;

import ollamaat.agent.Memory;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Groups individual findings by (title, severity) so one issue class that affects many endpoints becomes a single
 *  report row/section listing all affected URLs, instead of N near-identical rows. */
public final class FindingGroup {
    public final String title, confidence, detail, remediation;
    public String severity;
    public String aiTriage = "";
    public final List<String> urls = new ArrayList<>();
    public final List<String> evidence = new ArrayList<>();
    public long time;

    private FindingGroup(Memory.Finding f) {
        this.title = f.title(); this.severity = f.severity(); this.confidence = f.confidence();
        this.detail = f.detail(); this.remediation = f.remediation(); this.time = f.time();
    }

    /** Same issue name, regardless of "[AI]" prefix, case or spacing, so duplicates merge into one entry. */
    static String key(String title) {
        String t = title == null ? "" : title.trim();
        if (t.regionMatches(true, 0, "[AI]", 0, 4)) t = t.substring(4);
        return t.trim().replaceAll("\\s+", " ").toLowerCase(java.util.Locale.ROOT);
    }

    private void add(Memory.Finding f) {
        if (f.severity() != null && rank(f.severity()) < rank(this.severity)) this.severity = f.severity();
        if (aiTriage.isBlank() && f.aiTriage() != null && !f.aiTriage().isBlank()) aiTriage = f.aiTriage();
        if (!f.url().isBlank() && !urls.contains(f.url())) urls.add(f.url());
        for (String e : f.evidence()) if (!evidence.contains(e)) evidence.add(e);
        this.time = Math.max(this.time, f.time());
    }

    /** Suggested CVSS v3.1 base score for this merged issue (see {@link Cvss}). Uses the highest severity seen. */
    public Cvss.Score score() { return Cvss.forFinding(title, detail, severity); }

    private static int rank(String sev) {
        return switch (sev == null ? "" : sev.toUpperCase()) {
            case "HIGH" -> 0; case "MEDIUM" -> 1; case "LOW" -> 2; default -> 3;
        };
    }

    /**
     * Merges every finding with the same issue name into one entry listing all affected URLs. The entry takes the
     * highest severity seen across its duplicates. Sorted by severity (high first) then title.
     * includeInfo=false drops informational findings. Findings marked as false positive by the tester are always dropped.
     */
    public static List<FindingGroup> of(List<Memory.Finding> findings, boolean includeInfo) {
        Map<String, FindingGroup> map = new LinkedHashMap<>();
        for (Memory.Finding f : findings) {
            if (f.falsePositive()) continue; // marked by the tester: excluded from every report
            if (!includeInfo && f.severity().equalsIgnoreCase("information")) continue;
            FindingGroup g = map.computeIfAbsent(key(f.title()), k -> new FindingGroup(f));
            g.add(f);
        }
        List<FindingGroup> groups = new ArrayList<>(map.values());
        groups.sort(Comparator.comparingInt((FindingGroup g) -> rank(g.severity)).thenComparing(g -> g.title));
        return groups;
    }
}
