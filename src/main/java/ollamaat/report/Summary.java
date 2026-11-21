package ollamaat.report;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * Deterministic figures shared by the HTML and Excel reports: per-severity counts, affected locations, remediation
 * timelines, the highest-scoring issues and a business-impact sentence chosen from the finding categories.
 */
public final class Summary {
    /** Order used in every table: most severe first. */
    public static final List<String> ORDER = List.of("HIGH", "MEDIUM", "LOW", "INFORMATION");

    /** One row of the management table. */
    public record Row(String severity, long issues, long locations, String timeline) {}

    public final List<Row> rows;
    public final long issues, locations;
    /** Highest reported severity, or "None" when there are no findings. */
    public final String overall;
    /** Highest suggested CVSS base score across all issues (0.0 when none is scored). */
    public final double topScore;
    /** Up to three issues with the highest suggested CVSS scores, highest first. */
    public final List<FindingGroup> topRisks;
    public final String businessImpact;

    private Summary(List<Row> rows, long issues, long locations, String overall, double topScore,
                    List<FindingGroup> topRisks, String businessImpact) {
        this.rows = rows; this.issues = issues; this.locations = locations; this.overall = overall;
        this.topScore = topScore; this.topRisks = topRisks; this.businessImpact = businessImpact;
    }

    public static Summary of(List<FindingGroup> groups) {
        List<Row> rows = new ArrayList<>();
        long issues = 0, locations = 0;
        for (String sev : ORDER) {
            long n = 0, loc = 0;
            for (FindingGroup g : groups) {
                if (!g.severity.toUpperCase(Locale.ROOT).equals(sev)) continue;
                n++;
                loc += Math.max(1, g.urls.size());
            }
            rows.add(new Row(sev, n, loc, timeline(sev)));
            issues += n;
            locations += loc;
        }

        List<FindingGroup> ranked = new ArrayList<>(groups);
        ranked.sort(Comparator.comparingDouble((FindingGroup g) -> g.score().base()).reversed().thenComparing(g -> g.title));
        List<FindingGroup> top = new ArrayList<>();
        for (FindingGroup g : ranked) if (g.score().base() > 0 && top.size() < 3) top.add(g);
        double topScore = top.isEmpty() ? 0.0 : top.get(0).score().base();

        String overall = groups.isEmpty() ? "None" : cap(groups.get(0).severity);
        return new Summary(rows, issues, locations, overall, topScore, top, impactSentence(groups));
    }

    /** Remediation target for each reported severity. */
    public static String timeline(String severity) {
        return switch (severity.toUpperCase(Locale.ROOT)) {
            case "HIGH" -> "Within 7 days";
            case "MEDIUM" -> "Within 30 days";
            case "LOW" -> "Within 90 days";
            default -> "Hardening backlog";
        };
    }

    /** One or more sentences chosen from the categories present; never claims more than the findings show. */
    private static String impactSentence(List<FindingGroup> groups) {
        boolean access = false, client = false, exposure = false;
        for (FindingGroup g : groups) {
            String c = RemediationKb.lookup(g.title, g.detail).category().toLowerCase(Locale.ROOT);
            if (c.contains("authorization") || c.contains("idor") || c.contains("sql") || c.contains("traversal")) access = true;
            if (c.contains("xss") || c.contains("redirect") || c.contains("csp") || c.contains("header")
                    || c.contains("cookie") || c.contains("cors")) client = true;
            if (c.contains("disclosure") || c.contains("exposure") || c.contains("source map")
                    || c.contains("ssrf") || c.contains("sensitive")) exposure = true;
        }
        List<String> out = new ArrayList<>();
        if (access) out.add("Some issues could allow unauthorised access to data or functions, which may lead to a data breach and regulatory exposure where personal data is involved.");
        if (exposure) out.add("Information exposure could reveal configuration, credentials or internal addresses that make further attacks easier.");
        if (client) out.add("Client-side weaknesses could let an attacker act within a user's session or lure users to malicious content.");
        if (out.isEmpty()) out.add(groups.isEmpty() ? "No business impact was identified."
                : "The remaining items are mainly hardening measures that reduce the attack surface.");
        return String.join(" ", out);
    }

    private static String cap(String s) {
        if (s == null || s.isEmpty()) return "";
        return s.charAt(0) + s.substring(1).toLowerCase(Locale.ROOT);
    }
}
