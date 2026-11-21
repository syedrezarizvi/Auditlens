package ollamaat.report;

import java.util.Map;

/**
 * CVSS v3.1 base-score calculator plus a suggested base vector for each remediation category.
 *
 * <p>The scores are estimates for prioritisation, derived from the finding category, not from a full analysis of the
 * confirmed issue. A category vector is used only when its rating band agrees with the finding's reported severity
 * (HIGH = High or Critical, MEDIUM = Medium, LOW = Low). Otherwise the severity default vector is used, so a score
 * never contradicts the severity printed beside it. Informational findings are scored 0.0 with no vector.
 */
public final class Cvss {
    private Cvss() {}

    /** A base score, its vector (empty when unscored), its rating band, and whether it came from the category or severity. */
    public record Score(double base, String vector, String rating, String basis) {
        /** "9.8 (Critical)" for display. */
        public String label() { return String.format(java.util.Locale.ROOT, "%.1f (%s)", base, rating); }
    }

    private static final String PREFIX = "CVSS:3.1/";

    /** Suggested base metrics (without the prefix) for each category in {@link RemediationKb}. */
    private static final Map<String, String> CATEGORY_VECTORS = Map.ofEntries(
            Map.entry("Next.js Middleware Authorization Bypass", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
            Map.entry("Next.js Server Actions Authorization", "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
            Map.entry("Next.js Data Exposure (__NEXT_DATA__ / environment)", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
            Map.entry("React XSS (dangerouslySetInnerHTML / javascript: URLs)", "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
            Map.entry("Next.js Image Optimizer SSRF", "AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N"),
            Map.entry("JavaScript Source Map Exposure", "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
            Map.entry("Vulnerable Next.js or React Version", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
            Map.entry("Cross-Site Scripting (XSS)", "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
            Map.entry("SQL Injection", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            Map.entry("Server-Side Request Forgery (SSRF)", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"),
            Map.entry("Content Security Policy (CSP) Weakness", "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"),
            Map.entry("Missing Security Headers / Clickjacking", "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"),
            Map.entry("Insecure Cookie Attributes", "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"),
            Map.entry("CORS Misconfiguration", "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"),
            Map.entry("Information Disclosure", "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
            Map.entry("Insecure Direct Object Reference (IDOR / BOLA)", "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
            Map.entry("Open Redirect", "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
            Map.entry("Path / Directory Traversal", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
            Map.entry("Sensitive Data in URL", "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
            Map.entry("Insecure HTTP Methods", "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L"));

    /** Default vector for each reported severity, used when the category has no vector or its band disagrees. */
    private static final Map<String, String> SEVERITY_VECTORS = Map.of(
            "HIGH", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",      // 8.2
            "MEDIUM", "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",    // 5.4
            "LOW", "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");      // 3.1

    /** Suggested score for a finding, from its category (when consistent with severity) or the severity default. */
    public static Score forFinding(String title, String detail, String severity) {
        String sev = severity == null ? "" : severity.trim().toUpperCase(java.util.Locale.ROOT);
        if (!SEVERITY_VECTORS.containsKey(sev)) return new Score(0.0, "", "None", "informational");

        String category = RemediationKb.lookup(title, detail).category();
        String vector = CATEGORY_VECTORS.get(category);
        if (vector != null) {
            Score s = scoreOf(vector, "category");
            if (bandMatches(s.rating(), sev)) return s;
        }
        return scoreOf(SEVERITY_VECTORS.get(sev), "severity");
    }

    /** Base score for a CVSS v3.1 base vector such as "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" (prefix optional). */
    public static double base(String vector) {
        Map<String, String> m = parse(vector);
        boolean changed = need(m, "S").equals("C");

        double av = switch (need(m, "AV")) {
            case "N" -> 0.85; case "A" -> 0.62; case "L" -> 0.55; case "P" -> 0.2;
            default -> throw bad("AV");
        };
        double ac = switch (need(m, "AC")) {
            case "L" -> 0.77; case "H" -> 0.44; default -> throw bad("AC");
        };
        double pr = switch (need(m, "PR")) {
            case "N" -> 0.85;
            case "L" -> changed ? 0.68 : 0.62;
            case "H" -> changed ? 0.5 : 0.27;
            default -> throw bad("PR");
        };
        double ui = switch (need(m, "UI")) {
            case "N" -> 0.85; case "R" -> 0.62; default -> throw bad("UI");
        };
        double c = cia(need(m, "C")), i = cia(need(m, "I")), a = cia(need(m, "A"));

        double iss = 1 - (1 - c) * (1 - i) * (1 - a);
        double impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
        double exploitability = 8.22 * av * ac * pr * ui;
        if (impact <= 0) return 0.0;
        return changed ? roundUp(Math.min(1.08 * (impact + exploitability), 10))
                       : roundUp(Math.min(impact + exploitability, 10));
    }

    /** CVSS v3.1 qualitative rating: None, Low, Medium, High or Critical. */
    public static String ratingOf(double base) {
        if (base == 0.0) return "None";
        if (base < 4.0) return "Low";
        if (base < 7.0) return "Medium";
        if (base < 9.0) return "High";
        return "Critical";
    }

    /** CVSS v3.1 "Roundup": the smallest value with one decimal place that is not less than x. */
    public static double roundUp(double x) {
        long i = Math.round(x * 100000);
        if (i % 10000 == 0) return i / 100000.0;
        return (Math.floor(i / 10000.0) + 1) / 10.0;
    }

    private static Score scoreOf(String body, String basis) {
        double b = base(body);
        return new Score(b, PREFIX + body, ratingOf(b), basis);
    }

    private static boolean bandMatches(String rating, String sev) {
        return switch (sev) {
            case "HIGH" -> rating.equals("High") || rating.equals("Critical");
            case "MEDIUM" -> rating.equals("Medium");
            case "LOW" -> rating.equals("Low");
            default -> false;
        };
    }

    private static double cia(String v) {
        return switch (v) {
            case "H" -> 0.56; case "L" -> 0.22; case "N" -> 0.0;
            default -> throw new IllegalArgumentException("Bad CIA metric: " + v);
        };
    }

    private static Map<String, String> parse(String vector) {
        Map<String, String> m = new java.util.HashMap<>();
        if (vector == null) throw new IllegalArgumentException("Vector is null");
        for (String part : vector.trim().split("/")) {
            if (part.startsWith("CVSS:")) continue;
            int eq = part.indexOf(':');
            if (eq <= 0) throw new IllegalArgumentException("Bad vector segment: " + part);
            m.put(part.substring(0, eq), part.substring(eq + 1));
        }
        return m;
    }

    private static String need(Map<String, String> m, String k) {
        String v = m.get(k);
        if (v == null) throw new IllegalArgumentException("Vector is missing " + k);
        return v;
    }

    private static IllegalArgumentException bad(String k) {
        return new IllegalArgumentException("Bad value for " + k);
    }
}
