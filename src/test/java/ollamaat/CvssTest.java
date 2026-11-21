package ollamaat;

import ollamaat.agent.Memory;
import ollamaat.report.Cvss;
import ollamaat.report.FindingGroup;
import ollamaat.report.HtmlReport;
import ollamaat.report.ReportOptions;
import ollamaat.report.Summary;

import java.util.List;

/** Validates CVSS v3.1 scoring, rating bands, category/severity consistency, the management summary and the engine toggle. */
public final class CvssTest {
    public static void main(String[] a) {
        int fails = 0;

        // Reference vectors (CVSS v3.1 specification examples and published values)
        fails += check(Cvss.base("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8, "9.8 reference vector");
        fails += check(Cvss.base("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N") == 4.3, "4.3 reference vector with prefix");
        fails += check(Cvss.base("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N") == 7.5, "7.5 single high confidentiality impact");
        fails += check(Cvss.base("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0, "scope-changed maximum is 10.0");
        fails += check(Cvss.base("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0, "no impact scores 0.0");
        fails += throwsIae("incomplete vector is rejected", () -> Cvss.base("AV:N/AC:L"));
        fails += throwsIae("unknown metric value is rejected", () -> Cvss.base("AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"));

        // Roundup and rating bands
        fails += check(Cvss.roundUp(4.0) == 4.0, "roundup keeps exact tenths");
        fails += check(Cvss.roundUp(4.02) == 4.1, "roundup rounds up any remainder");
        fails += check(Cvss.ratingOf(0.0).equals("None"), "0.0 is None");
        fails += check(Cvss.ratingOf(3.9).equals("Low"), "3.9 is Low");
        fails += check(Cvss.ratingOf(4.0).equals("Medium"), "4.0 is Medium");
        fails += check(Cvss.ratingOf(6.9).equals("Medium"), "6.9 is Medium");
        fails += check(Cvss.ratingOf(7.0).equals("High"), "7.0 is High");
        fails += check(Cvss.ratingOf(8.9).equals("High"), "8.9 is High");
        fails += check(Cvss.ratingOf(9.0).equals("Critical"), "9.0 is Critical");

        // Category vector used when its band matches the reported severity
        Cvss.Score sqli = Cvss.forFinding("NoSQL/SSJI Time-Based Injection", "", "HIGH");
        fails += check(sqli.base() == 9.8 && sqli.basis().equals("category"), "SQL injection HIGH uses the category vector (" + sqli.label() + ")");
        fails += check(sqli.vector().equals("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), "vector carries the CVSS:3.1 prefix");

        // Band disagreement falls back to the severity default, so the score never contradicts the severity
        Cvss.Score mismatch = Cvss.forFinding("NoSQL/SSJI Time-Based Injection", "", "LOW");
        fails += check(mismatch.base() == 3.1 && mismatch.basis().equals("severity"), "LOW severity overrides a Critical category (" + mismatch.label() + ")");

        // Severity defaults for an unrecognised category
        Cvss.Score unknownHigh = Cvss.forFinding("Totally novel thing", "", "HIGH");
        fails += check(unknownHigh.base() == 8.2 && unknownHigh.rating().equals("High") && unknownHigh.basis().equals("severity"), "unknown HIGH uses the 8.2 default");
        Cvss.Score unknownMedium = Cvss.forFinding("Totally novel thing", "", "MEDIUM");
        fails += check(unknownMedium.base() == 5.4 && unknownMedium.rating().equals("Medium"), "unknown MEDIUM uses the 5.4 default");
        Cvss.Score info = Cvss.forFinding("Next.js Framework Detected", "", "INFORMATION");
        fails += check(info.base() == 0.0 && info.vector().isEmpty() && info.rating().equals("None"), "informational is unscored");

        // Management summary and top risks
        List<Memory.Finding> findings = List.of(
                new Memory.Finding(1L, 0, "NoSQL/SSJI Time-Based Injection", "HIGH", "TENTATIVE", "https://t/a", "Injected.", "", List.of("p1"), true),
                new Memory.Finding(2L, 0, "NoSQL/SSJI Time-Based Injection", "HIGH", "TENTATIVE", "https://t/b", "Injected.", "", List.of("p2"), true),
                new Memory.Finding(3L, 0, "Verbose User-Agent String", "LOW", "TENTATIVE", "https://t/c", "UA echoed.", "", List.of(), false),
                new Memory.Finding(4L, 0, "Next.js Framework Detected", "INFORMATION", "TENTATIVE", "https://t/d", "Next.js found.", "", List.of(), false));
        List<FindingGroup> groups = FindingGroup.of(findings, true);
        Summary s = Summary.of(groups);
        fails += check(s.issues == 3, "three distinct issues");
        fails += check(s.locations == 4, "four affected locations (duplicate URLs counted once each)");
        fails += check(s.rows.get(0).severity().equals("HIGH") && s.rows.get(0).issues() == 1 && s.rows.get(0).locations() == 2, "HIGH row counts issue and locations");
        fails += check(s.rows.get(1).issues() == 0, "MEDIUM row present with zero");
        fails += check(s.rows.get(0).timeline().equals("Within 7 days") && s.rows.get(3).timeline().equals("Hardening backlog"), "timelines per severity");
        fails += check(s.topScore == 9.8 && !s.topRisks.isEmpty() && s.topRisks.get(0).title.startsWith("NoSQL"), "top risk is the highest-scoring issue");
        fails += check(s.overall.equals("High") && !s.businessImpact.isBlank(), "overall rating and business impact present");

        // HTML: engine toggle, management table and CVSS presentation
        Settings settings = new Settings(Settings.memoryStore());
        ReportOptions on = new ReportOptions();
        on.showEngine = true;
        ReportOptions off = new ReportOptions();
        off.showEngine = false;
        String withEngine = HtmlReport.generate(on, findings, null, settings, null);
        String withoutEngine = HtmlReport.generate(off, findings, null, settings, null);
        fails += check(withEngine.contains("<dt>Engine</dt>"), "engine shown when enabled");
        fails += check(!withoutEngine.contains("<dt>Engine</dt>") && !withoutEngine.contains("AuditLens, local model"), "engine hidden when disabled");
        fails += check(withoutEngine.contains("Management summary by severity") && withoutEngine.contains("Within 7 days"), "management table rendered");
        fails += check(withoutEngine.contains("CVSS 9.8") && withoutEngine.contains("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), "CVSS score and vector rendered");
        fails += check(withoutEngine.contains("Highest-priority issues"), "executive summary lists top risks");

        System.out.println(fails == 0 ? "CvssTest: all checks passed" : "CvssTest: " + fails + " check(s) failed");
        if (fails > 0) System.exit(1);
    }

    private static int throwsIae(String name, Runnable r) {
        try { r.run(); return check(false, name); }
        catch (IllegalArgumentException e) { return check(true, name); }
    }

    private static int check(boolean ok, String name) {
        System.out.println((ok ? "PASS " : "FAIL ") + name);
        return ok ? 0 : 1;
    }
}
