package ollamaat;

import ollamaat.agent.*;
import ollamaat.report.FindingGroup;
import ollamaat.report.HtmlReport;
import ollamaat.report.ReportOptions;

import java.util.List;

/** A finding marked as a false positive stays in the Findings tab but is left out of every report, and the mark persists. */
public final class FalsePositiveTest {
    public static void main(String[] a) {
        int fails = 0;
        Persist store = Persist.memory();
        Memory m = new Memory(store);
        m.addFinding(new Memory.Finding(1L, 0, "Reflected XSS in search", "HIGH", "FIRM", "https://t.example/search",
                "Reflected value.", "", List.of(), false));
        m.addFinding(new Memory.Finding(2L, 0, "Missing HSTS header", "LOW", "TENTATIVE", "https://t.example/",
                "No HSTS.", "", List.of(), false));

        fails += check(FindingGroup.of(m.findings(), true).size() == 2, "both findings reported before marking");
        Memory.Finding xss = m.findings().get(0);
        fails += check(m.setFalsePositive(xss, true), "mark succeeds for a recorded finding");
        List<FindingGroup> groups = FindingGroup.of(m.findings(), true);
        fails += check(groups.size() == 1 && groups.get(0).title.equals("Missing HSTS header"), "marked finding is left out of the groups");
        fails += check(m.findings().size() == 2, "marked finding stays in the Findings list");

        String html = HtmlReport.generate(new ReportOptions(), m.findings(), null, new Settings(Settings.memoryStore()), null);
        fails += check(!html.contains("Reflected XSS in search") && html.contains("Missing HSTS header"), "HTML report omits the marked finding");

        fails += check(new Memory(store).findings().get(0).falsePositive(), "mark survives a reload");

        fails += check(m.setFalsePositive(m.findings().get(0), false), "unmark succeeds");
        fails += check(FindingGroup.of(m.findings(), true).size() == 2, "unmarked finding is reported again");

        fails += check(!m.setFalsePositive(new Memory.Finding(9L, 0, "Not recorded", "HIGH", "FIRM", "https://x.example/",
                "", "", List.of(), false), true), "unknown finding is not changed");

        System.out.println(fails == 0 ? "FalsePositiveTest: all checks passed" : "FalsePositiveTest: " + fails + " check(s) failed");
        if (fails > 0) System.exit(1);
    }

    private static int check(boolean ok, String name) {
        System.out.println((ok ? "PASS " : "FAIL ") + name);
        return ok ? 0 : 1;
    }
}
