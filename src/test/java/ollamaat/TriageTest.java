package ollamaat;

import ollamaat.agent.Memory;
import ollamaat.report.ExcelReport;
import ollamaat.report.FindingGroup;
import ollamaat.report.ReportOptions;

import java.io.ByteArrayInputStream;
import java.util.*;
import java.util.zip.ZipInputStream;

/** Findings carry an AI false-positive triage verdict that persists, groups, and shows in the Excel report. */
public final class TriageTest {
    static int n = 0;
    public static void main(String[] a) throws Exception {
        Map<String, String> store = new HashMap<>();
        ollamaat.agent.Persist persist = new ollamaat.agent.Persist() {
            public String get(String k) { return store.get(k); }
            public void set(String k, String v) { store.put(k, v); }
        };
        Memory mem = new Memory(persist);
        mem.addFinding(new Memory.Finding(1L, 0, "Reflected XSS", "HIGH", "FIRM", "https://t/x", "input reflected", "", List.of("p1"), true));
        int fails = 0;
        fails += check(mem.findings().get(0).aiTriage().isEmpty(), "new finding has empty triage");

        boolean set = mem.setTriage("Reflected XSS", "https://t/x", "FALSE POSITIVE (AI, high confidence) — reflected into a JSON string, safely encoded");
        fails += check(set, "setTriage finds and updates the finding");
        fails += check(mem.findings().get(0).aiTriage().startsWith("FALSE POSITIVE"), "triage verdict stored on finding");

        // Persisted: a fresh Memory over the same store reloads the triage.
        Memory reloaded = new Memory(persist);
        fails += check(reloaded.findings().size() == 1 && reloaded.findings().get(0).aiTriage().startsWith("FALSE POSITIVE"),
                "triage verdict persists across reload");

        // Grouping carries the verdict.
        List<FindingGroup> groups = FindingGroup.of(reloaded.findings(), true);
        fails += check(!groups.isEmpty() && groups.get(0).aiTriage.startsWith("FALSE POSITIVE"), "group carries triage verdict");

        // Excel report has the AI Triage column and the verdict.
        byte[] xlsx = ExcelReport.generate(new ReportOptions(), reloaded.findings());
        String sheet = null;
        try (ZipInputStream z = new ZipInputStream(new ByteArrayInputStream(xlsx))) {
            java.util.zip.ZipEntry e;
            while ((e = z.getNextEntry()) != null) if (e.getName().equals("xl/worksheets/sheet1.xml"))
                sheet = new String(z.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        }
        fails += check(sheet.contains("AI Triage") && sheet.contains("FALSE POSITIVE"), "Excel has AI Triage column with the verdict");
        fails += check(sheet.contains("FALSE POSITIVE"), "Excel row shows the triage verdict");

        System.out.println();
        System.out.println((n - fails) + " passed, " + fails + " failed");
        if (fails > 0) System.exit(1);
    }

    static int check(boolean ok, String what) { n++; System.out.println((ok ? "  ok   " : "  FAIL ") + what); return ok ? 0 : 1; }
}
