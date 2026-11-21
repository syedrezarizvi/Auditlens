package ollamaat;

import ollamaat.agent.Memory;
import ollamaat.report.ExcelReport;
import ollamaat.report.ReportOptions;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.ZipInputStream;

/** Excel export is a single Findings sheet; every XML part is well-formed. */
public final class ExcelMultiSheetTest {
    static int n = 0;
    public static void main(String[] a) throws Exception {
        int fails = 0;
        ReportOptions opt = new ReportOptions();
        opt.organization = "Acme Security Labs";
        opt.logoBytes = new byte[]{(byte) 0x89, 'P', 'N', 'G', 1, 2, 3};
        opt.logoExt = "png";
        List<Memory.Finding> f = List.of(new Memory.Finding(1L, 0, "Reflected XSS", "HIGH", "FIRM", "https://t.example/s",
                "reflected", "", List.of("p1", "s2"), true, "FALSE POSITIVE (AI)"));
        byte[] xlsx = ExcelReport.generate(opt, f);

        Map<String, byte[]> parts = new LinkedHashMap<>();
        try (ZipInputStream z = new ZipInputStream(new ByteArrayInputStream(xlsx))) {
            java.util.zip.ZipEntry e;
            while ((e = z.getNextEntry()) != null) parts.put(e.getName(), z.readAllBytes());
        }
        fails += check(parts.containsKey("xl/worksheets/sheet1.xml") && !parts.containsKey("xl/worksheets/sheet2.xml"),
                "single worksheet part");
        String wb = new String(parts.get("xl/workbook.xml"), StandardCharsets.UTF_8);
        fails += check(wb.contains("name=\"Findings\"") && !wb.contains("name=\"Cover\"") && !wb.contains("name=\"Evidence\""),
                "only the Findings tab");
        fails += check(!parts.containsKey("xl/drawings/drawing1.xml"), "cover logo is not written to Excel");
        String findings = new String(parts.get("xl/worksheets/sheet1.xml"), StandardCharsets.UTF_8);
        fails += check(findings.contains("Finding Name") && findings.contains("AI Triage") && findings.contains("Affected URLs"),
                "Findings table has the requested columns");
        fails += check(findings.contains("Reflected XSS"), "finding row is present");

        for (Map.Entry<String, byte[]> p : parts.entrySet()) {
            if (!p.getKey().endsWith(".xml") && !p.getKey().endsWith(".rels")) continue;
            boolean ok;
            try { DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(new ByteArrayInputStream(p.getValue())); ok = true; }
            catch (Exception ex) { ok = false; }
            fails += check(ok, "well-formed XML: " + p.getKey());
        }

        // An empty report still has the Findings tab with its "no findings" row.
        byte[] empty = ExcelReport.generate(new ReportOptions(), List.of());
        String emptySheet = "";
        try (ZipInputStream z = new ZipInputStream(new ByteArrayInputStream(empty))) {
            java.util.zip.ZipEntry e;
            while ((e = z.getNextEntry()) != null) if (e.getName().equals("xl/worksheets/sheet1.xml")) emptySheet = new String(z.readAllBytes(), StandardCharsets.UTF_8);
        }
        fails += check(emptySheet.contains("No findings recorded."), "empty report shows the no-findings row");

        System.out.println();
        System.out.println((n - fails) + " passed, " + fails + " failed");
        if (fails > 0) System.exit(1);
    }
    static int check(boolean ok, String what) { n++; System.out.println((ok ? "  ok   " : "  FAIL ") + what); return ok ? 0 : 1; }
}
