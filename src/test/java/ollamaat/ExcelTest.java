package ollamaat;

import ollamaat.agent.Memory;
import ollamaat.report.ExcelReport;
import ollamaat.report.RemediationKb;
import ollamaat.report.ReportOptions;

import java.io.ByteArrayInputStream;
import java.util.*;
import java.util.zip.ZipInputStream;

/** Validates the Excel report: KB lookup, required columns, reference links, and that the xlsx zip is well-formed. */
public final class ExcelTest {
    public static void main(String[] a) throws Exception {
        int fails = 0;

        // KB lookup routing
        fails += check(RemediationKb.lookup("Potential SSRF via X-Forwarded-Host", "").category().contains("SSRF"), "SSRF routed");
        fails += check(RemediationKb.lookup("Reflected XSS in search", "").category().contains("XSS"), "XSS routed");
        fails += check(RemediationKb.lookup("NoSQL/SSJI Time-Based Injection", "").category().contains("SQL"), "SQLi routed");
        fails += check(!RemediationKb.lookup("Totally novel thing", "").refs().isEmpty(), "generic has refs");
        fails += check(RemediationKb.lookup("Dangerous Content-Security-Policy (CSP)", "").refs().stream().anyMatch(r -> r.url().startsWith("https://")), "CSP refs are links");

        List<Memory.Finding> findings = List.of(
            new Memory.Finding(1L, 0, "Potential SSRF via X-Forwarded-Host", "HIGH", "TENTATIVE", "https://t/a", "Host reflected into fetch.", "", List.of("p1"), true),
            new Memory.Finding(2L, 0, "Verbose User-Agent String", "LOW", "TENTATIVE", "https://t/b", "UA echoed.", "Strip the header.", List.of(), false));

        byte[] xlsx = ExcelReport.generate(new ReportOptions(), findings);
        fails += check(xlsx.length > 500, "xlsx produced (" + xlsx.length + " bytes)");

        // Unzip and sanity-check parts + content
        Map<String, String> parts = new HashMap<>();
        try (ZipInputStream z = new ZipInputStream(new ByteArrayInputStream(xlsx))) {
            java.util.zip.ZipEntry e;
            while ((e = z.getNextEntry()) != null) {
                byte[] buf = z.readAllBytes();
                parts.put(e.getName(), new String(buf, java.nio.charset.StandardCharsets.UTF_8));
            }
        }
        fails += check(parts.containsKey("[Content_Types].xml"), "has [Content_Types].xml");
        fails += check(parts.containsKey("xl/workbook.xml"), "has workbook.xml");
        fails += check(parts.containsKey("xl/worksheets/sheet1.xml"), "has sheet1.xml (Findings, the only sheet)");
        fails += check(parts.containsKey("xl/styles.xml"), "has styles.xml");

        String sheet = parts.get("xl/worksheets/sheet1.xml");
        for (String col : new String[]{"SL.No", "Finding Name", "Issue Description", "Severity", "Affected URLs", "Impact", "Remediations", "AI Triage"})
            fails += check(sheet.contains(col), "header present: " + col);
        fails += check(sheet.contains("Potential SSRF via X-Forwarded-Host"), "finding title present");
        fails += check(sheet.contains("References:") && sheet.contains("https://cheatsheetseries.owasp.org"), "remediation has reference links");
        fails += check(sheet.contains("Finding-specific: Strip the header."), "finding-specific remediation merged");
        fails += check(sheet.contains(">1<") || sheet.contains("&gt;1") || sheet.contains("<t xml:space=\"preserve\">1</t>"), "SL numbering present");
        // well-formed XML parse of the sheet
        javax.xml.parsers.DocumentBuilderFactory.newInstance().newDocumentBuilder()
            .parse(new ByteArrayInputStream(sheet.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        fails += check(true, "Findings sheet parses as XML");

        // Strict CT_Worksheet child order (Excel rejects out-of-order parts even though openpyxl tolerates them).
        int iDim = sheet.indexOf("<dimension"), iViews = sheet.indexOf("<sheetViews"), iCols = sheet.indexOf("<cols"),
            iData = sheet.indexOf("<sheetData"), iFilter = sheet.indexOf("<autoFilter");
        fails += check(iDim >= 0 && iDim < iViews && iViews < iCols && iCols < iData && iData < iFilter,
                "worksheet child elements are in schema order (dimension<sheetViews<cols<sheetData<autoFilter)");

        // Grouping: two findings with the same title+severity across different URLs become ONE row listing both URLs.
        List<Memory.Finding> dup = List.of(
            new Memory.Finding(3L, 0, "Object identifier in URL - possible IDOR", "MEDIUM", "TENTATIVE", "https://t/a?kno=1", "d", "", List.of(), true),
            new Memory.Finding(4L, 0, "Object identifier in URL - possible IDOR", "MEDIUM", "TENTATIVE", "https://t/b?kno=2", "d", "", List.of(), true));
        byte[] gx = ExcelReport.generate(new ReportOptions(), dup);
        String gsheet;
        try (ZipInputStream z = new ZipInputStream(new ByteArrayInputStream(gx))) {
            java.util.zip.ZipEntry e; String found = null;
            while ((e = z.getNextEntry()) != null) if (e.getName().equals("xl/worksheets/sheet1.xml")) found = new String(z.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            gsheet = found;
        }
        int rowCount = gsheet.split("<row ").length - 1; // header + data rows
        fails += check(rowCount == 2, "two same-title findings collapse to one data row (header+1, got rows=" + rowCount + ")");
        fails += check(gsheet.contains("https://t/a?kno=1") && gsheet.contains("https://t/b?kno=2"), "both affected URLs listed in the grouped row");
        fails += check(gsheet.contains("(2 affected)"), "affected-URL count shown");

        // write it out so we can validate with a real reader
        java.nio.file.Files.write(java.nio.file.Path.of("/tmp/ollamaat-sample.xlsx"), xlsx);

        System.out.println();
        System.out.println((countChecks - fails) + " passed, " + fails + " failed");
        if (fails > 0) System.exit(1);
    }

    static int countChecks = 0;
    static int check(boolean ok, String what) { countChecks++; System.out.println((ok ? "  ok   " : "  FAIL ") + what); return ok ? 0 : 1; }
}
