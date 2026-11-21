package ollamaat;

import ollamaat.ui.ReportDialog;

import java.time.LocalDate;

/** Default report file name: AuditLens_<project>_<yyyy-MM-dd>.<ext>. */
public final class ReportFileNameTest {
    static int n = 0, fails = 0;
    public static void main(String[] a) {
        String today = LocalDate.now().toString();
        check(("AuditLens_Acme-Portal_" + today + ".html").equals(ReportDialog.defaultFileName("Acme Portal", "", "html")), "project name spaces become dashes");
        check(("AuditLens_shop.example.test_" + today + ".xlsx").equals(ReportDialog.defaultFileName("", "https://shop.example.test/login", "xlsx")), "falls back to scope host");
        check(("AuditLens_Project_" + today + ".html").equals(ReportDialog.defaultFileName("  ", "", "html")), "falls back to Project");
        check(("AuditLens_Client-X-v2_" + today + ".html").equals(ReportDialog.defaultFileName("Client/X: v2!", "", "html")), "unsafe characters removed");
        System.out.println();
        System.out.println((n - fails) + " passed, " + fails + " failed");
        if (fails > 0) System.exit(1);
    }
    static void check(boolean ok, String what) { n++; if (!ok) fails++; System.out.println((ok ? "  ok   " : "  FAIL ") + what); }
}
