package ollamaat;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.*;
import java.util.function.Function;

/** Checks that [AI] issues already in Burp's Issues list are imported into the Findings tab, once each. */
public final class SyncTest {
    public static void main(String[] x) {
        int fails = 0;
        Map<String, Function<Object[], Object>> o = new HashMap<>();
        o.put("Preferences.getString", a -> SmokeTest.PREFS.get(a[0]));
        o.put("Preferences.setString", a -> { SmokeTest.PREFS.put((String) a[0], (String) a[1]); return null; });
        o.put("PersistedObject.getString", a -> null);
        o.put("PersistedObject.setString", a -> null);
        List<AuditIssue> issues = new ArrayList<>();
        o.put("SiteMap.issues", a -> issues);
        MontoyaApi api = SmokeTest.stub(MontoyaApi.class, o);
        issues.add(issue("[AI] Potential XSS via IMG tag in User-Agent", "https://demo.testfire.net/login.jsp", "<p>The &lt;img&gt; tag</p><p><b>Evidence:</b> x</p>", AuditIssueSeverity.MEDIUM));
        issues.add(issue("[AI] Multiple spoofed IP headers present", "https://demo.testfire.net/login.jsp", "<p>d</p>", AuditIssueSeverity.LOW));
        issues.add(issue("Strict transport security not enforced", "https://demo.testfire.net/", "<p>burp native</p>", AuditIssueSeverity.LOW));

        Engine engine = new Engine(api);
        int n1 = engine.syncFindingsFromBurp();
        fails += check(n1 == 2, "imports only [AI] issues (got " + n1 + ")");
        fails += check(engine.memory.findings().size() == 2, "Findings tab has 2 rows");
        var f = engine.memory.findings().get(0);
        fails += check(f.title().equals("Potential XSS via IMG tag in User-Agent"), "title stripped of [AI] prefix");
        fails += check(f.detail().contains("The <img> tag") && !f.detail().contains("<p>"), "detail converted to plain text");
        fails += check(f.severity().equals("MEDIUM") && f.reportedToBurp(), "severity kept, marked as in Burp");
        int n2 = engine.syncFindingsFromBurp();
        fails += check(n2 == 0 && engine.memory.findings().size() == 2, "second sync adds no duplicates");

        // importBurpIssues(false) imports Burp's native issues too (the non-[AI] one), not just [AI]-tagged.
        int n3 = engine.importBurpIssues(false);
        fails += check(n3 == 1, "importing all Burp issues adds the native issue (got " + n3 + ")");
        fails += check(engine.memory.findings().stream().anyMatch(y -> y.title().equals("Strict transport security not enforced")),
                "native Burp issue appears in Findings with its own title");
        fails += check(engine.memory.findings().size() == 3, "Findings tab now has all 3 issues");
        int n4 = engine.importBurpIssues(false);
        fails += check(n4 == 0, "re-importing all Burp issues adds no duplicates");

        System.out.println();
        System.out.println((11 - fails) + " passed, " + fails + " failed");
        if (fails > 0) System.exit(1);
    }

    static AuditIssue issue(String name, String url, String detail, AuditIssueSeverity sev) {
        Map<String, Function<Object[], Object>> o = new HashMap<>();
        o.put("AuditIssue.name", a -> name);
        o.put("AuditIssue.baseUrl", a -> url);
        o.put("AuditIssue.detail", a -> detail);
        o.put("AuditIssue.remediation", a -> null);
        o.put("AuditIssue.severity", a -> sev);
        o.put("AuditIssue.requestResponses", a -> List.of());
        return SmokeTest.stub(AuditIssue.class, o);
    }

    static int check(boolean ok, String what) { System.out.println((ok ? "  ok   " : "  FAIL ") + what); return ok ? 0 : 1; }
}
