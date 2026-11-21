package ollamaat;

import ollamaat.tools.Evidence;

/** Host extraction used to reject evidence references that point at unrelated traffic. */
public final class EvidenceHostTest {
    public static void main(String[] a) {
        int fails = 0;
        fails += check("app.example.test".equals(Evidence.hostOf("https://app.example.test/admin?x=1")), "host from a full URL");
        fails += check("app.example.test".equals(Evidence.hostOf("https://app.example.test:8443/x")), "port is ignored");
        fails += check("i.ytimg.com".equals(Evidence.hostOf("https://i.ytimg.com/vi/abc/hq.jpg")), "third-party host is read");
        fails += check(Evidence.hostOf("") == null && Evidence.hostOf(null) == null, "blank or null URL has no host");
        fails += check(Evidence.hostOf("not a url with spaces") == null, "unparseable URL has no host");
        System.out.println(fails == 0 ? "EvidenceHostTest: all checks passed" : "EvidenceHostTest: " + fails + " check(s) failed");
        if (fails > 0) System.exit(1);
    }

    private static int check(boolean ok, String name) {
        System.out.println((ok ? "PASS " : "FAIL ") + name);
        return ok ? 0 : 1;
    }
}
