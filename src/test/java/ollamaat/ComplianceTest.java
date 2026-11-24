package ollamaat;

import burp.api.montoya.EnhancedCapability;

/** BApp Store compliance: the extension must declare AI support, or Burp keeps api.ai() disabled and Burp AI
 *  (the required default provider) never works. */
public final class ComplianceTest {
    public static void main(String[] a) {
        int fails = 0;
        var caps = new AuditLens().enhancedCapabilities();
        fails += check(caps != null && caps.contains(EnhancedCapability.AI_FEATURES),
                "AuditLens declares EnhancedCapability.AI_FEATURES (so Burp AI is available by default)");
        System.out.println(fails == 0 ? "ComplianceTest: all checks passed" : "ComplianceTest: " + fails + " check(s) failed");
        if (fails > 0) System.exit(1);
    }

    private static int check(boolean ok, String name) {
        System.out.println((ok ? "PASS " : "FAIL ") + name);
        return ok ? 0 : 1;
    }
}
