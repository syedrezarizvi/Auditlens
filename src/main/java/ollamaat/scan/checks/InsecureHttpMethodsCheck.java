package ollamaat.scan.checks;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import ollamaat.scan.CheckContext;
import ollamaat.scan.ScanCheck;
import ollamaat.scan.ScanFinding;

import java.util.ArrayList;
import java.util.List;

/** Host-level: sends one OPTIONS request and flags risky methods advertised in the Allow header, plus a single
 *  TRACE probe to check for Cross-Site Tracing (the server reflecting the request back verbatim). */
public final class InsecureHttpMethodsCheck implements ScanCheck {
    public String id() { return "http-methods"; }
    public String name() { return "Insecure HTTP methods"; }
    public String description() { return "Once per host: sends OPTIONS and checks the Allow header, and a single TRACE probe for Cross-Site Tracing."; }
    public boolean passiveOnly() { return false; }
    public boolean perHost() { return true; }

    public List<ScanFinding> run(HttpRequestResponse baseline, CheckContext ctx) {
        List<ScanFinding> out = new ArrayList<>();
        HttpRequest opt = baseline.request().withMethod("OPTIONS").withPath("/");
        var r1 = ctx.send(opt, "OPTIONS probe on " + baseline.httpService());
        if (r1.ok()) {
            String allow = r1.rr().response().headerValue("Allow");
            if (allow != null) {
                String upper = allow.toUpperCase();
                List<String> risky = new ArrayList<>();
                for (String m : List.of("PUT", "DELETE", "TRACE", "CONNECT")) if (upper.contains(m)) risky.add(m);
                if (!risky.isEmpty()) {
                    String ref = ctx.evidence.addAgent(r1.rr());
                    out.add(ScanFinding.of(id(), "Potentially risky HTTP methods enabled: " + String.join(", ", risky), "low", "firm",
                            baseline.httpService().toString(), "OPTIONS on the host advertises: " + allow + ". Methods like PUT/DELETE/TRACE/CONNECT "
                                    + "should only be enabled where the application explicitly needs them and enforces proper authorization.",
                            "Disable unused HTTP methods at the web server/framework level; ensure PUT/DELETE require the same authorization as "
                                    + "their GET/POST equivalents.", List.of(ref)));
                }
            }
        }
        HttpRequest trace = baseline.request().withMethod("TRACE").withPath("/").withAddedHeader("X-Ollamaat-Trace-Check", "1");
        var r2 = ctx.send(trace, "TRACE probe on " + baseline.httpService());
        if (r2.ok() && r2.rr().response().statusCode() == 200 && r2.rr().response().bodyToString().contains("X-Ollamaat-Trace-Check")) {
            String ref = ctx.evidence.addAgent(r2.rr());
            out.add(ScanFinding.of(id(), "Cross-Site Tracing (TRACE method reflects request)", "low", "firm", baseline.httpService().toString(),
                    "The server accepts TRACE and reflects the request (including our custom header) verbatim in the response body, which can be "
                            + "combined with other bugs (e.g. XSS) to read HttpOnly cookies via Cross-Site Tracing.",
                    "Disable the TRACE method at the web server level.", List.of(ref)));
        }
        return out;
    }
}
