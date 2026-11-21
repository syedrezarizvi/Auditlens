package ollamaat.scan.checks;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import ollamaat.scan.CheckContext;
import ollamaat.scan.ScanCheck;
import ollamaat.scan.ScanFinding;
import ollamaat.tools.Fmt;

import java.util.ArrayList;
import java.util.List;

/** CORS: reflects an arbitrary Origin and checks whether it is trusted (optionally with credentials). Only
 *  runs on responses that already look like API traffic (JSON/XML) to keep volume down on static/HTML pages. */
public final class CorsMisconfigCheck implements ScanCheck {
    private static final String ORIGIN = "https://ollamaat-cors-check.invalid";
    public String id() { return "cors-misconfig"; }
    public String name() { return "CORS misconfiguration"; }
    public String description() { return "Sends an arbitrary Origin header on API-like requests and checks whether it is reflected as trusted, especially with credentials allowed."; }
    public boolean passiveOnly() { return false; }

    public List<ScanFinding> run(HttpRequestResponse baseline, CheckContext ctx) {
        List<ScanFinding> out = new ArrayList<>();
        if (!baseline.hasResponse()) return out;
        String ct = Fmt.contentType(baseline.response());
        boolean apiLike = ct.contains("json") || ct.contains("xml") || baseline.request().path().toLowerCase().contains("/api/");
        if (!apiLike) return out;

        HttpRequest req = baseline.request().withHeader("Origin", ORIGIN);
        var r = ctx.send(req, "CORS probe at " + baseline.request().url());
        if (!r.ok()) return out;
        var resp = r.rr().response();
        String acao = resp.headerValue("Access-Control-Allow-Origin");
        String acac = resp.headerValue("Access-Control-Allow-Credentials");
        if (acao == null) return out;
        boolean reflectsArbitrary = acao.equals(ORIGIN);
        boolean wildcard = acao.equals("*");
        boolean credsTrue = "true".equalsIgnoreCase(acac);
        if (!reflectsArbitrary && !(wildcard && credsTrue)) return out; // wildcard alone (no creds) is normal/intended public API behaviour

        String ref = ctx.evidence.addAgent(r.rr());
        boolean critical = reflectsArbitrary && credsTrue;
        out.add(ScanFinding.of(id(), "CORS misconfiguration" + (critical ? " allowing credentialed cross-origin reads" : ""),
                critical ? "high" : "medium", critical ? "firm" : "tentative", baseline.request().url(),
                "The response reflects an arbitrary Origin (`" + ORIGIN + "`) in Access-Control-Allow-Origin"
                        + (credsTrue ? " together with Access-Control-Allow-Credentials: true, which lets any website read this endpoint's "
                                       + "response while including the victim's cookies/session." : ", allowing any website to read this response.")
                        + (wildcard && credsTrue ? " (Note: Access-Control-Allow-Origin: * combined with credentials:true is invalid per the CORS "
                                                    + "spec and browsers should reject it, but the misconfiguration itself should still be fixed.)" : ""),
                "Only reflect Origin for an explicit allow-list of trusted origins, never a wildcard combined with credentials; "
                        + "validate Origin server-side rather than echoing it unconditionally.",
                List.of(ref)));
        return out;
    }
}
