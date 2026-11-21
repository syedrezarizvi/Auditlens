package ollamaat.scan.checks;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import ollamaat.scan.CheckContext;
import ollamaat.scan.ScanCheck;
import ollamaat.scan.ScanFinding;
import ollamaat.scan.Signatures;
import ollamaat.tools.Fmt;

import java.util.ArrayList;
import java.util.List;

/**
 * Reflected-XSS detector. Uses an inert, non-existent HTML tag name as the canary (never a real tag, never an
 * event handler, nothing that could execute): if it comes back byte-for-byte unescaped in an HTML response,
 * that proves the same unescaped-HTML-context reflection a real payload would exploit, with zero execution risk.
 */
public final class ReflectedXssCheck implements ScanCheck {
    public String id() { return "reflected-xss"; }
    public String name() { return "Reflected XSS (unescaped HTML reflection)"; }
    public String description() { return "Injects an inert marker tag into each parameter and checks whether it is reflected unescaped in an HTML response."; }
    public boolean passiveOnly() { return false; }

    public List<ScanFinding> run(HttpRequestResponse baseline, CheckContext ctx) {
        List<ScanFinding> out = new ArrayList<>();
        if (!baseline.hasResponse()) return out;
        String ct = Fmt.contentType(baseline.response());
        if (!ct.isEmpty() && !ct.contains("html") && !ct.contains("xml")) return out; // JSON/text reflection isn't HTML-exploitable here

        for (ParsedHttpParameter p : ParamUtil.mutable(baseline)) {
            if (ctx.cancelled()) break;
            String marker = Signatures.marker();
            String probe = "<" + marker + ">";
            HttpRequest req = ParamUtil.withValue(baseline, p, p.value() + probe);
            var r = ctx.send(req, "XSS probe on '" + p.name() + "' at " + baseline.request().url());
            if (!r.ok()) continue;
            String body = r.rr().response().bodyToString();
            if (body.contains(probe)) {
                String ref = ctx.evidence.addAgent(r.rr());
                out.add(ScanFinding.of(id(), "Reflected XSS via '" + p.name() + "'", "high", "firm", baseline.request().url(),
                        "The value of parameter '" + p.name() + "' is reflected unescaped in an HTML response. Probe marker `" + probe
                                + "` appeared verbatim (unescaped) in the response body, proving the application does not HTML-encode this input "
                                + "before writing it into the page. A real payload in place of the inert marker would execute in the victim's browser.",
                        "HTML-encode all user input before writing it into HTML responses (contextual output encoding); prefer a templating "
                                + "engine with auto-escaping enabled; add a restrictive Content-Security-Policy as defence in depth.",
                        List.of(ref)));
            }
        }
        return out;
    }
}
