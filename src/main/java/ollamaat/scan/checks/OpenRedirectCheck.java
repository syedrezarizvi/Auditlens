package ollamaat.scan.checks;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import ollamaat.scan.CheckContext;
import ollamaat.scan.ScanCheck;
import ollamaat.scan.ScanFinding;
import ollamaat.scan.Signatures;

import java.util.ArrayList;
import java.util.List;

/** Open-redirect detector using an RFC 2606 '.invalid' host, which can never resolve on the real internet. */
public final class OpenRedirectCheck implements ScanCheck {
    private static final String TARGET = "https://ollamaat-redirect-check.invalid/";
    public String id() { return "open-redirect"; }
    public String name() { return "Open redirect"; }
    public String description() { return "On redirect/return/next-style parameters, sets the value to an unresolvable external host and checks for a redirect to it."; }
    public boolean passiveOnly() { return false; }

    public List<ScanFinding> run(HttpRequestResponse baseline, CheckContext ctx) {
        List<ScanFinding> out = new ArrayList<>();
        for (ParsedHttpParameter p : ParamUtil.mutable(baseline)) {
            if (ctx.cancelled()) break;
            if (!Signatures.REDIRECT_PARAM.matcher(p.name()).find()) continue;
            HttpRequest req = ParamUtil.withValue(baseline, p, TARGET);
            var r = ctx.send(req, "Open redirect probe on '" + p.name() + "' at " + baseline.request().url());
            if (!r.ok()) continue;
            var resp = r.rr().response();
            String loc = resp.headerValue("Location");
            boolean redirected = resp.statusCode() / 100 == 3 && loc != null && loc.contains("ollamaat-redirect-check.invalid");
            boolean metaOrJs = resp.bodyToString().contains("ollamaat-redirect-check.invalid")
                    && (resp.bodyToString().toLowerCase().contains("http-equiv=\"refresh\"") || resp.bodyToString().toLowerCase().contains("location.href"));
            if (!redirected && !metaOrJs) continue;
            String ref = ctx.evidence.addAgent(r.rr());
            out.add(ScanFinding.of(id(), "Open redirect via '" + p.name() + "'", "medium", redirected ? "firm" : "tentative", baseline.request().url(),
                    "Setting parameter '" + p.name() + "' to an arbitrary external URL caused the application to redirect there "
                            + (redirected ? "(HTTP " + resp.statusCode() + " Location: " + loc + ")." : "via a client-side meta-refresh/JS redirect."),
                    "Validate redirect targets against an allow-list of known-safe destinations, or use indirect references (e.g. a lookup key) instead of a raw URL.",
                    List.of(ref)));
        }
        return out;
    }
}
