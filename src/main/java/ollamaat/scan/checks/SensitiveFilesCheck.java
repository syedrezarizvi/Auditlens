package ollamaat.scan.checks;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import ollamaat.scan.CheckContext;
import ollamaat.scan.ScanCheck;
import ollamaat.scan.ScanFinding;
import ollamaat.scan.Signatures;
import ollamaat.tools.Fmt;

import java.util.ArrayList;
import java.util.List;

/** Host-level, low-volume content discovery: a short curated list of common sensitive paths (.git, .env, actuator,
 *  swagger, backups). Establishes the app's generic 404 signature first so a soft-404 page isn't reported as a hit. */
public final class SensitiveFilesCheck implements ScanCheck {
    public String id() { return "sensitive-files"; }
    public String name() { return "Exposed sensitive files"; }
    public String description() { return "Once per host: requests a short list of common sensitive paths (.git/config, .env, actuator, swagger, backups)."; }
    public boolean passiveOnly() { return false; }
    public boolean perHost() { return true; }

    public List<ScanFinding> run(HttpRequestResponse baseline, CheckContext ctx) {
        List<ScanFinding> out = new ArrayList<>();
        String marker = "/ollamaat-404-check-" + Signatures.marker();
        var notFound = ctx.send(baseline.request().withPath(marker), "404-baseline probe on " + baseline.httpService());
        if (!notFound.ok()) return out;
        String notFoundBody = notFound.rr().response().bodyToString();
        int notFoundStatus = notFound.rr().response().statusCode();

        for (String path : Signatures.SENSITIVE_PATHS) {
            if (ctx.cancelled()) break;
            HttpRequest req = baseline.request().withPath(path);
            var r = ctx.send(req, "Sensitive-file probe " + path + " on " + baseline.httpService());
            if (!r.ok()) continue;
            var resp = r.rr().response();
            boolean looksLikeHit = (resp.statusCode() == 200 || resp.statusCode() == 403)
                    && resp.statusCode() != notFoundStatus
                    && Fmt.similarity(notFoundBody, resp.bodyToString()) < 0.8
                    && resp.body().length() > 0;
            if (!looksLikeHit) continue;
            String ref = ctx.evidence.addAgent(r.rr());
            boolean highRisk = path.contains(".git") || path.contains(".env") || path.contains("config");
            out.add(ScanFinding.of(id(), "Exposed sensitive path: " + path, highRisk ? "high" : "medium", "tentative",
                    baseline.httpService() + path, "Requesting " + path + " returned HTTP " + resp.statusCode()
                            + " with content distinct from the application's generic not-found response, suggesting the file/endpoint exists and "
                            + "is reachable. Confirm manually before relying on this (some apps serve a distinct-but-harmless page here).",
                    "Remove the file from the web root, block the path at the web server/CDN, or require authentication for internal endpoints.",
                    List.of(ref)));
        }
        return out;
    }
}
