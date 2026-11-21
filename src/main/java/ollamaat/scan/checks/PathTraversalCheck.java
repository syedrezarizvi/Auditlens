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

/** Conservative path-traversal signal: only fires on file/path-looking parameter names, never requests a real
 *  system file (no /etc/passwd etc.) — it looks for path-disclosure or a clear behavioural change instead. */
public final class PathTraversalCheck implements ScanCheck {
    public String id() { return "path-traversal"; }
    public String name() { return "Path traversal (signal only)"; }
    public String description() { return "On file/path-like parameters, prefixes '../' sequences and looks for path disclosure or a distinct error, without reading real system files."; }
    public boolean passiveOnly() { return false; }

    public List<ScanFinding> run(HttpRequestResponse baseline, CheckContext ctx) {
        List<ScanFinding> out = new ArrayList<>();
        if (!baseline.hasResponse()) return out;
        String baseBody = baseline.response().bodyToString();
        int baseStatus = baseline.response().statusCode();

        for (ParsedHttpParameter p : ParamUtil.mutable(baseline)) {
            if (ctx.cancelled()) break;
            if (!Signatures.FILE_PARAM.matcher(p.name()).find()) continue;
            String probeValue = "../../../../../../" + p.value();
            HttpRequest req = ParamUtil.withValue(baseline, p, probeValue);
            var r = ctx.send(req, "Path traversal probe on '" + p.name() + "' at " + baseline.request().url());
            if (!r.ok()) continue;
            String body = r.rr().response().bodyToString();
            int status = r.rr().response().statusCode();
            boolean pathDisclosed = body.matches("(?s).*(/[a-zA-Z0-9_./-]*" + java.util.regex.Pattern.quote(lastSegment(p.value())) + ").*")
                    && (body.contains("No such file") || body.contains("failed to open stream") || body.contains("cannot find the path"));
            boolean behaviourChanged = status != baseStatus && Fmt.similarity(baseBody, body) < 0.6;
            if (!pathDisclosed && !behaviourChanged) continue;
            String ref = ctx.evidence.addAgent(r.rr());
            out.add(ScanFinding.of(id(), "Possible path traversal via '" + p.name() + "'", "medium", "tentative", baseline.request().url(),
                    "Prefixing '../' sequences onto parameter '" + p.name() + "' "
                            + (pathDisclosed ? "caused the server to disclose a resolved filesystem path in its error output."
                                             : "produced a different status/response (" + baseStatus + " -> " + status + ") than the unmodified request.")
                            + " This is a signal only; no system file was read. Manual confirmation with the path-traversal-lfi skill is recommended.",
                    "Canonicalize and validate file paths server-side against an allow-list; never build filesystem paths directly from user input.",
                    List.of(ref)));
        }
        return out;
    }

    private static String lastSegment(String v) {
        int i = Math.max(v.lastIndexOf('/'), v.lastIndexOf('\\'));
        String s = i >= 0 ? v.substring(i + 1) : v;
        return s.isBlank() ? "x" : s;
    }
}
