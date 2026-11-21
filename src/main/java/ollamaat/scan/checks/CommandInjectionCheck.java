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

/** OS command injection via a single-shot timing probe (a short sleep), never a loop, never &gt;3s, and only
 *  on command/host/network-looking parameter names to keep volume low. No file writes, downloads or network
 *  callouts are attempted — a reproducible delay is sufficient signal. */
public final class CommandInjectionCheck implements ScanCheck {
    private static final int DELAY_SECONDS = 3;
    private static final List<String> SEPARATORS = List.of(";", "|");
    public String id() { return "command-injection"; }
    public String name() { return "OS command injection (timing signal)"; }
    public String description() { return "On command/host-like parameters, appends a single short 'sleep' probe (one shot, <=2 variants) and compares response latency to the baseline."; }
    public boolean passiveOnly() { return false; }

    public List<ScanFinding> run(HttpRequestResponse baseline, CheckContext ctx) {
        List<ScanFinding> out = new ArrayList<>();
        for (ParsedHttpParameter p : ParamUtil.mutable(baseline)) {
            if (ctx.cancelled()) break;
            if (!Signatures.COMMAND_PARAM.matcher(p.name()).find()) continue;
            for (String sep : SEPARATORS) {
                if (ctx.cancelled()) break;
                String probeValue = p.value() + " " + sep + "sleep " + DELAY_SECONDS + sep;
                HttpRequest req = ParamUtil.withValue(baseline, p, probeValue);
                var r = ctx.send(req, "Command injection timing probe on '" + p.name() + "' at " + baseline.request().url());
                if (!r.ok()) continue;
                if (r.elapsedMs() >= DELAY_SECONDS * 900L) {
                    String ref = ctx.evidence.addAgent(r.rr());
                    out.add(ScanFinding.of(id(), "Possible OS command injection via '" + p.name() + "'", "high", "tentative", baseline.request().url(),
                            "Appending `" + sep + "sleep " + DELAY_SECONDS + sep + "` to parameter '" + p.name() + "' made the response take "
                                    + r.elapsedMs() + "ms (vs a normal request), consistent with the server executing the injected sleep command. "
                                    + "Run this once more manually before relying on it, as network jitter can occasionally cause false positives.",
                            "Never pass user input to a shell; use language-level APIs (not shell invocation) or strict allow-listing if shelling out is unavoidable.",
                            List.of(ref)));
                    break; // one confirmed signal per parameter is enough
                }
            }
        }
        return out;
    }
}
