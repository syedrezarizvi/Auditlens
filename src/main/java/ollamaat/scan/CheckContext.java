package ollamaat.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import ollamaat.Settings;
import ollamaat.agent.Action;
import ollamaat.agent.PolicyGate;
import ollamaat.agent.RunState;
import ollamaat.tools.Evidence;
import ollamaat.tools.Fmt;
import ollamaat.tools.Throttle;

import java.util.function.Consumer;

/** What a {@link ScanCheck} needs to plan and (if allowed) send one probe request. Every send goes through the
 *  same {@link PolicyGate} as the chat agent: scope, budget, rate limit, approvals and the block list all apply. */
public final class CheckContext {
    public static final String TOOL = "active_scan";

    public final MontoyaApi api;
    public final Settings settings;
    public final Evidence evidence;
    public final Throttle throttle;
    public final RunState runState;
    private final PolicyGate gate;
    private final Consumer<String> log;

    public CheckContext(MontoyaApi api, Settings settings, Evidence evidence, Throttle throttle, RunState runState,
                        PolicyGate gate, Consumer<String> log) {
        this.api = api; this.settings = settings; this.evidence = evidence; this.throttle = throttle;
        this.runState = runState; this.gate = gate; this.log = log;
    }

    public void log(String s) { if (log != null) log.accept(s); }

    public boolean cancelled() { return runState.cancelled; }

    /** Outcome of one probe attempt: rr is null if policy blocked/denied it or it errored (see denyReason). */
    public record Probe(HttpRequestResponse rr, long elapsedMs, String denyReason) {
        public boolean ok() { return rr != null && rr.hasResponse(); }
    }

    /** Sends req if policy allows it; elapsedMs measures only the actual network call (not throttle wait or approval wait). */
    public Probe send(HttpRequest req, String summary) {
        if (runState.cancelled) return new Probe(null, 0, "run cancelled");
        var net = new Action.NetInfo(req.method(), req.url(), req.body().length() > 0, Fmt.request(req, 1500, false));
        Action a = Action.network(summary, net, () -> "");
        PolicyGate.Outcome o = gate.check(TOOL, a, runState);
        if (!o.allowed) {
            String reason = ("policy".equals(o.decidedBy) ? "blocked: " : "denied: ") + o.message;
            log.accept(reason + " — " + summary);
            return new Probe(null, 0, reason);
        }
        runState.requestsSent.incrementAndGet();
        throttle.acquire();
        long t0 = System.nanoTime();
        try {
            HttpRequestResponse rr = api.http().sendRequest(req);
            long elapsed = (System.nanoTime() - t0) / 1_000_000;
            gate.recordAllowed(runState.runId, TOOL, summary, o.decidedBy, rr.hasResponse() ? ("" + rr.response().statusCode() + " in " + elapsed + "ms") : "no response");
            return new Probe(rr, elapsed, null);
        } catch (RuntimeException e) {
            gate.recordAllowed(runState.runId, TOOL, summary, o.decidedBy, "error: " + e.getMessage());
            log.accept("error sending " + summary + ": " + e.getMessage());
            return new Probe(null, 0, "error: " + e.getMessage());
        }
    }
}
