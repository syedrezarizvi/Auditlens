package ollamaat.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import ollamaat.Settings;
import ollamaat.agent.*;
import ollamaat.scan.checks.*;
import ollamaat.tools.Evidence;
import ollamaat.tools.Throttle;

import java.util.*;
import java.util.function.BiConsumer;

/**
 * Orchestrates deterministic {@link ScanCheck}s across a set of candidate requests. Every probe goes through
 * {@link PolicyGate} (same scope/approval/budget/block-list rules as the chat agent), so active scanning cannot
 * exceed what the pentester's autonomy/scope settings already allow. Results become {@link ScanFinding}s, which
 * the caller turns into {@link Memory.Finding}s and Burp issues (see Engine#addScanFinding).
 */
public final class ActiveScanEngine {
    public enum EventType { START, ENDPOINT, CHECK, FINDING, SKIP, DONE, ERROR }
    public interface Listener {
        void event(EventType type, String text);
        /** Called once per confirmed finding, in addition to the FINDING text event, so the caller can persist it. */
        default void finding(ScanFinding f) { }
    }

    private final MontoyaApi api;
    private final Settings settings;
    private final Evidence evidence;
    private final Policy policy;
    private final Approvals approvals;
    private final AuditLog audit;
    private final Throttle throttle;
    private volatile RunState current;

    public static List<ScanCheck> allChecks() {
        return List.of(new PassiveAnalysisCheck(), new ReflectedXssCheck(), new SqlInjectionCheck(), new PathTraversalCheck(),
                new OpenRedirectCheck(), new CommandInjectionCheck(), new CorsMisconfigCheck(), new InsecureHttpMethodsCheck(),
                new SensitiveFilesCheck());
    }

    public ActiveScanEngine(MontoyaApi api, Settings settings, Evidence evidence, Policy policy, Approvals approvals,
                            AuditLog audit, Throttle throttle) {
        this.api = api; this.settings = settings; this.evidence = evidence; this.policy = policy;
        this.approvals = approvals; this.audit = audit; this.throttle = throttle;
    }

    public void cancel() { RunState rs = current; if (rs != null) { rs.cancelled = true; approvals.cancelRun(rs.runId); } }

    /** Rough worst-case request count, for the pre-flight confirmation dialog. Real volume is usually lower
     *  (checks skip parameters that don't match their heuristics, and stop at the request budget). */
    public static int estimateRequests(List<HttpRequestResponse> endpoints, List<ScanCheck> checks) {
        int perEndpointActive = 0, perHostActive = 0;
        for (ScanCheck c : checks) {
            if (c.passiveOnly()) continue;
            if (c.perHost()) perHostActive += (c instanceof SensitiveFilesCheck ? 1 + Signatures.SENSITIVE_PATHS.size() : 2);
            else perEndpointActive += 3; // rough average: most endpoints have 1-3 matching parameters per check
        }
        Set<String> hosts = new HashSet<>();
        for (HttpRequestResponse rr : endpoints) hosts.add(rr.httpService().toString());
        return endpoints.size() * perEndpointActive + hosts.size() * perHostActive;
    }

    /** Blocking; call from a background thread. runId should be unique per scan (Engine provides one). */
    public void scan(int runId, List<HttpRequestResponse> endpoints, List<ScanCheck> checks, boolean allowNetwork, Listener listener) {
        RunState rs = new RunState(runId);
        rs.allowNetwork = allowNetwork;
        current = rs;
        PolicyGate gate = new PolicyGate(settings, policy, approvals, audit);
        BiConsumer<EventType, String> emit = (t, s) -> { try { listener.event(t, s); } catch (RuntimeException ignored) { } };
        emit.accept(EventType.START, endpoints.size() + " endpoint(s), " + checks.size() + " check(s)"
                + (allowNetwork ? "" : " (passive only)"));

        Set<String> hostsDone = new HashSet<>();
        int total = endpoints.size(), i = 0;
        for (HttpRequestResponse ep : endpoints) {
            i++;
            if (rs.cancelled) break;
            if (!api.scope().isInScope(ep.request().url())) { emit.accept(EventType.SKIP, ep.request().url() + " (out of scope)"); continue; }
            emit.accept(EventType.ENDPOINT, "[" + i + "/" + total + "] " + ep.request().method() + " " + ep.request().url());
            String host = ep.httpService().toString();
            boolean firstForHost = hostsDone.add(host);

            for (ScanCheck c : checks) {
                if (rs.cancelled) break;
                if (c.perHost() && !firstForHost) continue;
                if (!allowNetwork && !c.passiveOnly()) continue;
                CheckContext ctx = new CheckContext(api, settings, evidence, throttle, rs, gate, s -> emit.accept(EventType.CHECK, s));
                emit.accept(EventType.CHECK, c.name());
                List<ScanFinding> found;
                try {
                    found = c.run(ep, ctx);
                } catch (RuntimeException e) {
                    emit.accept(EventType.ERROR, c.name() + " failed: " + e);
                    continue;
                }
                for (ScanFinding f : found) {
                    emit.accept(EventType.FINDING, describeForLog(f));
                    try { listener.finding(f); } catch (RuntimeException ignored) { }
                }
            }
        }
        emit.accept(EventType.DONE, rs.cancelled ? "Cancelled. " + rs.requestsSent.get() + " request(s) sent."
                : "Scan complete. " + rs.requestsSent.get() + " request(s) sent.");
        current = null;
    }

    private static String describeForLog(ScanFinding f) {
        return "[" + f.severity().toUpperCase() + "] " + f.title() + "  (" + f.url() + ")";
    }
}
