package ollamaat.scan;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.List;

/**
 * One vulnerability class. Deterministic (regex/diff-based) detection, mirroring how real web vulnerability
 * scanners work, rather than asking the local model to drive every probe — far more reliable than relying on
 * small-model tool calling for hundreds of payload attempts, and it still works with no model configured at all.
 */
public interface ScanCheck {
    String id();
    String name();
    /** Short description shown in the Active Scan tab's check list. */
    String description();
    /** True if this check needs no outbound request (pure analysis of the baseline response). */
    boolean passiveOnly();
    /** True if this check should run at most once per distinct host rather than once per endpoint (e.g. OPTIONS, content discovery). */
    default boolean perHost() { return false; }
    /** Runs against one baseline request/response. May call ctx.send(...) for active checks. Never throws. */
    List<ScanFinding> run(HttpRequestResponse baseline, CheckContext ctx);
}
