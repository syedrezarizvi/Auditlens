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

/** SQL injection signal detector. Two complementary, non-destructive signals per parameter:
 *  <ol>
 *    <li><b>Error-based</b> — a single unescaped-quote probe; a database error signature (firm) or a clean
 *        2xx-&gt;5xx flip with a very different body (tentative).</li>
 *    <li><b>Boolean-based</b> — if the quote probe did not fire, a logically-true (<code>' AND '1'='1</code>) and
 *        logically-false (<code>' AND '1'='2</code>) condition are sent; when the true page matches the original
 *        but the false page differs markedly, that asymmetry is the classic blind-SQLi signal (tentative).</li>
 *  </ol>
 *  Both conditions only ever <em>narrow</em> a query (AND), never broaden or modify data, and data extraction /
 *  time-based confirmation are deliberately left to the sql-injection-testing skill for agent-guided testing. */
public final class SqlInjectionCheck implements ScanCheck {
    public String id() { return "sql-injection"; }
    public String name() { return "SQL injection (error- and boolean-based signal)"; }
    public String description() { return "Per parameter: an unescaped-quote probe for DB errors, then a true/false condition pair to catch blind (error-free) injection."; }
    public boolean passiveOnly() { return false; }

    public List<ScanFinding> run(HttpRequestResponse baseline, CheckContext ctx) {
        List<ScanFinding> out = new ArrayList<>();
        if (!baseline.hasResponse()) return out;
        int baseStatus = baseline.response().statusCode();
        String baseBody = baseline.response().bodyToString();

        for (ParsedHttpParameter p : ParamUtil.mutable(baseline)) {
            if (ctx.cancelled()) break;

            // ---- Signal 1: error-based (single quote) ----
            HttpRequest req = ParamUtil.withValue(baseline, p, p.value() + "'");
            var r = ctx.send(req, "SQLi quote probe on '" + p.name() + "' at " + baseline.request().url());
            if (!r.ok()) continue;
            String body = r.rr().response().bodyToString();
            int status = r.rr().response().statusCode();
            boolean errorMatch = Signatures.SQL_ERROR.matcher(body).find() && !Signatures.SQL_ERROR.matcher(baseBody).find();
            boolean statusFlip = baseStatus < 500 && status >= 500 && Fmt.similarity(baseBody, body) < 0.5;
            if (errorMatch || statusFlip) {
                String ref = ctx.evidence.addAgent(r.rr());
                out.add(ScanFinding.of(id(), "Possible SQL injection via '" + p.name() + "'", errorMatch ? "high" : "medium",
                        errorMatch ? "firm" : "tentative", baseline.request().url(),
                        "Appending an unescaped `'` to parameter '" + p.name() + "' "
                                + (errorMatch ? "produced a database error message in the response, indicating the input reaches a SQL query unsanitised."
                                              : "changed the response from HTTP " + baseStatus + " to " + status + " with a substantially different body, "
                                                + "which is consistent with an unhandled query error but was not confirmed by a recognisable DB error string.")
                                + " Only the presence of a signal was confirmed here; extraction and boolean/time-based confirmation were deliberately not attempted.",
                        PREPARED_STMT_REMEDIATION, List.of(ref)));
                continue; // one signal per parameter is enough
            }

            // ---- Signal 2: boolean-based (true/false asymmetry), only if the quote probe was inconclusive ----
            if (ctx.cancelled()) break;
            var rt = ctx.send(ParamUtil.withValue(baseline, p, p.value() + "' AND '1'='1"),
                    "SQLi boolean-true probe on '" + p.name() + "' at " + baseline.request().url());
            if (!rt.ok()) continue;
            if (ctx.cancelled()) break;
            var rf = ctx.send(ParamUtil.withValue(baseline, p, p.value() + "' AND '1'='2"),
                    "SQLi boolean-false probe on '" + p.name() + "' at " + baseline.request().url());
            if (!rf.ok()) continue;

            String tBody = rt.rr().response().bodyToString();
            String fBody = rf.rr().response().bodyToString();
            double simTrueBase = Fmt.similarity(baseBody, tBody);   // true condition should look like the original
            double simFalseBase = Fmt.similarity(baseBody, fBody);  // false condition should differ
            // Classic blind-SQLi asymmetry: TRUE preserves the page, FALSE changes it clearly. Requiring a real gap
            // (and that TRUE and FALSE themselves differ) rejects pages that merely vary randomly between requests.
            boolean booleanSignal = simTrueBase >= 0.93 && simFalseBase <= 0.85
                    && (simTrueBase - simFalseBase) >= 0.12 && Fmt.similarity(tBody, fBody) <= 0.90;
            if (booleanSignal) {
                String ref = ctx.evidence.addAgent(rf.rr());
                out.add(ScanFinding.of(id(), "Possible blind SQL injection via '" + p.name() + "'", "medium", "tentative",
                        baseline.request().url(),
                        "Parameter '" + p.name() + "' responds to a true/false SQL condition like a live query. Appending "
                                + "`' AND '1'='1` returned a page matching the original, while `' AND '1'='2` returned a clearly "
                                + "different page — the boolean-based (blind) SQL injection signature. No database error was needed. "
                                + "Confirm manually (e.g. repeat the pair, or use the sql-injection-testing skill) before relying on it, "
                                + "as content that varies naturally between requests can occasionally mimic this.",
                        PREPARED_STMT_REMEDIATION, List.of(ref)));
            }
        }
        return out;
    }

    private static final String PREPARED_STMT_REMEDIATION =
            "Use parameterized queries / prepared statements everywhere user input reaches SQL; never concatenate input into query strings; "
                    + "return generic error pages instead of raw database errors.";
}
