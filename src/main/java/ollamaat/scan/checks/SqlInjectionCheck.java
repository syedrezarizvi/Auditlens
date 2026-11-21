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

/** SQL injection signal detector: one unescaped-quote probe per parameter. Error-pattern match = firm; a clean
 *  200-&gt;500 flip with a very different body = tentative. Deliberately does not attempt boolean/time-based
 *  confirmation or data extraction here (see the sql-injection-testing skill for agent-guided deeper testing). */
public final class SqlInjectionCheck implements ScanCheck {
    public String id() { return "sql-injection"; }
    public String name() { return "SQL injection (error-based signal)"; }
    public String description() { return "Appends a single unescaped quote to each parameter and looks for database error signatures or a status flip."; }
    public boolean passiveOnly() { return false; }

    public List<ScanFinding> run(HttpRequestResponse baseline, CheckContext ctx) {
        List<ScanFinding> out = new ArrayList<>();
        if (!baseline.hasResponse()) return out;
        int baseStatus = baseline.response().statusCode();
        String baseBody = baseline.response().bodyToString();

        for (ParsedHttpParameter p : ParamUtil.mutable(baseline)) {
            if (ctx.cancelled()) break;
            HttpRequest req = ParamUtil.withValue(baseline, p, p.value() + "'");
            var r = ctx.send(req, "SQLi probe on '" + p.name() + "' at " + baseline.request().url());
            if (!r.ok()) continue;
            String body = r.rr().response().bodyToString();
            int status = r.rr().response().statusCode();
            boolean errorMatch = Signatures.SQL_ERROR.matcher(body).find() && !Signatures.SQL_ERROR.matcher(baseBody).find();
            boolean statusFlip = baseStatus < 500 && status >= 500 && Fmt.similarity(baseBody, body) < 0.5;
            if (!errorMatch && !statusFlip) continue;
            String ref = ctx.evidence.addAgent(r.rr());
            out.add(ScanFinding.of(id(), "Possible SQL injection via '" + p.name() + "'", errorMatch ? "high" : "medium",
                    errorMatch ? "firm" : "tentative", baseline.request().url(),
                    "Appending an unescaped `'` to parameter '" + p.name() + "' "
                            + (errorMatch ? "produced a database error message in the response, indicating the input reaches a SQL query unsanitised."
                                          : "changed the response from HTTP " + baseStatus + " to " + status + " with a substantially different body, "
                                            + "which is consistent with an unhandled query error but was not confirmed by a recognisable DB error string.")
                            + " Only the presence of a signal was confirmed here; extraction and boolean/time-based confirmation were deliberately not attempted.",
                    "Use parameterized queries / prepared statements everywhere user input reaches SQL; never concatenate input into query strings; "
                            + "return generic error pages instead of raw database errors.",
                    List.of(ref)));
        }
        return out;
    }
}
