package ollamaat;

import ollamaat.report.RemediationKb;
import ollamaat.triage.Triage;

import java.util.List;

/** Deterministic triage rules, quote grounding, the two-pass pipeline (fake model), and Next.js/React KB routing. */
public final class TriageRulesTest {
    static int n = 0;

    public static void main(String[] a) throws Exception {
        int fails = 0;
        List<String> noReq = List.of();

        // Stage 1: rules decide from facts in the captured messages.
        Triage.Verdict v = Triage.ruleVerdict("Missing Content-Security-Policy", noReq,
                List.of("Content-Security-Policy: default-src 'self'"), "");
        fails += check(v != null && v.label().equals(Triage.FP) && v.method().equals("rule"), "CSP present in capture is a rule false positive");
        fails += check(Triage.ruleVerdict("Missing Content-Security-Policy", noReq, List.of("Server: nginx"), "") == null,
                "CSP absent falls through to the model (no rule verdict)");

        Triage.Verdict cookie = Triage.ruleVerdict("Cookie 'sid' missing Secure/HttpOnly/SameSite", noReq,
                List.of("Set-Cookie: sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax"), "");
        fails += check(cookie != null && cookie.label().equals(Triage.FP), "cookie carrying every reported flag is a false positive");
        fails += check(Triage.ruleVerdict("Cookie 'sid' missing Secure/HttpOnly", noReq,
                List.of("Set-Cookie: sid=abc; Path=/"), "") == null, "cookie missing its flags is not overturned by the rule");

        Triage.Verdict cors = Triage.ruleVerdict("Permissive CORS policy (Access-Control-Allow-Origin: *)", noReq,
                List.of("Access-Control-Allow-Origin: https://a.example"), "");
        fails += check(cors != null && cors.label().equals(Triage.FP), "CORS not wildcard in capture is a false positive");
        fails += check(Triage.ruleVerdict("Permissive CORS policy (Access-Control-Allow-Origin: *)", noReq,
                List.of("Access-Control-Allow-Origin: *"), "") == null, "CORS wildcard in capture goes to the model");

        Triage.Verdict nd = Triage.ruleVerdict("Secret-like value in Next.js __NEXT_DATA__ payload", noReq, noReq,
                "<script id=\"__NEXT_DATA__\">{\"props\":{\"title\":\"hello\"}}</script>");
        fails += check(nd != null && nd.label().equals(Triage.NR), "__NEXT_DATA__ finding with no secret in capture needs review, not a verdict");
        fails += check(Triage.ruleVerdict("Secret-like value in Next.js __NEXT_DATA__ payload", noReq, noReq,
                "<script id=\"__NEXT_DATA__\">{\"props\":{\"apiToken\":\"abcdef123456\"}}</script>") == null,
                "__NEXT_DATA__ finding with a secret present goes to the model");

        Triage.Verdict mw = Triage.ruleVerdict("Request carries x-middleware-subrequest header (Next.js middleware bypass pattern)",
                List.of("Host: app.example"), noReq, "");
        fails += check(mw != null && mw.label().equals(Triage.NR), "middleware header finding without the header in the request needs review");

        Triage.Verdict sm = Triage.ruleVerdict("JavaScript source map reference exposed (possible source code disclosure)", noReq, noReq,
                "console.log(1)");
        fails += check(sm != null && sm.label().equals(Triage.NR), "source map finding without a sourceMappingURL in the script needs review");

        // Stage 2: quote grounding. A quote must be literally present in the evidence the model was shown.
        fails += check(Triage.quoteFound("Reflected   VALUE", "...the reflected value came back..."),
                "quote matches despite case and whitespace differences");
        fails += check(!Triage.quoteFound("not present anywhere", "the reflected value came back"),
                "a quote missing from the evidence is rejected");
        fails += check(!Triage.quoteFound("hi", "hi there"), "very short quotes are rejected as too weak to ground a verdict");

        // Parsing a model reply.
        Triage.Llm p = Triage.parse("{\"verdict\":\"false positive\",\"confidence\":\"High\",\"evidence_quote\":\"Content-Type: application/json\",\"rationale\":\"JSON only\"}");
        fails += check(p != null && p.label().equals(Triage.FP) && p.confidence().equals("high") && p.quote().startsWith("Content-Type"),
                "model reply parses verdict, confidence and quote");
        fails += check(Triage.parse("I am not sure") == null, "non-JSON reply yields no verdict");

        // Stages 2-4 with a fake model.
        Triage.Input in = new Triage.Input("Reflected XSS", "HIGH", "https://t.example/s", "input reflected",
                noReq, noReq, "", "RESPONSE:\nContent-Type: text/html\n<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>\n");

        String tpReply = "{\"verdict\":\"true positive\",\"confidence\":\"high\",\"evidence_quote\":\"<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>\",\"rationale\":\"x\"}";
        String fpReply = "{\"verdict\":\"false positive\",\"confidence\":\"high\",\"evidence_quote\":\"&lt;script&gt;\",\"rationale\":\"encoded\"}";

        Triage.Verdict agree = Triage.analyze(in, prompt -> prompt.contains("Argue the other side") ? tpReply : tpReply);
        fails += check(agree.label().equals(Triage.TP) && agree.method().startsWith("AI two-pass"),
                "two agreeing passes keep a definite verdict");

        Triage.Verdict disagree = Triage.analyze(in, prompt -> prompt.contains("Argue the other side") ? fpReply : tpReply);
        fails += check(disagree.label().equals(Triage.NR), "passes that disagree become NEEDS REVIEW");

        Triage.Verdict ungrounded = Triage.analyze(in, prompt -> "{\"verdict\":\"true positive\",\"confidence\":\"high\",\"evidence_quote\":\"invented text not in evidence\",\"rationale\":\"x\"}");
        fails += check(ungrounded.label().equals(Triage.NR) && ungrounded.rationale().contains("not found"),
                "a verdict with an ungrounded quote is withheld");

        Triage.Verdict lowConf = Triage.analyze(in, prompt -> "{\"verdict\":\"false positive\",\"confidence\":\"low\",\"evidence_quote\":\"Content-Type: text/html\",\"rationale\":\"x\"}");
        fails += check(lowConf.label().equals(Triage.NR), "low model confidence becomes NEEDS REVIEW");

        // Value windows: the part of the response that echoes a request parameter is shown to the model.
        String body = "x".repeat(900) + "<p>abcdef</p>" + "y".repeat(900);
        String win = Engine.valueWindows(body, "GET /search?q=abcdef HTTP/1.1");
        fails += check(win.contains("abcdef") && win.contains("WINDOW"), "reflected parameter value is windowed out of a long body");

        // Knowledge base routing for the Next.js / React rules, and no regressions on the generic XSS rule.
        fails += check(RemediationKb.lookup("Next.js Middleware Authorization Bypass", "").category().contains("Middleware"),
                "middleware bypass title routes to the middleware entry");
        fails += check(RemediationKb.lookup("Secret-like value in Next.js __NEXT_DATA__ payload", "").category().contains("Data Exposure"),
                "__NEXT_DATA__ title routes to the data exposure entry");
        fails += check(RemediationKb.lookup("React XSS via dangerouslySetInnerHTML", "").category().contains("React XSS"),
                "React sink title routes to the React XSS entry");
        fails += check(RemediationKb.lookup("Reflected XSS", "").category().startsWith("Cross-Site Scripting"),
                "generic XSS title still routes to the XSS entry");
        fails += check(RemediationKb.lookup("Next.js Image Optimizer SSRF", "").refs().size() >= 2,
                "Next.js entries carry reference links");

        // Duplicate merge: same issue name (with or without the [AI] prefix) across URLs becomes one entry, highest severity wins.
        List<ollamaat.agent.Memory.Finding> dups = List.of(
                new ollamaat.agent.Memory.Finding(1L, 0, "[AI] Missing CSP", "MEDIUM", "FIRM", "https://a.example/x", "d", "", List.of(), false),
                new ollamaat.agent.Memory.Finding(2L, 0, "missing  csp", "HIGH", "FIRM", "https://b.example/y", "d", "", List.of(), true));
        List<ollamaat.report.FindingGroup> merged = ollamaat.report.FindingGroup.of(dups, true);
        fails += check(merged.size() == 1 && merged.get(0).urls.size() == 2 && merged.get(0).severity.equals("HIGH"),
                "duplicate findings merge into one entry with all URLs and the highest severity");

        // Analyst-style prompting: the reviewer is asked to reason in steps and to name the check that would settle it
        String pr = Triage.prompt(new Triage.Input("Reflected XSS", "HIGH", "https://a.example/s", "d", List.of(), List.of(), "", "EVIDENCE TEXT"), false, null);
        fails += check(pr.contains("Work like a careful human reviewer") && pr.contains("Name the one check"), "prompt asks for analyst steps");
        fails += check(pr.contains("single check that would confirm or refute"), "rationale asks for the confirming check");
        fails += check(Triage.checklist("Cookie without HttpOnly flag").contains("session or authentication"), "cookie findings get a cookie check");
        fails += check(Triage.checklist("Missing Security Headers").contains("static asset"), "header findings consider whether the page needs framing protection");
        fails += check(Triage.checklist("Server version disclosure").contains("public version string"), "version findings allow public values");
        fails += check(Triage.checklist("JavaScript Source Map Exposure").contains("harmless"), "source map findings are judged on content");

        System.out.println();
        System.out.println((n - fails) + " passed, " + fails + " failed");
        if (fails > 0) System.exit(1);
    }

    static int check(boolean ok, String what) { n++; System.out.println((ok ? "  ok   " : "  FAIL ") + what); return ok ? 0 : 1; }
}
