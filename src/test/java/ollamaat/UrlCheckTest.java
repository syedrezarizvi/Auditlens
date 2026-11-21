package ollamaat;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.HttpService;
import ollamaat.report.RemediationKb;
import ollamaat.scan.ScanFinding;
import ollamaat.scan.checks.PassiveAnalysisCheck;

import java.util.*;

/** The deterministic passive check must flag sensitive data / object identifiers carried in the URL query string,
 *  even when all response security headers are present (so the tool is not silent on hardened-but-imperfect APIs). */
public final class UrlCheckTest {
    static int n = 0;
    public static void main(String[] a) {
        int fails = 0;

        // Hardened JSON response (all headers set) but URL carries a sequential consumer id + an auth token.
        List<ScanFinding> f1 = runOn("https://api.test/api/consumer/billing?kno=210731025144&date=2026-11-01");
        fails += has(f1, "Object identifier in URL", "flags object identifier / IDOR from kno=");
        List<ScanFinding> f2 = runOn("https://api.test/api/auth/session?token=abc123&user=5");
        fails += has(f2, "Credentials or token in URL", "flags token in URL");
        List<ScanFinding> f3 = runOn("https://api.test/api/user?mobile=9876543210");
        fails += has(f3, "(PII) in URL", "flags PII in URL");
        List<ScanFinding> jwt = runWithBody("https://api.test/t", "{\"token\":\"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.abcdEFGHijkl\"}");
        fails += has(jwt, "Secret or token disclosed in response body", "flags JWT in response body");
        List<ScanFinding> email = runWithBody("https://api.test/t", "{\"email\":\"user@example.com\"}");
        fails += has(email, "(PII) in response body", "flags email PII in response body");
        List<ScanFinding> cors = runWithCors("https://api.test/t", "*", true);
        fails += has(cors, "Permissive CORS", "flags wildcard CORS with credentials");

        List<ScanFinding> clean = runOn("https://api.test/api/health");
        fails += check(clean.stream().noneMatch(x -> x.title().contains("URL query string")), "no URL finding when there is no query");

        // KB routing for the new titles.
        fails += check(RemediationKb.lookup("Object identifier in URL - possible IDOR and sensitive data in URL", "").category().contains("IDOR"),
                "IDOR title routes to IDOR remediation");
        fails += check(RemediationKb.lookup("Credentials or token in URL query string", "").category().contains("Sensitive Data in URL"),
                "token-in-URL routes to Sensitive Data in URL");
        var idorRefs = RemediationKb.lookup("Object identifier in URL - possible IDOR", "").refs();
        fails += check(idorRefs.stream().anyMatch(r -> r.url().contains("owasp.org")), "IDOR remediation has OWASP reference links");

        System.out.println();
        System.out.println((n - fails) + " passed, " + fails + " failed");
        if (fails > 0) System.exit(1);
    }

    static List<ScanFinding> runWithBody(String url, String body) { return build(url, body, null, false); }
    static List<ScanFinding> runWithCors(String url, String acao, boolean creds) { return build(url, "{}", acao, creds); }
    static List<ScanFinding> runOn(String url) { return build(url, "{\"ok\":true}", null, false); }

    static List<ScanFinding> build(String url, String body, String acao, boolean creds) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("Content-Security-Policy", "default-src 'self'");
        headers.put("X-Frame-Options", "DENY");
        headers.put("X-Content-Type-Options", "nosniff");
        headers.put("Strict-Transport-Security", "max-age=31536000");
        headers.put("Referrer-Policy", "no-referrer");
        headers.put("Permissions-Policy", "geolocation=()");
        if (acao != null) { headers.put("Access-Control-Allow-Origin", acao); if (creds) headers.put("Access-Control-Allow-Credentials", "true"); }
        List<HttpHeader> hlist = new ArrayList<>();
        for (var e : headers.entrySet()) hlist.add(ScanStub.header(e.getKey(), e.getValue()));

        Map<String, Object> ro = new HashMap<>();
        ro.put("statusCode", (short) 200);
        ro.put("bodyToString", body);
        ro.put("headers", hlist);
        HttpResponse resp = ScanStub.stub(HttpResponse.class, ro, headers);

        HttpService svc = ScanStub.stub(HttpService.class, Map.of("host", "api.test", "secure", true), Map.of());
        HttpRequest req = ScanStub.stub(HttpRequest.class, Map.of("url", url, "method", "GET", "httpService", svc), Map.of());
        HttpRequestResponse rr = ScanStub.stub(HttpRequestResponse.class,
                Map.of("request", req, "response", resp, "hasResponse", true), Map.of());
        return new PassiveAnalysisCheck().run(rr, null);
    }

    static int has(List<ScanFinding> fs, String titleContains, String what) {
        return check(fs.stream().anyMatch(x -> x.title().contains(titleContains)), what);
    }
    static int check(boolean ok, String what) { n++; System.out.println((ok ? "  ok   " : "  FAIL ") + what); return ok ? 0 : 1; }
}
