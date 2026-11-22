package ollamaat;

import ollamaat.agent.AuditLog;
import ollamaat.agent.Memory;
import ollamaat.agent.Persist;
import ollamaat.scan.ActiveScanEngine;
import ollamaat.scan.ScanCheck;
import ollamaat.scan.Signatures;
import ollamaat.report.HtmlReport;
import ollamaat.report.ReportOptions;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.*;

/** Pure-logic tests for the active scanner and HTML report: detection signatures, estimate math, and report
 *  rendering/escaping. These do not require a live Burp or Ollama instance. */
public class ScanTest {
    static int passed, failed;

    static void check(boolean cond, String name) {
        if (cond) { passed++; System.out.println("  ok   " + name); }
        else { failed++; System.out.println("  FAIL " + name); }
    }

    @SuppressWarnings("unchecked")
    static <T> T stub(Class<T> c, Map<String, Object> methodReturns) {
        InvocationHandler h = (proxy, m, args) -> {
            String key = m.getName();
            if (methodReturns.containsKey(key)) return methodReturns.get(key);
            Class<?> r = m.getReturnType();
            if (r == boolean.class) return false;
            if (r.isPrimitive()) return r == void.class ? null : 0;
            if (r == String.class) return "";
            if (r == List.class) return List.of();
            return null;
        };
        return (T) Proxy.newProxyInstance(c.getClassLoader(), new Class<?>[]{c}, h);
    }

    static HttpRequestResponse endpoint(String host, String url) {
        HttpService svc = stub(HttpService.class, Map.of("host", host, "toString", host));
        HttpRequest req = stub(HttpRequest.class, Map.of("url", url, "method", "GET", "httpService", svc));
        return stub(HttpRequestResponse.class, Map.of("request", req, "httpService", svc, "hasResponse", false));
    }

    public static void main(String[] args) {
        System.out.println("Signatures: SQL error fingerprints");
        for (String s : List.of("You have an error in your SQL syntax", "unclosed quotation mark after the character string",
                "PG::SyntaxError: ERROR", "SQLite3::SQLException", "ORA-00933: SQL command not properly ended",
                "System.Data.SqlClient.SqlException", "PDOException: SQLSTATE[42000]",
                // broadened coverage: MSSQL (testfire/AltoroMutual), MySQL, PostgreSQL, DB2
                "Incorrect syntax near ')'", "Microsoft SQL Server", "[SQL Server]Unclosed quotation mark",
                "Conversion failed when converting the varchar value", "Warning: mysql_query()", "valid MySQL result",
                "syntax error at or near \"'\"", "unterminated quoted string at or near", "DB2 SQL error: SQLCODE"))
            check(Signatures.SQL_ERROR.matcher(s).find(), "matches: " + s.substring(0, Math.min(34, s.length())));
        check(!Signatures.SQL_ERROR.matcher("Welcome to the site, here is your search result").find(), "no false positive on benign text");
        check(!Signatures.SQL_ERROR.matcher("Please enter a valid email address").find(), "no false positive on 'valid' in benign text");

        System.out.println("Signatures: parameter-name heuristics");
        for (String n : List.of("file", "filename", "template_path", "doc", "lang")) check(Signatures.FILE_PARAM.matcher(n).find(), "file-param: " + n);
        check(!Signatures.FILE_PARAM.matcher("username").find(), "file-param rejects 'username'");
        check(!Signatures.FILE_PARAM.matcher("profile").find(), "file-param rejects 'profile' (substring false positive)");
        for (String n : List.of("redirect_url", "next", "returnurl", "callback")) check(Signatures.REDIRECT_PARAM.matcher(n).find(), "redirect-param: " + n);
        check(!Signatures.REDIRECT_PARAM.matcher("password").find(), "redirect-param rejects 'password'");
        for (String n : List.of("cmd", "host", "ping", "lookup")) check(Signatures.COMMAND_PARAM.matcher(n).find(), "command-param: " + n);

        System.out.println("Signatures: disclosure patterns");
        check(Signatures.DIRECTORY_LISTING.matcher("<title>Index of /uploads</title>").find(), "directory listing detected");
        check(Signatures.SERVER_ERROR_SIGNATURE.matcher("Traceback (most recent call last): File \"app.py\"").find(), "stack trace detected");
        check(!Signatures.SERVER_ERROR_SIGNATURE.matcher("<h1>404 Not Found</h1>").find(), "plain 404 page not flagged as a stack trace");

        System.out.println("Policy.parseLenient: probe URLs with payload characters are still parseable (not blocked)");
        for (String u : List.of(
                "https://demo.test/search.jsp?query=test<oatabc123>",      // reflected-XSS marker
                "https://demo.test/search.jsp?query=test' AND '1'='1",     // boolean-SQLi condition (has spaces)
                "https://demo.test/page?q=a\"b{c}|d")) {                    // other URI-illegal characters
            java.net.URI parsed = ollamaat.agent.Policy.parseLenient(u);
            check(parsed != null && "demo.test".equals(parsed.getHost()),
                    "parseLenient keeps host for probe URL: " + u.substring(0, Math.min(46, u.length())));
        }
        check(ollamaat.agent.Policy.parseLenient("https://ok.test/clean?x=1") != null, "parseLenient still parses a clean URL");

        System.out.println("ActiveScanEngine: check catalogue");
        List<ScanCheck> all = ActiveScanEngine.allChecks();
        Set<String> ids = new HashSet<>();
        for (ScanCheck c : all) ids.add(c.id());
        check(ids.size() == all.size(), "no duplicate check ids");
        for (String id : List.of("reflected-xss", "sql-injection", "path-traversal", "open-redirect", "command-injection",
                "cors-misconfig", "http-methods", "sensitive-files", "passive-analysis"))
            check(ids.contains(id), "catalogue includes " + id);
        check(all.stream().filter(ScanCheck::passiveOnly).count() == 1, "exactly one passive-only check");
        check(all.stream().filter(ScanCheck::perHost).count() == 2, "exactly two per-host checks (methods, sensitive-files)");

        System.out.println("ActiveScanEngine: request estimate");
        List<HttpRequestResponse> eps = List.of(endpoint("a.test", "https://a.test/1"), endpoint("a.test", "https://a.test/2"), endpoint("b.test", "https://b.test/1"));
        ScanCheck perEndpointCheck = all.stream().filter(c -> !c.passiveOnly() && !c.perHost()).findFirst().orElseThrow();
        ScanCheck perHostCheck = all.stream().filter(ScanCheck::perHost).findFirst().orElseThrow();
        ScanCheck passive = all.stream().filter(ScanCheck::passiveOnly).findFirst().orElseThrow();
        int est1 = ActiveScanEngine.estimateRequests(eps, List.of(perEndpointCheck));
        int est2 = ActiveScanEngine.estimateRequests(eps, List.of(perHostCheck));
        int est3 = ActiveScanEngine.estimateRequests(eps, List.of(passive));
        check(est1 == 3 * 3, "per-endpoint check scales with endpoint count: " + est1);
        check(est2 > 0 && est2 < est1, "per-host check costs less than per-endpoint across 2 hosts: " + est2);
        check(est3 == 0, "passive-only check contributes zero to the estimate");
        check(ActiveScanEngine.estimateRequests(List.of(), all) == 0, "no endpoints -> zero estimate");

        System.out.println("HtmlReport: structure, sorting and escaping");
        Memory.Finding high = new Memory.Finding(1000, 1, "SQLi in id param", "HIGH", "FIRM", "https://app.test/a?id=1",
                "detail text", "use prepared statements", List.of("p1", "a2"), true);
        Memory.Finding xssWithPayload = new Memory.Finding(2000, 1, "<script>alert(1)</script> reflected", "HIGH", "TENTATIVE",
                "https://app.test/b", "payload was <img src=x onerror=alert(1)> in the body", "", List.of("a3"), false);
        Memory.Finding info = new Memory.Finding(500, 1, "Server banner disclosed", "INFORMATION", "FIRM", "https://app.test/c", "nginx/1.2", "", List.of(), false);
        Memory.Finding low = new Memory.Finding(1500, 1, "Missing CSP", "LOW", "FIRM", "https://app.test/d", "no csp", "add csp", List.of(), false);

        ReportOptions optAll = new ReportOptions();
        optAll.includeAuditLog = true;
        AuditLog audit = new AuditLog(Persist.memory());
        audit.add(1, "active_scan", "probe", "ALLOWED", "policy", "200 in 40ms");
        String html = HtmlReport.generate(optAll, List.of(low, info, xssWithPayload, high), audit, new Settings(Settings.memoryStore()), null);
        check(html.contains("<!DOCTYPE html>") && html.contains("</html>"), "produces a full HTML document");
        check(html.contains(optAll.title), "includes the report title");
        check(!html.contains("<script>alert(1)</script>") && html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
                "finding title is HTML-escaped (no stored XSS from attacker-controlled finding text)");
        check(!html.contains("<img src=x onerror=alert(1)>") && html.contains("&lt;img src=x onerror=alert(1)&gt;"),
                "finding detail is HTML-escaped");
        int posHigh1 = html.indexOf("SQLi in id param");
        int posHigh2 = html.indexOf("script&gt;alert");
        int posLow = html.indexOf("Missing CSP");
        int posInfo = html.indexOf("Server banner disclosed");
        check(posHigh1 >= 0 && posHigh2 >= 0 && posLow > posHigh2 && posInfo > posLow, "findings are ordered by severity (high before low before info)");
        check(html.contains("p1") && html.contains("a2") && html.contains("a3"), "evidence refs are rendered");
        check(html.contains("Audit log") && html.contains("active_scan"), "audit log appendix included when requested");

        ReportOptions optNoInfo = new ReportOptions();
        optNoInfo.includeInfo = false;
        String htmlNoInfo = HtmlReport.generate(optNoInfo, List.of(info, high), null, new Settings(Settings.memoryStore()), null);
        check(!htmlNoInfo.contains("Server banner disclosed"), "info findings excluded when includeInfo=false");
        check(!htmlNoInfo.contains("Audit log"), "audit log omitted by default");

        ReportOptions optNoEvidence = new ReportOptions();
        optNoEvidence.includeEvidence = false;
        String htmlNoEv = HtmlReport.generate(optNoEvidence, List.of(high), null, new Settings(Settings.memoryStore()), null);
        check(!htmlNoEv.contains(">p1<"), "evidence refs omitted when includeEvidence=false");

        String emptyHtml = HtmlReport.generate(new ReportOptions(), List.of(), null, new Settings(Settings.memoryStore()), null);
        check(emptyHtml.contains("No findings recorded"), "empty findings list handled gracefully");

        System.out.println("\n" + passed + " passed, " + failed + " failed");
        System.exit(failed == 0 ? 0 : 1);
    }
}
