package ollamaat.scan.checks;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import ollamaat.scan.CheckContext;
import ollamaat.scan.ScanCheck;
import ollamaat.scan.ScanFinding;
import ollamaat.scan.Signatures;
import ollamaat.tools.Fmt;
import ollamaat.triage.Triage;
import ollamaat.util.Text;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Sends no requests: reviews the already-captured baseline response for missing security headers, weak cookie
 *  flags, verbose error/stack-trace disclosure and directory listings. */
public final class PassiveAnalysisCheck implements ScanCheck {
    public String id() { return "passive-analysis"; }
    public String name() { return "Headers, cookies & information disclosure"; }
    public String description() { return "Passive only: missing security headers, insecure cookie flags, stack traces/verbose errors, directory listings."; }
    public boolean passiveOnly() { return true; }

    public List<ScanFinding> run(HttpRequestResponse baseline, CheckContext ctx) {
        List<ScanFinding> out = new ArrayList<>();
        if (!baseline.hasResponse()) return out;
        var resp = baseline.response();
        String url = baseline.request().url();
        boolean https = baseline.request().httpService().secure();
        String body = resp.bodyToString();
        String ct = Fmt.contentType(resp);
        boolean html = ct.isEmpty() || ct.contains("html");

        if (html) {
            if (resp.headerValue("Content-Security-Policy") == null)
                out.add(low(url, "Missing Content-Security-Policy", "No Content-Security-Policy header was found on this HTML response, which "
                        + "removes an important defence-in-depth layer against XSS and data injection.",
                        "Add a restrictive CSP (start with a report-only policy if needed, then enforce it)."));
            if (resp.headerValue("X-Frame-Options") == null && !hasFrameAncestors(resp.headerValue("Content-Security-Policy")))
                out.add(low(url, "Missing clickjacking protection (X-Frame-Options / frame-ancestors)",
                        "Neither X-Frame-Options nor a CSP frame-ancestors directive was found; this page could be framed by another site.",
                        "Add 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive."));
        }
        if (resp.headerValue("X-Content-Type-Options") == null)
            out.add(low(url, "Missing X-Content-Type-Options", "The response does not send 'X-Content-Type-Options: nosniff', allowing some "
                    + "browsers to MIME-sniff the content type.", "Add 'X-Content-Type-Options: nosniff' to all responses."));
        if (https && resp.headerValue("Strict-Transport-Security") == null)
            out.add(low(url, "Missing Strict-Transport-Security", "This HTTPS response has no HSTS header, so a user's first visit (or any "
                    + "downgrade) is not protected against SSL-stripping.", "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."));

        for (HttpHeader h : resp.headers()) {
            if (!h.name().equalsIgnoreCase("Set-Cookie")) continue;
            String raw = h.value(), lower = raw.toLowerCase();
            String cookieName = raw.contains("=") ? raw.substring(0, raw.indexOf('=')).trim() : raw.trim();
            List<String> missing = new ArrayList<>();
            if (https && !lower.contains("secure")) missing.add("Secure");
            if (!lower.contains("httponly")) missing.add("HttpOnly");
            if (!lower.contains("samesite")) missing.add("SameSite");
            if (!missing.isEmpty())
                out.add(med(url, "Cookie '" + cookieName + "' missing " + String.join("/", missing),
                        "Cookie '" + cookieName + "' is set without: " + String.join(", ", missing) + ". Missing HttpOnly allows JavaScript/XSS to "
                                + "read it; missing Secure allows it over plain HTTP; missing SameSite weakens CSRF defences.",
                        "Set Secure, HttpOnly and an explicit SameSite attribute on all session/auth cookies."));
        }

        if (resp.statusCode() >= 500 && Signatures.SERVER_ERROR_SIGNATURE.matcher(body).find())
            out.add(med(url, "Verbose error / stack trace disclosed", "A server error response includes what looks like a stack trace or "
                    + "framework debug page, which can reveal internal paths, library versions and logic.",
                    "Return generic error pages to clients; log details server-side only; disable debug/dev mode in production."));
        if (Signatures.DIRECTORY_LISTING.matcher(body).find())
            out.add(med(url, "Directory listing enabled", "The response looks like an auto-generated directory index, which can expose files "
                    + "not meant to be browsable.", "Disable directory listing on the web server/static file handler."));

        out.addAll(sensitiveUrlFindings(url));
        out.addAll(responseBodyFindings(url, body));
        out.addAll(corsFindings(url, resp));
        out.addAll(hardeningHeaderFindings(url, resp, html));
        out.addAll(nextReactFindings(url, baseline.request(), resp, body));
        out.addAll(captchaFindings(url, body, html));

        String server = resp.headerValue("Server"), powered = resp.headerValue("X-Powered-By");
        if ((server != null && server.matches(".*[0-9]+\\.[0-9]+.*")) || powered != null)
            out.add(ScanFinding.of(id(), "Server version/technology banner disclosed", "info", "firm", url,
                    "Response headers disclose implementation details: " + Text.oneLine((server == null ? "" : "Server: " + server + " ") +
                            (powered == null ? "" : "X-Powered-By: " + powered), 160) + ". This helps an attacker target known vulnerabilities for that version.",
                    "Suppress or genericize version-revealing headers (Server, X-Powered-By) at the web server/framework level.", List.of()));
        return out;
    }

    // Credentials/tokens, PII, and object identifiers carried in the URL query string. Query strings are logged by
    // servers/proxies and leaked via the Referer header, and sequential object ids in the URL are a classic IDOR signal.
    private static final Pattern SECRET_PARAM = Pattern.compile("(?i)^(pass(word|wd)?|pwd|otp|pin|token|access[_-]?token|id[_-]?token|refresh[_-]?token|auth|authorization|session[_-]?id|sid|jwt|api[_-]?key|apikey|secret|client[_-]?secret|signature)$");
    private static final Pattern PII_PARAM = Pattern.compile("(?i)^(aadha?ar|pan|ssn|dob|date[_-]?of[_-]?birth|mobile|msisdn|phone|email|e[_-]?mail|passport|voterid|uidai)$");
    private static final Pattern ID_PARAM = Pattern.compile("(?i)^(id|uid|user[_-]?id|userid|account(no)?|acct(no)?|acc[_-]?no|kno|k[_-]?no|can|cano|ca[_-]?no|consumer(no)?|cust(omer)?(id|no)?|customerid|srno|sr[_-]?no|ref(no|id)?|application(no)?|appno|order(id|no)?|invoice(no)?|billno|bill[_-]?no)$");

    // Secrets and PII that should never appear in a response body a client can read.
    private static final Pattern JWT = Pattern.compile("eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{4,}");
    private static final Pattern PRIVATE_KEY = Pattern.compile("-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----");
    private static final Pattern AWS_KEY = Pattern.compile("\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b");
    private static final Pattern GOOGLE_KEY = Pattern.compile("\\bAIza[0-9A-Za-z_-]{35}\\b");
    private static final Pattern EMAIL = Pattern.compile("(?i)\\b[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}\\b");
    private static final Pattern PAN = Pattern.compile("\\b[A-Z]{5}[0-9]{4}[A-Z]\\b");
    private static final Pattern AADHAAR = Pattern.compile("\\b[2-9][0-9]{3}\\s[0-9]{4}\\s[0-9]{4}\\b");

    private List<ScanFinding> responseBodyFindings(String url, String body) {
        List<ScanFinding> out = new ArrayList<>();
        if (body == null || body.isEmpty()) return out;
        List<String> secrets = new ArrayList<>();
        if (JWT.matcher(body).find()) secrets.add("JSON Web Token (JWT)");
        if (PRIVATE_KEY.matcher(body).find()) secrets.add("private key block");
        if (AWS_KEY.matcher(body).find()) secrets.add("AWS access key id");
        if (GOOGLE_KEY.matcher(body).find()) secrets.add("Google API key");
        if (!secrets.isEmpty())
            out.add(ScanFinding.of(id(), "Secret or token disclosed in response body", "high", "firm", url,
                    "The response body exposes credential-grade material to any client that can read it: " + String.join(", ", secrets)
                    + ". Such secrets can be extracted and reused to impersonate the application or access protected resources.",
                    "Never return secrets, API keys, private keys or raw tokens in a response body. Keep secrets server-side, scope and "
                    + "short-lived any token that must reach the client, and rotate any value exposed here immediately.", List.of()));

        List<String> pii = new ArrayList<>();
        if (EMAIL.matcher(body).find()) pii.add("email address");
        if (PAN.matcher(body).find()) pii.add("PAN (Indian tax id)");
        if (AADHAAR.matcher(body).find()) pii.add("Aadhaar-formatted number");
        if (!pii.isEmpty())
            out.add(ScanFinding.of(id(), "Sensitive data (PII) in response body", "medium", "tentative", url,
                    "The response body appears to contain personally identifiable information (" + String.join(", ", pii)
                    + "). If this endpoint is reachable without strict per-user authorization, or the data is broader than the user needs, "
                    + "this is a data-exposure risk. Verify what data is returned and to whom.",
                    "Return only the minimum data the authenticated user is entitled to, enforce per-user authorization on the endpoint, "
                    + "mask or omit identifiers that are not needed, and ensure responses carrying PII are not cacheable.", List.of()));
        return out;
    }

    private List<ScanFinding> corsFindings(String url, burp.api.montoya.http.message.responses.HttpResponse resp) {
        List<ScanFinding> out = new ArrayList<>();
        String acao = resp.headerValue("Access-Control-Allow-Origin");
        if (acao == null) return out;
        boolean creds = "true".equalsIgnoreCase(resp.headerValue("Access-Control-Allow-Credentials"));
        if (acao.trim().equals("*"))
            out.add(ScanFinding.of(id(), "Permissive CORS policy (Access-Control-Allow-Origin: *)", creds ? "high" : "low",
                    creds ? "firm" : "tentative", url,
                    "The response allows cross-origin reads from any origin (Access-Control-Allow-Origin: *)"
                    + (creds ? " together with Access-Control-Allow-Credentials: true, an invalid and dangerous combination that browsers "
                    + "block but which signals a serious misconfiguration — any site could read authenticated responses." : ". For non-public "
                    + "data this lets any website read the response on behalf of a visitor."),
                    "Do not use a wildcard ACAO for authenticated or non-public responses. Maintain a server-side allow-list of trusted origins "
                    + "and echo only an exact match; never combine a wildcard or reflected origin with Allow-Credentials: true.", List.of()));
        else if (acao.trim().matches("(?i)null"))
            out.add(ScanFinding.of(id(), "CORS allows the 'null' origin", "medium", "tentative", url,
                    "Access-Control-Allow-Origin is set to 'null', which can be forced by sandboxed iframes and some redirects, letting "
                    + "attacker-controlled contexts read the response.",
                    "Never allow the 'null' origin. Use an explicit allow-list of trusted origins.", List.of()));
        return out;
    }

    // Next.js and React: markers and patterns in captured traffic that call for a manual check (see the
    // nextjs-react-vulnerabilities skill). Each one is a lead for the tester, not a confirmed vulnerability.
    private static final Pattern NEXT_DATA_MARK = Pattern.compile("id=\"__NEXT_DATA__\"");

    private List<ScanFinding> nextReactFindings(String url, HttpRequest req, burp.api.montoya.http.message.responses.HttpResponse resp, String body) {
        List<ScanFinding> out = new ArrayList<>();
        String b = body == null ? "" : body;
        String path = req.path() == null ? "" : req.path();
        String query = req.query() == null ? "" : req.query();
        String powered = resp.headerValue("X-Powered-By");
        boolean nextApp = (powered != null && powered.toLowerCase().contains("next.js"))
                || b.contains("/_next/static/") || NEXT_DATA_MARK.matcher(b).find();
        if (nextApp)
            out.add(ScanFinding.of(id(), "Next.js application detected (review Next.js-specific risks)", "info", "firm", url,
                    "The response carries Next.js markers (an X-Powered-By: Next.js header, /_next/ asset paths or __NEXT_DATA__). "
                    + "Next.js applications have framework-specific risks: authorization that lives only in middleware, Server Actions "
                    + "reachable as POST endpoints, secrets in hydration payloads, image-optimizer fetches and public source maps.",
                    "Work through the Next.js-specific checks in the nextjs-react-vulnerabilities skill: middleware authorization, Server Actions, __NEXT_DATA__, /_next/image and source maps.", List.of()));
        if (NEXT_DATA_MARK.matcher(b).find() && Triage.NEXT_DATA_SECRET.matcher(b).find())
            out.add(ScanFinding.of(id(), "Secret-like value in Next.js __NEXT_DATA__ payload", "medium", "tentative", url,
                    "The server-rendered __NEXT_DATA__ JSON is sent to every visitor's browser and contains a key that looks like a secret, token or password with a value attached.",
                    "Pass only the data the client needs into page props. Keep secrets and server-only fields out of getServerSideProps and getStaticProps results.", List.of()));
        if (req.hasHeader("Next-Action"))
            out.add(ScanFinding.of(id(), "Next.js Server Action endpoint observed (verify server-side authorization)", "low", "tentative", url,
                    "The request uses the Next-Action header, which invokes a Next.js Server Action. Server Actions are public POST endpoints, so they need their own authentication and authorization checks.",
                    "Authenticate and authorize inside every Server Action, validate its input with a schema, and do not rely on the UI to gate it.", List.of()));
        if (req.hasHeader("x-middleware-subrequest"))
            out.add(ScanFinding.of(id(), "Request carries x-middleware-subrequest header (Next.js middleware bypass pattern)", "medium", "tentative", url,
                    "The request sends x-middleware-subrequest, the internal header Next.js uses to skip middleware. On affected Next.js versions this can bypass middleware-based authorization.",
                    "Upgrade to a patched Next.js release, strip x-middleware-subrequest at the edge, and do not make middleware the only authorization control.", List.of()));
        if (path.startsWith("/_next/image") && query.matches("(?i).*(^|&)url=https?(%3A|:).*"))
            out.add(ScanFinding.of(id(), "Next.js image optimizer fetches a remote URL (SSRF surface)", "low", "tentative", url,
                    "The /_next/image endpoint is given a remote URL. If remote hosts are not restricted, the server can be made to request internal addresses.",
                    "Restrict images.remotePatterns to specific hosts and block egress to private and link-local addresses.", List.of()));
        if (path.endsWith(".js") && b.contains("dangerouslySetInnerHTML"))
            out.add(ScanFinding.of(id(), "dangerouslySetInnerHTML present in client JavaScript (review the sink for XSS)", "info", "tentative", url,
                    "The client bundle uses React's dangerouslySetInnerHTML. This is only a risk when attacker-controlled content reaches it unsanitised.",
                    "Confirm each sink is fed only trusted or sanitised HTML (for example with DOMPurify), and avoid it where possible.", List.of()));
        if (path.endsWith(".js") && b.contains("sourceMappingURL="))
            out.add(ScanFinding.of(id(), "JavaScript source map reference exposed (possible source code disclosure)", "low", "tentative", url,
                    "The script points to a source map. If the .map file is publicly served it reveals the original source code.",
                    "Disable browser source maps in production, or serve them only to the error-tracking service.", List.of()));
        return out;
    }

    // A CAPTCHA marks a flow that automated testing should not push through. This check only records that it is there.
    private static final Pattern CAPTCHA_MARK = Pattern.compile("(?i)(google\\.com/recaptcha|g-recaptcha|hcaptcha\\.com|h-captcha|challenges\\.cloudflare\\.com/turnstile|cf-turnstile|<input[^>]+name=[\"']?[^\"'>]*captcha)");

    /** Names the CAPTCHA provider on an HTML page, or returns null when there is none. Detection only: nothing is solved. */
    public static String captchaProvider(String body) {
        if (body == null || !CAPTCHA_MARK.matcher(body).find()) return null;
        String lower = body.toLowerCase(java.util.Locale.ROOT);
        if (lower.contains("recaptcha")) return "Google reCAPTCHA";
        if (lower.contains("hcaptcha") || lower.contains("h-captcha")) return "hCaptcha";
        if (lower.contains("turnstile")) return "Cloudflare Turnstile";
        return "a CAPTCHA";
    }

    private List<ScanFinding> captchaFindings(String url, String body, boolean html) {
        List<ScanFinding> out = new ArrayList<>();
        if (!html) return out;
        String provider = captchaProvider(body);
        if (provider == null) return out;
        out.add(ScanFinding.of(id(), "CAPTCHA protection detected (" + provider + ")", "info", "firm", url,
                "This page protects an action with " + provider + ". Automated scanning and AI review of the protected flow are limited by "
                + "design, so results for it need manual testing. OllamaAT does not attempt to solve or bypass CAPTCHAs.",
                "Manual testing only, with test accounts: confirm the CAPTCHA is validated server-side for every request it protects, and that tokens "
                + "cannot be reused. Keep rate limiting and account lockout as independent controls.", List.of()));
        return out;
    }

    private List<ScanFinding> hardeningHeaderFindings(String url, burp.api.montoya.http.message.responses.HttpResponse resp, boolean html) {
        List<ScanFinding> out = new ArrayList<>();
        if (resp.headerValue("Referrer-Policy") == null)
            out.add(ScanFinding.of(id(), "Missing Referrer-Policy header", "info", "firm", url,
                    "No Referrer-Policy header is set, so the full URL (which may contain identifiers or sensitive parameters) can leak to "
                    + "third-party sites via the Referer header.",
                    "Set 'Referrer-Policy: strict-origin-when-cross-origin' (or stricter) on all responses.", List.of()));
        if (resp.headerValue("Permissions-Policy") == null && resp.headerValue("Feature-Policy") == null && html)
            out.add(ScanFinding.of(id(), "Missing Permissions-Policy header", "info", "firm", url,
                    "No Permissions-Policy header is set, so the page does not restrict access to powerful browser features (camera, "
                    + "microphone, geolocation, etc.) for itself and any embedded content.",
                    "Add a least-privilege 'Permissions-Policy' header disabling features the application does not use.", List.of()));
        return out;
    }

    private List<ScanFinding> sensitiveUrlFindings(String url) {
        List<ScanFinding> out = new ArrayList<>();
        int q = url.indexOf('?');
        if (q < 0 || q == url.length() - 1) return out;
        String query = url.substring(q + 1);
        Map<String, String> secrets = new LinkedHashMap<>(), pii = new LinkedHashMap<>(), ids = new LinkedHashMap<>();
        for (String pair : query.split("&")) {
            if (pair.isBlank()) continue;
            int eq = pair.indexOf('=');
            String name = (eq >= 0 ? pair.substring(0, eq) : pair).trim();
            String value = eq >= 0 ? pair.substring(eq + 1).trim() : "";
            if (name.isEmpty() || value.isEmpty()) continue;
            if (SECRET_PARAM.matcher(name).matches()) secrets.putIfAbsent(name, value);
            else if (PII_PARAM.matcher(name).matches()) pii.putIfAbsent(name, value);
            else if (ID_PARAM.matcher(name).matches()) ids.putIfAbsent(name, value);
        }
        String base = url.substring(0, q);
        if (!secrets.isEmpty())
            out.add(ScanFinding.of(id(), "Credentials or token in URL query string", "high", "firm", url,
                    "The URL carries sensitive authentication data in its query string (parameter(s): " + String.join(", ", secrets.keySet())
                    + "). Query strings are stored in browser history and server/proxy logs and leak via the Referer header, so this value "
                    + "can be captured and replayed. Endpoint: " + base,
                    "Never place passwords, OTPs, tokens, API keys or session identifiers in the URL. Send them in the request body or a "
                    + "secure header over HTTPS (POST), set a strict Referrer-Policy, and rotate any value already exposed.", List.of()));
        if (!pii.isEmpty())
            out.add(ScanFinding.of(id(), "Sensitive data (PII) in URL query string", "medium", "firm", url,
                    "The URL exposes personally identifiable information in its query string (parameter(s): " + String.join(", ", pii.keySet())
                    + "). URLs are logged and leaked via the Referer header, exposing this PII to third parties and log readers. Endpoint: " + base,
                    "Do not pass PII (ID numbers, phone, email, date of birth) in the URL. Move it to the request body over HTTPS and apply a "
                    + "strict Referrer-Policy; review existing logs that may already contain it.", List.of()));
        if (!ids.isEmpty())
            out.add(ScanFinding.of(id(), "Object identifier in URL - possible IDOR and sensitive data in URL", "medium", "tentative", url,
                    "The URL references an object by a direct, often guessable identifier in its query string (parameter(s): "
                    + idSummary(ids) + "). If the endpoint does not enforce per-user authorization, changing this value may return another "
                    + "user's data (Insecure Direct Object Reference / Broken Object Level Authorization). The identifier is also exposed in "
                    + "logs and the Referer header. Endpoint: " + base,
                    "Enforce server-side authorization that the authenticated user owns the requested object on every request, independent of the "
                    + "identifier supplied. Prefer unpredictable identifiers (UUIDs) over sequential numbers, and avoid placing object ids in the URL "
                    + "where they will be logged. Verify manually by requesting the same endpoint with a different identifier.", List.of()));
        return out;
    }

    private static String idSummary(Map<String, String> ids) {
        StringBuilder b = new StringBuilder();
        for (Map.Entry<String, String> e : ids.entrySet()) {
            if (b.length() > 0) b.append(", ");
            String v = e.getValue();
            boolean numeric = v.matches("\\d{3,}");
            b.append(e.getKey()).append(numeric ? " (sequential numeric id)" : "");
        }
        return b.toString();
    }

    private static boolean hasFrameAncestors(String csp) { return csp != null && csp.toLowerCase().contains("frame-ancestors"); }
    private ScanFinding low(String url, String t, String d, String rem) { return ScanFinding.of(id(), t, "low", "firm", url, d, rem, List.of()); }
    private ScanFinding med(String url, String t, String d, String rem) { return ScanFinding.of(id(), t, "medium", "firm", url, d, rem, List.of()); }
}
