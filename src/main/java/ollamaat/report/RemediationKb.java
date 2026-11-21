package ollamaat.report;

import java.util.List;
import java.util.Locale;

/**
 * Built-in remediation knowledge base. Maps a finding (by title/description keywords) to a comprehensive
 * remediation guideline, an impact statement, and authoritative reference links (OWASP cheat sheets, MDN, RFCs).
 * Used by both the HTML and the Excel report so guidance is consistent and does not depend on the local model.
 */
public final class RemediationKb {
    private RemediationKb() {}

    /** A remediation entry. {@code remediation} is multi-paragraph guidance; {@code refs} are reference links. */
    public record Entry(String category, String impact, String remediation, List<Ref> refs) {}
    public record Ref(String title, String url) {}

    private record Rule(String category, String[] keys, String impact, String remediation, List<Ref> refs) {}

    private static Ref r(String t, String u) { return new Ref(t, u); }

    private static final List<Rule> RULES = List.of(
        // ---- Next.js / React (placed first so framework-specific titles are not routed to a generic XSS entry)
        new Rule("Next.js Middleware Authorization Bypass",
            new String[]{"x-middleware-subrequest", "middleware bypass", "middleware authorization bypass", "middleware auth bypass"},
            "Next.js middleware can be skipped by sending the internal x-middleware-subrequest header on affected versions, so any access control that lives only in middleware (login checks, role checks, redirects) can be bypassed and protected pages or API routes reached without authorization.",
            "Upgrade Next.js to a patched release for your major version (the advisory for this issue lists the fixed versions). Strip or block the x-middleware-subrequest header at the edge (CDN, load balancer or reverse proxy) as a stop-gap. Do not make middleware the only authorization control: re-verify the session and the permission inside each route handler, Server Action and data-access function. Add regression tests that request protected paths with this header set.",
            List.of(r("Next.js security advisory for CVE-2025-29927 (middleware authorization bypass)", "https://nextjs.org/blog/cve-2025-29927"),
                    r("OWASP Authorization Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"))),
        new Rule("Next.js Server Actions Authorization",
            new String[]{"server action", "server actions", "next-action", "server function"},
            "Server Actions are publicly reachable POST endpoints. Without server-side authentication, authorization and input validation inside each action, any client that can reach the endpoint can invoke it directly, read or change data, or call privileged logic that the UI never exposed.",
            "Treat every Server Action as a public API endpoint. Authenticate the caller and check authorization for the specific resource inside the action, not in the page or the component that calls it. Validate and type every argument with a schema library (for example zod) and reject unexpected fields. Return only the data the caller is entitled to. Rely on Next.js's built-in origin checks for CSRF protection but do not treat them as an authorization control. Rate-limit sensitive actions.",
            List.of(r("React documentation: Server Functions", "https://react.dev/reference/rsc/server-functions"),
                    r("OWASP Input Validation Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"),
                    r("OWASP Authorization Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"))),
        new Rule("Next.js Data Exposure (__NEXT_DATA__ / environment)",
            new String[]{"__next_data__", "next_public", "hydration payload", "next data", "getserversideprops", "getstaticprops"},
            "Next.js serializes page props into the __NEXT_DATA__ script that every visitor's browser receives. Secrets, tokens, internal identifiers or whole database records passed as props, or NEXT_PUBLIC_ variables holding secrets, are disclosed to anyone who loads the page.",
            "Pass only the fields the page actually renders into props, and filter records in getServerSideProps, getStaticProps or the server component before returning them. Keep secrets in server-only code and mark server-only modules with the 'server-only' package so they cannot be imported into client components. Only NEXT_PUBLIC_ variables are inlined into the client bundle, so never give a secret that prefix. Review the rendered __NEXT_DATA__ JSON for keys such as token, secret, password and apiKey before each release.",
            List.of(r("Next.js documentation: Environment variables", "https://nextjs.org/docs/app/building-your-application/configuring/environment-variables"),
                    r("OWASP Secrets Management Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"))),
        new Rule("React XSS (dangerouslySetInnerHTML / javascript: URLs)",
            new String[]{"dangerouslysetinnerhtml", "react xss", "reactjs xss", "javascript: url", "javascript url", "javascript: uri"},
            "React escapes text by default, but dangerouslySetInnerHTML writes raw HTML, and a javascript: URL placed in href or src runs script when clicked. Attacker-controlled content reaching either sink gives script execution in the victim's session.",
            "Avoid dangerouslySetInnerHTML. Where rich HTML is unavoidable, sanitise it with a vetted library such as DOMPurify immediately before rendering, with a strict allow-list of tags and attributes. Validate URLs before putting them in href, src or action: allow only http, https and mailto (and relative paths), and reject javascript:, data: and vbscript:. Keep a strict Content-Security-Policy as defence-in-depth. Do not build HTML or script with string concatenation from user input.",
            List.of(r("React documentation: dangerouslySetInnerHTML", "https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html"),
                    r("OWASP DOM-based XSS Prevention Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html"),
                    r("OWASP XSS Prevention Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"))),
        new Rule("Next.js Image Optimizer SSRF",
            new String[]{"/_next/image", "image optimizer", "remotepatterns", "next/image"},
            "The Next.js image optimizer fetches whatever URL it is given. If remote image hosts are not restricted, an attacker can make the server request internal hosts or cloud metadata endpoints and read or relay the responses, which is server-side request forgery.",
            "Restrict images.remotePatterns to the exact hostnames and paths you need, and never use a wildcard hostname. Disable the optimizer for untrusted sources (unoptimized images) where it is not needed. Make sure the upstream host cannot redirect to internal addresses, and block egress from the application tier to private and link-local ranges including 169.254.169.254.",
            List.of(r("Next.js documentation: Image component (remotePatterns)", "https://nextjs.org/docs/app/api-reference/components/image"),
                    r("OWASP SSRF Prevention Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"))),
        new Rule("JavaScript Source Map Exposure",
            new String[]{"source map", "sourcemap", "sourcemappingurl", ".js.map", "productionbrowsersourcemaps"},
            "Production source maps map minified bundles back to the original source code, including comments, internal routes, API paths and sometimes embedded configuration. Publicly served maps make it much easier to find hidden endpoints and logic flaws.",
            "Disable browser source maps in production builds (for Next.js, leave productionBrowserSourceMaps off). If maps are needed for error tracking, upload them privately to the monitoring service and do not serve them from the public web root. Remove the sourceMappingURL comment from shipped bundles, and block requests for *.map files at the edge.",
            List.of(r("Next.js configuration: productionBrowserSourceMaps", "https://nextjs.org/docs/app/api-reference/config/next-config-js/productionBrowserSourceMaps"),
                    r("OWASP Web Security Testing Guide: Review webpack source maps", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage"))),
        new Rule("Vulnerable Next.js or React Version",
            new String[]{"vulnerable next", "vulnerable react", "outdated next", "outdated react", "framework version", "react server components vulnerab"},
            "Next.js and React releases fix security issues in middleware, Server Components and rendering. Running an affected version exposes the application to any public advisory for that version, often without any application-level mistake being required.",
            "Inventory the exact next and react-dom versions (package.json and lockfile) and compare them with the vendor advisories. Upgrade to a patched release on the supported branch, run npm audit or an equivalent SCA tool in CI, and enable automated dependency update pull requests. Re-test the application after upgrading, since behaviour can change between minor versions.",
            List.of(r("Next.js blog and security advisories", "https://nextjs.org/blog"),
                    r("React blog", "https://react.dev/blog"),
                    r("OWASP Dependency-Check / Vulnerable and Outdated Components", "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"))),
        new Rule("Next.js Framework Detected",
            new String[]{"next.js application detected", "nextjs application detected"},
            "This is an informational marker that the target is a Next.js application. It does not prove a vulnerability, but it means the Next.js-specific risks (middleware-only authorization, Server Actions, hydration data, image optimizer and source maps) should be checked.",
            "Review the Next.js-specific areas: confirm authorization inside route handlers and Server Actions rather than middleware alone, check __NEXT_DATA__ for sensitive props, confirm the image optimizer's remote patterns are restricted, and confirm source maps are not public. Keep Next.js on a supported, patched release.",
            List.of(r("Next.js security documentation", "https://nextjs.org/docs"),
                    r("OWASP Web Security Testing Guide", "https://owasp.org/www-project-web-security-testing-guide/latest/"))),
        new Rule("Cross-Site Scripting (XSS)",
            new String[]{"xss", "cross-site scripting", "cross site scripting", "html injection", "reflected xss", "dom-based xss", "stored xss"},
            "An attacker can execute arbitrary JavaScript in the victim's browser in the context of the application, enabling session/cookie theft, account takeover, keylogging, UI redress, and actions performed as the victim.",
            "Treat all user-controllable input as untrusted. Apply context-aware output encoding at the point of output (HTML body, HTML attribute, JavaScript, URL and CSS contexts each need their own encoding). Prefer a framework's auto-escaping templating and avoid sinks such as innerHTML, document.write and eval; use textContent and safe DOM APIs instead. Validate input against an allow-list where feasible. Deploy a strict Content-Security-Policy as defence-in-depth (nonce/hash-based, no unsafe-inline). Set HttpOnly on session cookies so script cannot read them. Sanitise rich HTML with a vetted library (e.g. DOMPurify) rather than hand-rolled filters.",
            List.of(r("OWASP XSS Prevention Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"),
                    r("OWASP DOM-based XSS Prevention", "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html"),
                    r("OWASP WSTG - Testing for XSS", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting"))),
        new Rule("SQL Injection",
            new String[]{"sql injection", "sqli", "sql-injection", "nosql", "ssji", "database error", "query tampering"},
            "An attacker can read, modify or delete arbitrary database data, bypass authentication, and in some configurations execute operating-system commands or move laterally, leading to full data breach.",
            "Use parameterised queries / prepared statements for every database call; never build queries by string concatenation. For NoSQL, use the driver's typed query API and reject operator-injection in user input ($where, $ne, etc.). Apply strict input validation and least-privilege database accounts (no DDL/admin rights for the app user). Use an ORM safely (avoid raw query interpolation). Disable verbose database error messages in production. Add a WAF as defence-in-depth, not as the primary control.",
            List.of(r("OWASP SQL Injection Prevention Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"),
                    r("OWASP Query Parameterization Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html"),
                    r("OWASP Testing for NoSQL Injection", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection"))),
        new Rule("Server-Side Request Forgery (SSRF)",
            new String[]{"ssrf", "server-side request forgery", "server side request forgery", "x-forwarded-host", "forwarded-host", "outbound fetch"},
            "An attacker can make the server send crafted requests to internal systems and cloud metadata endpoints, exposing internal services, credentials (e.g. cloud IAM tokens) and enabling pivoting into the internal network.",
            "Do not send server-side requests to user-supplied URLs or hosts. Where outbound requests are required, enforce a strict allow-list of destinations (scheme, host, port) and resolve-then-validate the IP to block private, loopback, link-local and cloud-metadata ranges (169.254.169.254, 100.100.100.200). Disable unused URL schemes and HTTP redirects, or re-validate the target after each redirect. Do not reflect Host/X-Forwarded-Host into outbound calls. Require authentication on internal services and apply network egress filtering from the application tier.",
            List.of(r("OWASP SSRF Prevention Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"),
                    r("OWASP WSTG - Testing for SSRF", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery"))),
        new Rule("Content Security Policy (CSP) Weakness",
            new String[]{"content-security-policy", "content security policy", "csp"},
            "A weak or missing CSP removes a key layer of defence against cross-site scripting and data injection, making script-injection flaws far easier to exploit and increasing the blast radius of any XSS.",
            "Deploy a strict Content-Security-Policy. Avoid 'unsafe-inline' and 'unsafe-eval'; use nonces or hashes for any required inline script. Set default-src 'self' (or 'none') and explicitly allow only trusted origins per directive (script-src, style-src, connect-src, img-src, frame-ancestors, base-uri, object-src 'none', form-action). Add frame-ancestors to prevent clickjacking and base-uri 'self' to block base-tag injection. Roll out with Content-Security-Policy-Report-Only first, monitor violation reports, then enforce.",
            List.of(r("OWASP Content Security Policy Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"),
                    r("MDN - Content-Security-Policy", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"))),
        new Rule("Missing Security Headers / Clickjacking",
            new String[]{"x-frame-options", "clickjacking", "frame-options", "security header", "x-content-type-options", "nosniff", "hsts", "strict-transport-security", "referrer-policy", "permissions-policy"},
            "Missing hardening headers expose users to clickjacking, MIME-sniffing attacks, protocol downgrade/SSL-strip, and referrer leakage, each of which can facilitate account compromise or data exposure.",
            "Set the standard response security headers on every response: Strict-Transport-Security (max-age>=31536000; includeSubDomains; preload) over HTTPS; X-Content-Type-Options: nosniff; a framing control via CSP frame-ancestors (or X-Frame-Options: DENY/SAMEORIGIN for legacy clients); Referrer-Policy: strict-origin-when-cross-origin or stricter; and a least-privilege Permissions-Policy disabling unused browser features. Apply these centrally (reverse proxy, gateway or middleware) so no endpoint is missed.",
            List.of(r("OWASP Secure Headers Project", "https://owasp.org/www-project-secure-headers/"),
                    r("OWASP Clickjacking Defense Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"),
                    r("MDN - Strict-Transport-Security", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"))),
        new Rule("Insecure Cookie Attributes",
            new String[]{"cookie", "httponly", "secure flag", "samesite", "session cookie"},
            "Cookies without protective attributes can be stolen via XSS (no HttpOnly), intercepted over cleartext (no Secure), or abused in cross-site request forgery (no SameSite), leading to session hijacking and account takeover.",
            "Set session and sensitive cookies with HttpOnly (block script access), Secure (HTTPS only), and SameSite=Lax or Strict (mitigate CSRF). Scope cookies with a specific Path and, where possible, the __Host- prefix. Keep session lifetimes short, rotate identifiers on privilege change, and invalidate server-side on logout. Do not store sensitive data in cookies in cleartext.",
            List.of(r("OWASP Session Management Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"),
                    r("MDN - Set-Cookie", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie"))),
        new Rule("CORS Misconfiguration",
            new String[]{"cors", "access-control-allow-origin", "cross-origin resource sharing"},
            "An overly permissive CORS policy lets malicious origins read authenticated responses, exposing user data and tokens and enabling actions on behalf of the victim.",
            "Do not reflect the Origin header or use Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true. Maintain a server-side allow-list of trusted origins and echo only an exact match. Restrict allowed methods and headers to the minimum required. Never rely on CORS as an access-control mechanism - enforce authorization server-side regardless of origin.",
            List.of(r("OWASP CORS - Testing Guide", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing"),
                    r("MDN - CORS", "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"))),
        new Rule("Information Disclosure",
            new String[]{"information disclosure", "verbose", "server banner", "stack trace", "error message", "version disclosure", "directory listing", "sensitive data exposure", "tracking domains", "user-agent", "in response body", "secret or token disclosed"},
            "Leaked technology versions, internal paths, stack traces or sensitive data help an attacker fingerprint the stack, find known-vulnerable components and craft targeted attacks, and may directly expose confidential information.",
            "Return generic error pages and log details server-side only; disable stack traces and debug output in production. Remove or genericise version-revealing headers (Server, X-Powered-By, X-AspNet-Version). Disable directory listing. Do not expose internal hostnames, file paths, tokens or PII in responses, URLs or comments. Review third-party/tracking content and remove what is unnecessary. Apply the same hardening at the reverse proxy.",
            List.of(r("OWASP WSTG - Information Gathering", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/"),
                    r("OWASP Error Handling Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html"))),
        new Rule("Insecure Direct Object Reference (IDOR / BOLA)",
            new String[]{"idor", "object identifier in url", "broken object level", "bola", "direct object reference", "insecure direct object"},
            "If per-request authorization is not enforced, an attacker can change the object identifier (e.g. an account or consumer number) "
            + "to read or modify other users' records, leading to mass data exposure or unauthorized changes.",
            "Enforce server-side authorization on every request: confirm the authenticated user is allowed to access the specific object, "
            + "independent of any identifier supplied by the client. Do not rely on the identifier being secret. Prefer unpredictable identifiers "
            + "(UUIDs) over sequential numbers, keep object ids out of URLs where they are logged, and add automated access-control tests that "
            + "request one user's objects while authenticated as another.",
            List.of(r("OWASP API1:2023 Broken Object Level Authorization", "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"),
                    r("OWASP Authorization Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"),
                    r("OWASP WSTG - Testing for IDOR", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References"))),
        new Rule("Open Redirect",
            new String[]{"open redirect", "unvalidated redirect"},
            "An attacker can craft a trusted-looking link on your domain that forwards victims to an attacker-controlled site, enabling phishing, credential theft and OAuth token leakage.",
            "Avoid redirects driven by user input. Where needed, use a server-side allow-list of permitted destinations or indirection via a mapping key rather than a raw URL. Accept only relative paths, or validate that the target host exactly matches an approved domain. Do not place user-supplied URLs in Location headers unvalidated.",
            List.of(r("OWASP Unvalidated Redirects and Forwards Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"))),
        new Rule("Path / Directory Traversal",
            new String[]{"path traversal", "directory traversal", "lfi", "file inclusion", "../"},
            "An attacker can read or write files outside the intended directory, exposing source code, configuration and credentials, and in some cases achieving remote code execution.",
            "Do not pass user input into file-system paths. Resolve the canonical path and verify it stays within an allow-listed base directory; reject path separators and traversal sequences. Prefer opaque identifiers mapped server-side to files. Run the application with least privilege so sensitive files are not readable, and store user content outside the web root.",
            List.of(r("OWASP Path Traversal", "https://owasp.org/www-community/attacks/Path_Traversal"),
                    r("OWASP WSTG - Testing Directory Traversal", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include"))),
        new Rule("Sensitive Data in URL",
            new String[]{"sensitive data in url", "token in url", "credentials in url", "data in query", "sensitive data in the url", "in url query string", "pii) in url", "credentials or token in url"},
            "Secrets placed in URLs are logged in browser history, proxy and server logs, and leaked via the Referer header, allowing credential or token theft.",
            "Never place tokens, session identifiers, passwords or PII in URL query strings or path. Transmit sensitive values in the request body or secure headers over HTTPS. Use POST for sensitive submissions, set Referrer-Policy to limit leakage, and rotate any secret that may have been exposed in logs.",
            List.of(r("OWASP WSTG - Sensitive Information in URL", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/"),
                    r("OWASP Session Management Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"))),
        new Rule("Insecure HTTP Methods",
            new String[]{"http methods", "insecure method", "put method", "delete method", "trace method", "options method"},
            "Dangerous HTTP methods left enabled can allow unauthorised file upload/deletion or cross-site tracing, aiding content manipulation and credential theft.",
            "Disable HTTP methods that are not required (PUT, DELETE, TRACE, CONNECT, PATCH) at the server or gateway. Enforce method-level authorization on every endpoint. Disable TRACE to prevent Cross-Site Tracing. Return 405 for unsupported methods and ensure OPTIONS does not leak unintended capability.",
            List.of(r("OWASP WSTG - Testing HTTP Methods", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods"))));

    private static final Entry GENERIC = new Entry("General Security Weakness",
        "Depending on exploitability, this issue could contribute to unauthorised access, data exposure, or degradation of the confidentiality, integrity or availability of the application.",
        "Verify the finding manually to confirm exploitability and impact. Apply defence-in-depth appropriate to the issue class: validate and encode all untrusted input/output, enforce least privilege and server-side authorization, keep components patched, and apply the standard response security headers. Follow the OWASP ASVS verification requirements for the affected area and re-test after remediation.",
        List.of(r("OWASP Application Security Verification Standard (ASVS)", "https://owasp.org/www-project-application-security-verification-standard/"),
                r("OWASP Cheat Sheet Series (index)", "https://cheatsheetseries.owasp.org/")));

    /** Best-match entry for a finding by its title and description. Never null. */
    public static Entry lookup(String title, String detail) {
        // Match the title first (curated, low-noise), then fall back to title+description. This avoids a stray word
        // in the description (e.g. "reflected") routing a finding to the wrong category.
        String t = (title == null ? "" : title).toLowerCase(Locale.ROOT);
        Entry byTitle = match(t);
        if (byTitle != null) return byTitle;
        Entry byBoth = match((t + " " + (detail == null ? "" : detail)).toLowerCase(Locale.ROOT));
        return byBoth != null ? byBoth : GENERIC;
    }

    private static Entry match(String hay) {
        for (Rule rule : RULES)
            for (String k : rule.keys())
                if (hay.contains(k)) return new Entry(rule.category(), rule.impact(), rule.remediation(), rule.refs());
        return null;
    }

    public static Entry generic() { return GENERIC; }
}
