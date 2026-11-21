package ollamaat.tools;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import ollamaat.util.Text;

import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Renders Burp messages as compact text for the model. */
public final class Fmt {
    private Fmt() {}

    private static final Set<String> SECRET_HEADERS = Set.of("authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token");
    private static final Pattern TITLE = Pattern.compile("(?is)<title[^>]*>(.*?)</title>");

    private static String header(HttpHeader h, boolean redact) {
        if (redact && SECRET_HEADERS.contains(h.name().toLowerCase())) return h.name() + ": [REDACTED len=" + h.value().length() + "]";
        return h.name() + ": " + h.value();
    }

    public static String request(HttpRequest r, int maxBody, boolean redact) {
        StringBuilder sb = new StringBuilder();
        sb.append(r.method()).append(' ').append(r.path()).append(' ').append(r.httpVersion()).append('\n');
        for (HttpHeader h : r.headers()) sb.append(header(h, redact)).append('\n');
        sb.append('\n').append(body(r.bodyToString(), r.body().length(), maxBody));
        return sb.toString();
    }

    public static String response(HttpResponse r, int maxBody, boolean redact) {
        if (r == null) return "(no response)";
        StringBuilder sb = new StringBuilder();
        sb.append(r.httpVersion()).append(' ').append(r.statusCode()).append(' ').append(r.reasonPhrase()).append('\n');
        for (HttpHeader h : r.headers()) sb.append(header(h, redact)).append('\n');
        sb.append('\n').append(body(r.bodyToString(), r.body().length(), maxBody));
        return sb.toString();
    }

    private static String body(String s, int len, int max) {
        if (len == 0) return "";
        if (Text.looksBinary(s)) return "[binary body, " + len + " bytes]";
        return Text.truncate(s, max);
    }

    public static String title(HttpResponse r) {
        if (r == null) return "";
        Matcher m = TITLE.matcher(r.bodyToString());
        return m.find() ? Text.oneLine(m.group(1), 80) : "";
    }

    public static String contentType(HttpResponse r) {
        if (r == null) return "";
        String ct = r.headerValue("Content-Type");
        if (ct == null) return "";
        int i = ct.indexOf(';');
        return (i > 0 ? ct.substring(0, i) : ct).trim().toLowerCase();
    }

    public static String line(String ref, HttpRequestResponse rr) {
        HttpResponse resp = rr.hasResponse() ? rr.response() : null;
        return ref + " " + rr.request().method() + " " + rr.request().url() + " -> "
                + (resp == null ? "no-response" : resp.statusCode() + " " + contentType(resp) + " " + resp.body().length() + "B");
    }

    /** Word-set Jaccard similarity, 0..1. Cheap structural similarity for IDOR/auth comparisons. */
    public static double similarity(String a, String b) {
        if (a.equals(b)) return 1.0;
        java.util.Set<String> x = tokens(a), y = tokens(b);
        if (x.isEmpty() && y.isEmpty()) return 1.0;
        int inter = 0;
        for (String t : x) if (y.contains(t)) inter++;
        int union = x.size() + y.size() - inter;
        return union == 0 ? 1.0 : (double) inter / union;
    }

    private static java.util.Set<String> tokens(String s) {
        java.util.Set<String> out = new java.util.HashSet<>();
        for (String t : Text.truncate(s, 60000).split("[^A-Za-z0-9_]+")) if (!t.isEmpty()) out.add(t);
        return out;
    }
}
