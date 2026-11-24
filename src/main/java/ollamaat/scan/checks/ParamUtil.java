package ollamaat.scan.checks;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.List;

/** Shared helpers for mutating URL/body (form) parameters. JSON/XML bodies are intentionally not mutated here
 *  (structured injection into them is better done by the agent via replay_request / the relevant skill). */
public final class ParamUtil {
    private ParamUtil() {}

    public static List<ParsedHttpParameter> mutable(HttpRequestResponse baseline) {
        List<ParsedHttpParameter> out = new ArrayList<>();
        // A blank-valued parameter (e.g. ?query= or an empty form field) is still a real injection point, so it is
        // tested too — the probe payload simply replaces the empty value. Skipping these was missing obvious XSS/SQLi.
        for (ParsedHttpParameter p : baseline.request().parameters())
            if (p.type() == HttpParameterType.URL || p.type() == HttpParameterType.BODY)
                out.add(p);
        return out;
    }

    public static HttpRequest withValue(HttpRequestResponse baseline, ParsedHttpParameter p, String newValue) {
        // Burp inserts URL- and form-parameter values verbatim; it does NOT percent-encode them. A probe value with
        // raw '<', '>' or spaces (XSS markers, boolean-SQLi conditions) therefore goes on the wire unencoded, and a
        // strict server (e.g. Tomcat/Apache-Coyote, which demo.testfire.net runs) rejects the whole request with
        // 400 Bad Request before the application sees it — so nothing reflects and no injection is ever detected.
        // Percent-encode the value so the request is well-formed; the server decodes it back to the real payload.
        String encoded = java.net.URLEncoder.encode(newValue, java.nio.charset.StandardCharsets.UTF_8);
        HttpParameter hp = p.type() == HttpParameterType.BODY
                ? HttpParameter.bodyParameter(p.name(), encoded)
                : HttpParameter.urlParameter(p.name(), encoded);
        return baseline.request().withParameter(hp);
    }
}
