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
        for (ParsedHttpParameter p : baseline.request().parameters())
            if ((p.type() == HttpParameterType.URL || p.type() == HttpParameterType.BODY) && !p.value().isBlank())
                out.add(p);
        return out;
    }

    public static HttpRequest withValue(HttpRequestResponse baseline, ParsedHttpParameter p, String newValue) {
        HttpParameter hp = p.type() == HttpParameterType.BODY
                ? HttpParameter.bodyParameter(p.name(), newValue)
                : HttpParameter.urlParameter(p.name(), newValue);
        return baseline.request().withParameter(hp);
    }
}
