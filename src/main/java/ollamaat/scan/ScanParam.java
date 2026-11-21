package ollamaat.scan;

import burp.api.montoya.http.message.params.HttpParameterType;

/** A single parameter instance (name/value/type) belonging to a candidate request, flattened for iteration by checks. */
public record ScanParam(String name, String value, HttpParameterType type) {
    public boolean isBody() { return type == HttpParameterType.BODY; }
}
