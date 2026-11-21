package ollamaat.agent;

import java.util.*;

/** Tiny builder for JSON-schema "properties". */
public final class Schema {
    private final Map<String, Object> props = new LinkedHashMap<>();
    private final List<String> required = new ArrayList<>();

    public static Schema of() { return new Schema(); }

    private Schema add(String name, String type, String desc, boolean req) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("type", type);
        p.put("description", desc);
        props.put(name, p);
        if (req) required.add(name);
        return this;
    }

    public Schema str(String n, String d, boolean req) { return add(n, "string", d, req); }
    public Schema integer(String n, String d, boolean req) { return add(n, "integer", d, req); }
    public Schema bool(String n, String d, boolean req) { return add(n, "boolean", d, req); }
    public Schema obj(String n, String d, boolean req) { return add(n, "object", d, req); }
    public Schema arr(String n, String d, boolean req) { return add(n, "array", d, req); }

    public Map<String, Object> props() { return props; }
    public List<String> required() { return required; }
}
