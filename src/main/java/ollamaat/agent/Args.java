package ollamaat.agent;

import java.util.*;

/** Lenient typed access to model-supplied arguments (small models often send numbers as strings, etc.). */
public final class Args {
    private final Map<String, Object> m;
    public Args(Map<String, Object> m) { this.m = m == null ? new LinkedHashMap<>() : m; }

    public Map<String, Object> raw() { return m; }
    public boolean has(String k) { return m.get(k) != null; }

    public String str(String k, String def) {
        Object o = m.get(k);
        if (o == null) return def;
        if (o instanceof Map || o instanceof List) return ollamaat.util.Json.write(o);
        return String.valueOf(o);
    }

    public String req(String k) throws ToolException {
        String v = str(k, null);
        if (v == null || v.isBlank()) throw new ToolException("Missing required argument '" + k + "'");
        return v;
    }

    public int integer(String k, int def) {
        Object o = m.get(k);
        if (o instanceof Number) return ((Number) o).intValue();
        if (o instanceof String) try { return Integer.parseInt(((String) o).trim()); } catch (NumberFormatException e) { /* fall through */ }
        return def;
    }

    public boolean bool(String k, boolean def) {
        Object o = m.get(k);
        if (o instanceof Boolean) return (Boolean) o;
        if (o instanceof String) return Boolean.parseBoolean(((String) o).trim());
        return def;
    }

    /** String-to-string map; accepts a JSON object or a JSON-encoded string. */
    public Map<String, String> strMap(String k) {
        Object o = m.get(k);
        if (o instanceof String) o = ollamaat.util.Json.parseLenient((String) o);
        Map<String, String> out = new LinkedHashMap<>();
        if (o instanceof Map) for (Map.Entry<?, ?> e : ((Map<?, ?>) o).entrySet())
            out.put(String.valueOf(e.getKey()), e.getValue() == null ? "" : String.valueOf(e.getValue()));
        return out;
    }

    public List<String> strList(String k) {
        Object o = m.get(k);
        if (o instanceof String) {
            Object p = ollamaat.util.Json.parseLenient((String) o);
            o = p instanceof List ? p : List.of(((String) o).split("\\s*,\\s*"));
        }
        List<String> out = new ArrayList<>();
        if (o instanceof List) for (Object v : (List<?>) o) if (v != null) out.add(String.valueOf(v));
        return out;
    }

    /** List of {find, replace} pairs. */
    public List<String[]> pairs(String k) {
        Object o = m.get(k);
        if (o instanceof String) o = ollamaat.util.Json.parseLenient((String) o);
        List<String[]> out = new ArrayList<>();
        if (o instanceof List) for (Object v : (List<?>) o) {
            Map<String, Object> e = ollamaat.util.Json.asMap(v);
            if (e != null && e.get("find") != null)
                out.add(new String[]{String.valueOf(e.get("find")), e.get("replace") == null ? "" : String.valueOf(e.get("replace"))});
        }
        return out;
    }
}
