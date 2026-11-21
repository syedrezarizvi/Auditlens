package ollamaat.util;

import java.util.*;

/** Minimal dependency-free JSON reader/writer. Objects -> LinkedHashMap, arrays -> ArrayList, numbers -> Long/Double. */
public final class Json {
    private final String s;
    private int i;

    private Json(String s) { this.s = s; }

    public static Object parse(String text) {
        Json j = new Json(text);
        j.ws();
        Object v = j.value();
        j.ws();
        if (j.i != j.s.length()) throw j.err("trailing data");
        return v;
    }

    /** Parses the first valid JSON object/array found in free text (tolerates markdown fences and chatter). */
    public static Object parseLenient(String text) {
        if (text == null) return null;
        for (int k = 0; k < text.length(); k++) {
            char c = text.charAt(k);
            if (c == '{' || c == '[') {
                try {
                    Json j = new Json(text);
                    j.i = k;
                    return j.value();
                } catch (RuntimeException e) { /* keep scanning */ }
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> asMap(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    @SuppressWarnings("unchecked")
    public static List<Object> asList(Object o) { return o instanceof List ? (List<Object>) o : null; }

    // ---------- parsing ----------
    private RuntimeException err(String m) { return new IllegalArgumentException("JSON: " + m + " at " + i); }

    private void ws() { while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++; }

    private Object value() {
        if (i >= s.length()) throw err("unexpected end");
        switch (s.charAt(i)) {
            case '{': return object();
            case '[': return array();
            case '"': return string();
            case 't': return lit("true", Boolean.TRUE);
            case 'f': return lit("false", Boolean.FALSE);
            case 'n': return lit("null", null);
            default: return number();
        }
    }

    private Object lit(String w, Object v) {
        if (!s.startsWith(w, i)) throw err("bad literal");
        i += w.length();
        return v;
    }

    private Map<String, Object> object() {
        Map<String, Object> m = new LinkedHashMap<>();
        i++; ws();
        if (peek('}')) { i++; return m; }
        while (true) {
            ws();
            if (!peek('"')) throw err("expected key");
            String k = string();
            ws();
            if (!peek(':')) throw err("expected ':'");
            i++; ws();
            m.put(k, value());
            ws();
            if (peek(',')) { i++; continue; }
            if (peek('}')) { i++; return m; }
            throw err("expected ',' or '}'");
        }
    }

    private List<Object> array() {
        List<Object> l = new ArrayList<>();
        i++; ws();
        if (peek(']')) { i++; return l; }
        while (true) {
            ws();
            l.add(value());
            ws();
            if (peek(',')) { i++; continue; }
            if (peek(']')) { i++; return l; }
            throw err("expected ',' or ']'");
        }
    }

    private boolean peek(char c) { return i < s.length() && s.charAt(i) == c; }

    private String string() {
        StringBuilder sb = new StringBuilder();
        i++;
        while (true) {
            if (i >= s.length()) throw err("unterminated string");
            char c = s.charAt(i++);
            if (c == '"') return sb.toString();
            if (c != '\\') { sb.append(c); continue; }
            if (i >= s.length()) throw err("bad escape");
            char e = s.charAt(i++);
            switch (e) {
                case '"': sb.append('"'); break;
                case '\\': sb.append('\\'); break;
                case '/': sb.append('/'); break;
                case 'b': sb.append('\b'); break;
                case 'f': sb.append('\f'); break;
                case 'n': sb.append('\n'); break;
                case 'r': sb.append('\r'); break;
                case 't': sb.append('\t'); break;
                case 'u':
                    if (i + 4 > s.length()) throw err("bad unicode escape");
                    sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                    i += 4;
                    break;
                default: throw err("bad escape");
            }
        }
    }

    private Object number() {
        int st = i;
        if (peek('-')) i++;
        while (i < s.length() && "0123456789.eE+-".indexOf(s.charAt(i)) >= 0) i++;
        String t = s.substring(st, i);
        if (t.isEmpty() || t.equals("-")) throw err("unexpected character");
        try {
            if (t.indexOf('.') < 0 && t.indexOf('e') < 0 && t.indexOf('E') < 0) return Long.parseLong(t);
            return Double.parseDouble(t);
        } catch (NumberFormatException ex) { throw err("bad number " + t); }
    }

    // ---------- writing ----------
    public static String write(Object o) { StringBuilder sb = new StringBuilder(); write(o, sb, -1, 0); return sb.toString(); }

    public static String pretty(Object o) { StringBuilder sb = new StringBuilder(); write(o, sb, 2, 0); return sb.toString(); }

    private static void nl(StringBuilder sb, int indent, int level) {
        if (indent < 0) return;
        sb.append('\n');
        for (int k = 0; k < indent * level; k++) sb.append(' ');
    }

    private static void write(Object o, StringBuilder sb, int indent, int level) {
        if (o == null) sb.append("null");
        else if (o instanceof String) quote((String) o, sb);
        else if (o instanceof Boolean) sb.append(o);
        else if (o instanceof Double || o instanceof Float) {
            double d = ((Number) o).doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) sb.append("null");
            else if (d == Math.rint(d) && Math.abs(d) < 1e15) sb.append((long) d);
            else sb.append(d);
        } else if (o instanceof Number) sb.append(o);
        else if (o instanceof Map) {
            Map<?, ?> m = (Map<?, ?>) o;
            if (m.isEmpty()) { sb.append("{}"); return; }
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (!first) sb.append(',');
                first = false;
                nl(sb, indent, level + 1);
                quote(String.valueOf(e.getKey()), sb);
                sb.append(indent < 0 ? ":" : ": ");
                write(e.getValue(), sb, indent, level + 1);
            }
            nl(sb, indent, level);
            sb.append('}');
        } else if (o instanceof Collection) {
            Collection<?> c = (Collection<?>) o;
            if (c.isEmpty()) { sb.append("[]"); return; }
            sb.append('[');
            boolean first = true;
            for (Object v : c) {
                if (!first) sb.append(',');
                first = false;
                nl(sb, indent, level + 1);
                write(v, sb, indent, level + 1);
            }
            nl(sb, indent, level);
            sb.append(']');
        } else quote(String.valueOf(o), sb);
    }

    private static void quote(String v, StringBuilder sb) {
        sb.append('"');
        for (int k = 0; k < v.length(); k++) {
            char c = v.charAt(k);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        sb.append('"');
    }
}
