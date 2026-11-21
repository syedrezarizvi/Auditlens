package ollamaat.util;

import java.util.regex.Pattern;

public final class Text {
    private Text() {}

    public static String truncate(String s, int max) {
        if (s == null) return "";
        if (max <= 0 || s.length() <= max) return s;
        return s.substring(0, max) + "\n…[truncated " + (s.length() - max) + " chars]";
    }

    public static String oneLine(String s, int max) {
        if (s == null) return "";
        String t = s.replaceAll("\\s+", " ").trim();
        return t.length() <= max ? t : t.substring(0, Math.max(0, max - 1)) + "…";
    }

    /** Heuristic: true if the text looks like binary data. */
    public static boolean looksBinary(String s) {
        if (s == null || s.isEmpty()) return false;
        int n = Math.min(s.length(), 600), bad = 0;
        for (int k = 0; k < n; k++) {
            char c = s.charAt(k);
            if (c == 0xFFFD || (c < 0x20 && c != '\n' && c != '\r' && c != '\t')) bad++;
        }
        return bad * 10 > n;
    }

    private static final Pattern NUM = Pattern.compile("(?<=/)\\d+(?=/|$)");
    private static final Pattern UUID = Pattern.compile("(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");

    /** Normalises ids so /users/12 and /users/13 collapse to /users/{n}. Query string is dropped. */
    public static String pathTemplate(String path) {
        if (path == null) return "";
        String p = path;
        int q = p.indexOf('?');
        if (q >= 0) p = p.substring(0, q);
        p = UUID.matcher(p).replaceAll("{uuid}");
        return NUM.matcher(p).replaceAll("{n}");
    }
}
