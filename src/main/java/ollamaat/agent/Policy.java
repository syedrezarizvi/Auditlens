package ollamaat.agent;

import ollamaat.Settings;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Deterministic control layer, deliberately separate from the model. The model can only propose actions;
 * this class (plus the human) decides. Nothing here is prompt-based, so it cannot be talked around.
 */
public final class Policy {
    public enum Verdict { ALLOW, ASK, BLOCK }
    public record Decision(Verdict verdict, String reason) {
        static Decision allow(String r) { return new Decision(Verdict.ALLOW, r); }
        static Decision ask(String r) { return new Decision(Verdict.ASK, r); }
        static Decision block(String r) { return new Decision(Verdict.BLOCK, r); }
    }

    private static final Pattern DESTRUCTIVE = Pattern.compile(
            "(?i)(delete|remove|destroy|drop|purge|wipe|revoke|cancel|terminate|disable|unsubscribe|"
                    + "checkout|purchase|payment|pay|transfer|withdraw|refund|reset|logout|signout|sign-out|log-out)");

    private final Settings settings;
    private final Predicate<String> inScope;

    public Policy(Settings settings, Predicate<String> inScope) {
        this.settings = settings;
        this.inScope = inScope;
    }

    public static String allowanceKey(String tool, Action.NetInfo n) {
        String host = "";
        try { host = URI.create(n.url()).getHost(); } catch (RuntimeException e) { /* ignore */ }
        return tool + "|" + n.method().toUpperCase() + "|" + host;
    }

    public Decision evaluate(String tool, Action a, RunState rs) {
        switch (a.kind()) {
            case READ:
            case FINISH:
                return Decision.allow("read-only");
            case ANNOTATE:
                return Decision.allow("local annotation (findings/notes)");
            case PROJECT_WRITE:
                return settings.autonomy() == Settings.Autonomy.STRICT
                        ? Decision.ask("strict mode: project changes need approval")
                        : Decision.allow("project annotation");
            case NETWORK:
                return network(tool, a, rs);
            default:
                return Decision.block("unknown action kind");
        }
    }

    private Decision network(String tool, Action a, RunState rs) {
        Action.NetInfo n = a.net();
        if (n == null) return Decision.block("network action without request details");
        if (!rs.allowNetwork) return Decision.block("this run is read-only (no network access)");

        String url = n.url();
        // Parse leniently: active-scan probes legitimately put characters like '<', '>' or spaces (XSS markers,
        // boolean-SQLi conditions) into the query. Burp sends those fine, so the gate must not reject them as an
        // "invalid URL" — that would silently block every injection probe. Only the host is needed for the checks
        // below; percent-encoding the offending characters for parsing does not change what is actually sent.
        URI u = parseLenient(url);
        if (u == null || u.getHost() == null || !(url.startsWith("http://") || url.startsWith("https://")))
            return Decision.block("only absolute http(s) URLs are allowed");

        // 1. Hard scope gate: Burp's target scope is the only source of truth.
        if (!inScope.test(url))
            return Decision.block("out of Burp target scope (" + u.getHost() + "). Add the target to Burp scope to test it");

        // 2. Hard budget gate.
        if (rs.requestsSent.get() >= settings.maxRequestsPerRun())
            return Decision.block("request budget exhausted (" + settings.maxRequestsPerRun() + " per run)");

        // 3. User-defined hard block list.
        for (String line : settings.blockedPatterns().split("\\n")) {
            String p = line.trim();
            if (p.isEmpty()) continue;
            try { if (Pattern.compile(p).matcher(url).find()) return Decision.block("matches blocked pattern: " + p); }
            catch (PatternSyntaxException e) { /* ignore bad user regex */ }
        }

        String method = n.method().toUpperCase();
        boolean safeMethod = method.equals("GET") || method.equals("HEAD") || method.equals("OPTIONS");
        boolean destructive = method.equals("DELETE") || DESTRUCTIVE.matcher(urlPathAndQuery(u)).find();

        // 4. Things a human must always see.
        if (method.equals("DELETE")) return Decision.ask("DELETE requests always require approval");
        if (destructive) return Decision.ask("URL looks state-changing/destructive");

        // 5. Per-run allowance the user granted earlier.
        if (rs.allowances.contains(allowanceKey(tool, n))) return Decision.allow("approved earlier for this run");

        switch (settings.autonomy()) {
            case STRICT:
                return Decision.ask("strict mode: every request needs approval");
            case SMART:
                if (safeMethod && !n.hasBody()) return Decision.allow("in-scope read-only request");
                return Decision.ask(method + " may change server state");
            case AUTONOMOUS:
                return Decision.allow("autonomous mode, in scope");
            default:
                return Decision.ask("unknown autonomy level");
        }
    }

    private static String urlPathAndQuery(URI u) {
        return (u.getPath() == null ? "" : u.getPath()) + "?" + (u.getQuery() == null ? "" : u.getQuery());
    }

    /** URI.create() rejects characters that are illegal in a raw URI (space, &lt;, &gt;, ", etc.), but active-scan
     *  probes routinely include them and Burp sends them without complaint. Parse strictly first; on failure,
     *  percent-encode just those characters and retry, so host/path parsing succeeds without altering the real
     *  request. Returns null only if it still cannot be parsed. */
    public static URI parseLenient(String url) {
        if (url == null) return null;
        try { return URI.create(url); } catch (RuntimeException ignored) { }
        StringBuilder sb = new StringBuilder(url.length() + 16);
        for (int i = 0; i < url.length(); i++) {
            char c = url.charAt(i);
            if (c <= 0x20 || c == 0x7F || "<>\"{}|\\^`".indexOf(c) >= 0)
                sb.append('%').append(String.format("%02X", c & 0xFF));
            else sb.append(c);
        }
        try { return URI.create(sb.toString()); } catch (RuntimeException e) { return null; }
    }

    public static List<String> validatePatterns(String text) {
        List<String> bad = new ArrayList<>();
        for (String l : text.split("\\n")) {
            if (l.isBlank()) continue;
            try { Pattern.compile(l.trim()); } catch (PatternSyntaxException e) { bad.add(l.trim()); }
        }
        return bad;
    }
}
